from asn1_structs import *
from kerberoserror import *
from constants import *
from common import *
from encryption import _enctype_table, Key
import collections
import datetime
import secrets
import socket
import logging

class KerberosSocketType(enum.Enum):
	UDP = enum.auto()
	TCP = enum.auto()
	
class KerberosSocket:
	def __init__(self, ip, port = 88, soc_type = KerberosSocketType.TCP):
		self.soc_type = soc_type
		self.dst_ip = ip
		self.dst_port = port
		self.soc = None
		
	def create_soc(self):
		if self.soc_type == KerberosSocketType.TCP:
			self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.soc.connect((self.dst_ip, self.dst_port))
			
			
		elif self.soc_type == KerberosSocketType.UDP:
			self.soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			
		else:
			raise Exception('Unknown socket type!')
			
	def sendrecv(self, data):
		self.create_soc()
		if self.soc_type == KerberosSocketType.TCP:
			length = len(data).to_bytes(4, byteorder = 'big', signed = False)
			self.soc.sendall(length + data)
			buff = b''
			total_length = -1
			while True:
				temp = b''
				temp = self.soc.recv(4096)
				if temp == b'':
					break
				buff += temp
				if total_length == -1:
					if len(buff) > 4:
						total_length = int.from_bytes(buff[:4], byteorder = 'big', signed = False)
						if total_length == 0:
							raise Exception('Returned data length is 0! This means the server did not understand our message')
				
				if total_length != -1:
					if len(buff) == total_length + 4:
						buff = buff[4:]
						break
					elif len(buff) > total_length + 4:
						raise Exception('Got too much data somehow')
					else:
						continue
						
			
		elif self.soc_type == KerberosSocketType.UDP:
			self.soc.sendto(data)
			while True:
				buff, addr = self.soc.recvfrom(65535)
				if addr[0] == self.dst_ip:
					break
				else:
					# got a message from a different IP than the target, strange!
					# continuing, but this might result in an infinite loop
					continue
		
		return KerberosResponse.load(buff)
		
		

class KerbrosComm:
	def __init__(self,ccred, target, ksoc):
		self.usercreds = ccred
		self.target = target
		self.ksoc = ksoc
		self.kerberos_session_key = None
		self.kerberos_TGT = None
		self.kerberos_cipher = None
		self.kerberos_cipher_type = None
		
	def get_TGT(self):
		"""
		Steps performed:
			1. Send and empty (no encrypted timestamp) AS_REQ with all the encryption types we support
			2. Depending on the response (either error or AS_REP with TGT) we either send another AS_REQ with the encrypted data or return the TGT (or fail miserably)
			3. PROFIT
		"""
		now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
		kdc_req_body = {}
		kdc_req_body['kdc-options'] = KDCOptions(set(['forwardable','renewable','proxiable']))
		kdc_req_body['cname'] = PrincipalName({'name-type': 1, 'name-string': [self.usercreds.username]})
		kdc_req_body['realm'] = self.usercreds.domain.upper()
		kdc_req_body['sname'] = PrincipalName({'name-type': 1, 'name-string': ['krbtgt', self.usercreds.domain.upper()]})
		kdc_req_body['till'] = now
		kdc_req_body['rtime'] = now
		kdc_req_body['nonce'] = secrets.randbits(31)
		kdc_req_body['etype'] = [18]#SequenceOfEnctype([int(ENCTYPE('AES256_CTS_HMAC_SHA1_96'))])
		
		pa_data_1 = {}
		pa_data_1['padata-type'] = int(PADATA_TYPE('PA-PAC-REQUEST'))
		pa_data_1['padata-value'] = PA_PAC_REQUEST({'include-pac': True}).dump()
		
		kdc_req = {}
		kdc_req['pvno'] = krb5_pvno
		kdc_req['msg-type'] = int(MESSAGE_TYPE('krb-as-req'))
		kdc_req['padata'] = [pa_data_1]
		kdc_req['req-body'] = KDC_REQ_BODY(kdc_req_body)
		
		req = AS_REQ(kdc_req)
		print(req.dump())
		
		
		rep = self.ksoc.sendrecv(req.dump())
				
		if rep.name != 'KRB_ERROR':	
			raise Exception('IMPLEMENT!!!')
			return
		
		rep = rep.native
		#now getting server's supported encryption methods
		
		supp_enc_methods = collections.OrderedDict()
		for enc_method in METHOD_DATA.load(rep['e-data']).native:					
			data_type = PaDataType(enc_method['padata-type'])
			
			if data_type == PaDataType.ETYPE_INFO or data_type == PaDataType.ETYPE_INFO2:
				if data_type == PaDataType.ETYPE_INFO:
					enc_info_list = ETYPE_INFO.load(enc_method['padata-value'])
					
				elif data_type == PaDataType.ETYPE_INFO2:
					enc_info_list = ETYPE_INFO2.load(enc_method['padata-value'])
		
				for enc_info in enc_info_list.native:
					supp_enc_methods[EncryptionType(enc_info['etype'])] = enc_info['salt']
					logging.debug('Server supports encryption type %s with salt %s' % (EncryptionType(enc_info['etype']).name, enc_info['salt']))
			
		#now to create an AS_REQ with encrypted timestamp for authentication
		now = datetime.datetime.utcnow()
		kdc_req_body = {}
		kdc_req_body['kdc-options'] = KDCOptions(set(['forwardable','renewable','proxiable']))
		kdc_req_body['cname'] = PrincipalName({'name-type': 1, 'name-string': [self.usercreds.username]})
		kdc_req_body['realm'] = self.usercreds.domain.upper()
		kdc_req_body['sname'] = PrincipalName({'name-type': 1, 'name-string': ['krbtgt', self.usercreds.domain.upper()]})
		kdc_req_body['till'] = now + datetime.timedelta(days=1)
		kdc_req_body['rtime'] = now + datetime.timedelta(days=1)
		kdc_req_body['nonce'] = secrets.randbits(31)
		kdc_req_body['etype'] = [18]#SequenceOfEnctype([int(ENCTYPE('AES256_CTS_HMAC_SHA1_96'))])
		
		pa_data_1 = {}
		pa_data_1['padata-type'] = int(PADATA_TYPE('PA-PAC-REQUEST'))
		pa_data_1['padata-value'] = PA_PAC_REQUEST({'include-pac': True}).dump()
		
		
		#creating timestamp asn1
		timestamp = PA_ENC_TS_ENC({'patimestamp': now, 'pausec': now.microsecond}).dump()
		
		for supp_enc in supp_enc_methods:
			cipher = _enctype_table[supp_enc.value]
			key = Key(cipher.enctype, bytes.fromhex(self.usercreds.kerberos_key_aes_256))
		enc_timestamp = cipher.encrypt(key, 1, timestamp, None)
		self.kerberos_cipher = cipher
		self.kerberos_cipher_type = supp_enc.value
		
		pa_data_2 = {}
		pa_data_2['padata-type'] = int(PADATA_TYPE('ENC-TIMESTAMP'))
		pa_data_2['padata-value'] = EncryptedData({'etype': supp_enc.value, 'cipher': enc_timestamp}).dump()
		
		kdc_req = {}
		kdc_req['pvno'] = krb5_pvno
		kdc_req['msg-type'] = int(MESSAGE_TYPE('krb-as-req'))
		kdc_req['padata'] = [pa_data_2,pa_data_1]
		kdc_req['req-body'] = KDC_REQ_BODY(kdc_req_body)
		
		req = AS_REQ(kdc_req)
		print(req.dump())
		with open('test3.asn1','wb') as f:
			f.write(req.dump())
		
		rep = self.ksoc.sendrecv(req.dump())
		print(rep.native)
		rep = rep.native
		self.kerberos_TGT = rep
		
		cipherText = rep['enc-part']['cipher']
		temp = cipher.decrypt(key, 3, cipherText)
		plainText = EncASRepPart.load(temp).native
		print(plainText)
		self.kerberos_session_key = Key(cipher.enctype, plainText['key']['keyvalue'])
		
		
	def get_TGS(self):
		#construct tgs_req
		now = datetime.datetime.utcnow() 
		kdc_req_body = {}
		kdc_req_body['kdc-options'] = KDCOptions(set(['forwardable','renewable','renewable_ok', 'canonicalize']))
		kdc_req_body['realm'] = self.target.domain.upper()
		kdc_req_body['till'] = now + datetime.timedelta(days=1)
		kdc_req_body['nonce'] = secrets.randbits(31)
		kdc_req_body['etype'] = [self.kerberos_cipher_type]

		authenticator_data = {}
		authenticator_data['authenticator-vno'] = krb5_pvno
		authenticator_data['crealm'] = Realm(self.kerberos_TGT['crealm'])
		authenticator_data['cname'] = PrincipalName({'name-type': 1, 'name-string': [self.usercreds.username]})
		authenticator_data['cusec'] = now.microsecond
		authenticator_data['ctime'] = now
		
		authenticator_data_enc = self.kerberos_cipher.encrypt(self.kerberos_session_key, 7, Authenticator(authenticator_data).dump(), None)
		
		ap_req = {}
		ap_req['pvno'] = krb5_pvno
		ap_req['msg-type'] = int(MESSAGE_TYPE('krb-ap-req'))
		ap_req['ap-options'] = APOptions(set())
		ap_req['ticket'] = Ticket(self.kerberos_TGT['ticket'])
		ap_req['authenticator'] = EncryptedData({'etype': self.kerberos_cipher_type, 'cipher': authenticator_data_enc})
		AP_REQ(ap_req)
		
		pa_data_1 = {}
		pa_data_1['padata-type'] = PaDataType.TGS_REQ.value
		pa_data_1['padata-value'] = AP_REQ(ap_req).dump()
		
		
		kdc_req = {}
		kdc_req['pvno'] = krb5_pvno
		kdc_req['msg-type'] = int(MESSAGE_TYPE('krb-tgs-req'))
		kdc_req['padata'] = [pa_data_1]
		kdc_req['req-body'] = KDC_REQ_BODY(kdc_req_body)
		
		req = TGS_REQ(kdc_req)
		#print(req.native)
		rep = self.ksoc.sendrecv(req.dump())
		print(rep.native)
		

if __name__ == '__main__':
	logging.basicConfig(level=logging.DEBUG)
	
	ccred = UserCredential()
	ccred.username = 'victim'
	ccred.domain = 'TEST.corp'
	ccred.password = 'Almaalmaalma!1'
	ccred.NT = 'df85f802490f0384233c895f06ba2011'
	ccred.kerberos_key_aes_256 = 'd3f3593c9debec0be8db57b160f6b0f0c82fb4c0e5dcaa1e1e26ceddcfd05f60'
	ccred.kerberos_key_aes_128 = 'fa021d1bf218a731bad4c19b5bcaae8c'
	ccred.kerberos_key_rc4 = 'b3644f0d983dd058'
	
	target = TargetServer()
	target.ip = '192.168.9.15'
	target.hostname = 'FileServer'
	target.domain = 'TEST.corp' #the kerberos realm
	target.kerberos_ip = '192.168.9.1' #IP address of the kerberos server (active directory)
	
	ksoc = KerberosSocket(target.kerberos_ip)
	
	kc = KerbrosComm(ccred, target, ksoc)
	tgt = kc.get_TGT()
	tgs = kc.get_TGS()