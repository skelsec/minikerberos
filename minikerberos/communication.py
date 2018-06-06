from asn1_structs import *
from common import *
import datetime
import secrets
import socket

class KerbrosComm:
	def __init__(self,ccred, target):
		self.usercreds = ccred
		self.target = target
		
	def get_TGT(self):
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
		
		#pa_data_2 = {}
		#pa_data_2['padata-type'] = PADATA_TYPE('ENC-TIMESTAMP')
		#pa_data_2['padata-value'] = PA_ENC_TS_ENC({'patimestamp': True})
		
		kdc_req = {}
		kdc_req['pvno'] = krb5_pvno
		kdc_req['msg-type'] = int(MESSAGE_TYPE('krb-as-req'))
		kdc_req['padata'] = [pa_data_1]
		kdc_req['req-body'] = KDC_REQ_BODY(kdc_req_body)
		
		req = AS_REQ(kdc_req)
		print(req.dump())
		
		length = len(req.dump()).to_bytes(4, byteorder = 'big', signed = False)
		
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((self.target.kerberos_ip, 88))
		s.sendall(length + req.dump())
		
		data = s.recv(4096)
		print(data)
		
		
		
		
		
	def get_TGS(self):
		pass
		

if __name__ == '__main__':
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
	
	
	kc = KerbrosComm(ccred, target)
	tgt = kc.get_TGT()