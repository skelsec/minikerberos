#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import collections
import datetime
import secrets
import socket
import logging

from minikerberos import logger
from minikerberos.asn1_structs import *
from minikerberos.kerberoserror import *
from minikerberos.constants import *
from minikerberos.common import *
from minikerberos.ccache import *
from minikerberos.encryption import _enctype_table, Key


class KerberosSocketType(enum.Enum):
	UDP = enum.auto()
	TCP = enum.auto()
	
class KerberosSocket:
	def __init__(self, ip, port = 88, soc_type = KerberosSocketType.TCP):
		self.soc_type = soc_type
		self.dst_ip = ip
		self.dst_port = int(port)
		self.soc = None
		
	def get_addr_str(self):
		return '%s:%d' % (self.dst_ip, self.dst_port)
		
	def create_soc(self):
		if self.soc_type == KerberosSocketType.TCP:
			self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.soc.connect((self.dst_ip, self.dst_port))
			
			
		elif self.soc_type == KerberosSocketType.UDP:
			self.soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			
		else:
			raise Exception('Unknown socket type!')
			
	def sendrecv(self, data, throw = True):
		self.create_soc()
		try:
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
				self.soc.sendto(data, (self.dst_ip, self.dst_port))
				while True:
					buff, addr = self.soc.recvfrom(65535)
					if addr[0] == self.dst_ip:
						break
					else:
						# got a message from a different IP than the target, strange!
						# continuing, but this might result in an infinite loop
						continue
			
			krb_message = KerberosResponse.load(buff)
			if krb_message.name == 'KRB_ERROR' and throw == True:
				raise KerberosError(krb_message)
			return krb_message
		finally:
			self.soc.close()
		
		

class KerbrosComm:
	def __init__(self,ccred, ksoc, ccache = None):
		self.usercreds = ccred
		self.ksoc = ksoc
		self.user_ccache = ccache
		self.ccache = CCACHE()
		self.kerberos_session_key = None
		self.kerberos_TGT = None
		self.kerberos_TGS = None
		self.kerberos_cipher = None
		self.kerberos_cipher_type = None
		self.kerberos_key = None
		
	@staticmethod
	def from_tgt(ksoc, tgt, key):
		"""
		Sets up the kerberos object from tgt and the session key.
		Use this function when pulling the TGT from ccache file.
		"""
		kc = KerbrosComm(None, ksoc)
		kc.kerberos_TGT = tgt
		
		kc.kerberos_cipher_type = key['keytype']
		kc.kerberos_session_key = Key(kc.kerberos_cipher_type, key['keyvalue']) 
		kc.kerberos_cipher = _enctype_table[kc.kerberos_cipher_type]
		return kc

	def do_preauth(self, rep):
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
					logger.debug('Server supports encryption type %s with salt %s' % (EncryptionType(enc_info['etype']).name, enc_info['salt']))
		
		logger.debug('Constructing TGT request with auth data')
		#now to create an AS_REQ with encrypted timestamp for authentication
		pa_data_1 = {}
		pa_data_1['padata-type'] = int(PADATA_TYPE('PA-PAC-REQUEST'))
		pa_data_1['padata-value'] = PA_PAC_REQUEST({'include-pac': True}).dump()
		
		now = datetime.datetime.utcnow()
		#creating timestamp asn1
		timestamp = PA_ENC_TS_ENC({'patimestamp': now, 'pausec': now.microsecond}).dump()
		
		supp_enc = self.usercreds.get_preferred_enctype(supp_enc_methods)
		logger.debug('Selecting common encryption type: %s' % supp_enc.name)
		self.kerberos_cipher = _enctype_table[supp_enc.value]
		self.kerberos_cipher_type = supp_enc.value
		self.kerberos_key = Key(self.kerberos_cipher.enctype, self.usercreds.get_key_for_enctype(supp_enc))
		enc_timestamp = self.kerberos_cipher.encrypt(self.kerberos_key, 1, timestamp, None)
		
		
		pa_data_2 = {}
		pa_data_2['padata-type'] = int(PADATA_TYPE('ENC-TIMESTAMP'))
		pa_data_2['padata-value'] = EncryptedData({'etype': supp_enc.value, 'cipher': enc_timestamp}).dump()
		
		
		
		kdc_req_body = {}
		kdc_req_body['kdc-options'] = KDCOptions(set(['forwardable','renewable','proxiable']))
		kdc_req_body['cname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': [self.usercreds.username]})
		kdc_req_body['realm'] = self.usercreds.domain.upper()
		kdc_req_body['sname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': ['krbtgt', self.usercreds.domain.upper()]})
		kdc_req_body['till'] = now + datetime.timedelta(days=1)
		kdc_req_body['rtime'] = now + datetime.timedelta(days=1)
		kdc_req_body['nonce'] = secrets.randbits(31)
		kdc_req_body['etype'] = [supp_enc.value] #selecting according to server's preferences
		
		
		kdc_req = {}
		kdc_req['pvno'] = krb5_pvno
		kdc_req['msg-type'] = MESSAGE_TYPE.KRB_AS_REQ.value
		kdc_req['padata'] = [pa_data_2,pa_data_1]
		kdc_req['req-body'] = KDC_REQ_BODY(kdc_req_body)
		
		req = AS_REQ(kdc_req)
		
		logger.debug('Sending TGT request to server')
		return self.ksoc.sendrecv(req.dump())

	def get_TGT(self, override_etype = None, decrypt_tgt = True):
		"""
		decrypt_tgt: used for asreproast attacks
		Steps performed:
			1. Send and empty (no encrypted timestamp) AS_REQ with all the encryption types we support
			2. Depending on the response (either error or AS_REP with TGT) we either send another AS_REQ with the encrypted data or return the TGT (or fail miserably)
			3. PROFIT
		"""
		logger.debug('Generating initial TGT without authentication data')
		now = datetime.datetime.utcnow()
		kdc_req_body = {}
		kdc_req_body['kdc-options'] = KDCOptions(set(['forwardable','renewable','proxiable']))
		kdc_req_body['cname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': [self.usercreds.username]})
		kdc_req_body['realm'] = self.usercreds.domain.upper()
		kdc_req_body['sname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': ['krbtgt', self.usercreds.domain.upper()]})
		kdc_req_body['till'] = now + datetime.timedelta(days=1)
		kdc_req_body['rtime'] = now + datetime.timedelta(days=1)
		kdc_req_body['nonce'] = secrets.randbits(31)
		if override_etype is None:
			kdc_req_body['etype'] = self.usercreds.get_supported_enctypes()
		else:
			kdc_req_body['etype'] = override_etype

		pa_data_1 = {}
		pa_data_1['padata-type'] = int(PADATA_TYPE('PA-PAC-REQUEST'))
		pa_data_1['padata-value'] = PA_PAC_REQUEST({'include-pac': True}).dump()
		
		kdc_req = {}
		kdc_req['pvno'] = krb5_pvno
		kdc_req['msg-type'] = MESSAGE_TYPE.KRB_AS_REQ.value
		kdc_req['padata'] = [pa_data_1]
		kdc_req['req-body'] = KDC_REQ_BODY(kdc_req_body)
		
		req = AS_REQ(kdc_req)	
		
		logger.debug('Sending initial TGT to %s' % self.ksoc.get_addr_str())
		rep = self.ksoc.sendrecv(req.dump(), throw = False)
				
		if rep.name != 'KRB_ERROR':
			#user can do kerberos auth without preauthentication!
			self.kerberos_TGT = rep.native

			#if we want to roast the asrep (tgt rep) part then we dont even have the proper keys to decrypt
			#so we just return, the asrep can be extracted from this object anyhow
			if decrypt_tgt == False:
				return

			self.kerberos_cipher = _enctype_table[23]
			self.kerberos_cipher_type = 23
			self.kerberos_key = Key(self.kerberos_cipher.enctype, self.usercreds.get_key_for_enctype(EncryptionType.ARCFOUR_HMAC_MD5))
			
		else:
			if rep.native['error-code'] != KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED.value:
				raise KerberosError(rep)
			rep = rep.native
			logger.debug('Got reply from server, asikg to provide auth data')
			
			rep = self.do_preauth(rep)
			logger.debug('Got valid TGT response from server')
			rep = rep.native
			self.kerberos_TGT = rep


		cipherText = rep['enc-part']['cipher']
		temp = self.kerberos_cipher.decrypt(self.kerberos_key, 3, cipherText)
		enc_as_rep_part = EncASRepPart.load(temp).native
		self.kerberos_session_key = Key(self.kerberos_cipher.enctype, enc_as_rep_part['key']['keyvalue'])
		self.ccache.add_tgt(self.kerberos_TGT, enc_as_rep_part)
		logger.debug('Got valid TGT')
		
		return 
		
	def get_TGS(self, spn_user, override_etype = None):
		"""
		Requests a TGS ticket for the specified user.
		Retruns the TGS ticket, end the decrpyted encTGSRepPart.

		spn_user: KerberosTarget: the service user you want to get TGS for.
		override_etype: None or list of etype values (int) Used mostly for kerberoasting, will override the AP_REQ supported etype values (which is derived from the TGT) to be able to recieve whatever tgs tiecket 
		"""
		#construct tgs_req
		logger.debug('Constructing TGS request for user %s' % spn_user.get_formatted_pname())
		now = datetime.datetime.utcnow() 
		kdc_req_body = {}
		kdc_req_body['kdc-options'] = KDCOptions(set(['forwardable','renewable','renewable_ok', 'canonicalize']))
		kdc_req_body['realm'] = spn_user.domain.upper()
		kdc_req_body['sname'] = PrincipalName({'name-type': NAME_TYPE.SRV_INST.value, 'name-string': spn_user.get_principalname()})
		kdc_req_body['till'] = now + datetime.timedelta(days=1)
		kdc_req_body['nonce'] = secrets.randbits(31)
		if override_etype:
			kdc_req_body['etype'] = override_etype
		else:
			kdc_req_body['etype'] = [self.kerberos_cipher_type]

		authenticator_data = {}
		authenticator_data['authenticator-vno'] = krb5_pvno
		authenticator_data['crealm'] = Realm(self.kerberos_TGT['crealm'])
		authenticator_data['cname'] = self.kerberos_TGT['cname']
		authenticator_data['cusec'] = now.microsecond
		authenticator_data['ctime'] = now
		
		authenticator_data_enc = self.kerberos_cipher.encrypt(self.kerberos_session_key, 7, Authenticator(authenticator_data).dump(), None)
		
		ap_req = {}
		ap_req['pvno'] = krb5_pvno
		ap_req['msg-type'] = MESSAGE_TYPE.KRB_AP_REQ.value
		ap_req['ap-options'] = APOptions(set())
		ap_req['ticket'] = Ticket(self.kerberos_TGT['ticket'])
		ap_req['authenticator'] = EncryptedData({'etype': self.kerberos_cipher_type, 'cipher': authenticator_data_enc})
		
		pa_data_1 = {}
		pa_data_1['padata-type'] = PaDataType.TGS_REQ.value
		pa_data_1['padata-value'] = AP_REQ(ap_req).dump()
		
		
		kdc_req = {}
		kdc_req['pvno'] = krb5_pvno
		kdc_req['msg-type'] = MESSAGE_TYPE.KRB_TGS_REQ.value
		kdc_req['padata'] = [pa_data_1]
		kdc_req['req-body'] = KDC_REQ_BODY(kdc_req_body)
		
		req = TGS_REQ(kdc_req)
		logger.debug('Constructing TGS request to server')
		rep = self.ksoc.sendrecv(req.dump())
		logger.debug('Got TGS reply, decrypting...')
		tgs = rep.native
		
		encTGSRepPart = EncTGSRepPart.load(self.kerberos_cipher.decrypt(self.kerberos_session_key, 8, tgs['enc-part']['cipher'])).native
		key = Key(encTGSRepPart['key']['keytype'], encTGSRepPart['key']['keyvalue'])
		
		self.ccache.add_tgs(tgs, encTGSRepPart)
		logger.debug('Got valid TGS reply')
		self.kerberos_TGS = tgs
		return tgs, encTGSRepPart, key
		
		
	def get_something(self, tgs, encTGSRepPart, sessionkey):
		now = datetime.datetime.utcnow() 
		authenticator_data = {}
		authenticator_data['authenticator-vno'] = krb5_pvno
		authenticator_data['crealm'] = Realm(self.kerberos_TGT['crealm'])
		authenticator_data['cname'] = self.kerberos_TGT['cname']
		authenticator_data['cusec'] = now.microsecond
		authenticator_data['ctime'] = now
		
		print(encTGSRepPart['key']['keytype'])
		cipher = _enctype_table[encTGSRepPart['key']['keytype']]
		authenticator_data_enc = cipher.encrypt(sessionkey, 11, Authenticator(authenticator_data).dump(), None)
		
		ap_req = {}
		ap_req['pvno'] = krb5_pvno
		ap_req['msg-type'] = MESSAGE_TYPE.KRB_AP_REQ.value
		ap_req['ticket'] = Ticket(tgs['ticket'])
		ap_req['ap-options'] = APOptions(set([]))
		ap_req['authenticator'] = EncryptedData({'etype': self.kerberos_cipher_type, 'cipher': authenticator_data_enc})

		return AP_REQ(ap_req).dump()


		
		

if __name__ == '__main__':
	logger.setLevel(logging.DEBUG)
	
	ccred = User()
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
	target.service = 'cifs'
	target.domain = 'TEST.corp' #the kerberos realm
	target.kerberos_ip = '192.168.9.1' #IP address of the kerberos server (active directory)
	
	ksoc = KerberosSocket(target.kerberos_ip)
	
	kc = KerbrosComm(ccred, ksoc)
	tgt = kc.get_TGT()
	tgs = kc.get_TGS(target)
	kc.ccache.to_file('test.ccache')