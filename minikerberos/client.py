#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import collections
import datetime
import secrets

from minikerberos import logger
from minikerberos.common.ccache import CCACHE
from minikerberos.network.clientsocket import KerberosClientSocket
from minikerberos.protocol.asn1_structs import METHOD_DATA, ETYPE_INFO, ETYPE_INFO2, \
	PADATA_TYPE, PA_PAC_REQUEST, PA_ENC_TS_ENC, EncryptedData, krb5_pvno, KDC_REQ_BODY, \
	AS_REQ, KDCOptions, PrincipalName, EncASRepPart, EncTGSRepPart, PrincipalName, Realm, \
	Checksum, APOptions, Authenticator, Ticket, AP_REQ, TGS_REQ, CKSUMTYPE, \
	PA_FOR_USER_ENC, PA_PAC_OPTIONS, PA_PAC_OPTIONSTypes

from minikerberos.protocol.errors import KerberosErrorCode, KerberosError
from minikerberos.protocol.encryption import Key, _enctype_table, _HMACMD5
from minikerberos.protocol.constants import PaDataType, EncryptionType, NAME_TYPE, MESSAGE_TYPE
from minikerberos.protocol.structures import AuthenticatorChecksum

class KerbrosClient:
	def __init__(self, ccred, target, ccache = None):
		self.usercreds = ccred
		self.target = target
		self.ksoc = KerberosClientSocket(self.target)
		self.ccache = CCACHE() if ccache is None else ccache
		self.kerberos_session_key = None
		self.kerberos_TGT = None
		self.kerberos_TGT_encpart = None
		self.kerberos_TGS = None
		self.kerberos_cipher = None
		self.kerberos_cipher_type = None
		self.kerberos_key = None
		self.server_salt = None
		
	@staticmethod
	def from_tgt(target, tgt, key):
		"""
		Sets up the kerberos object from tgt and the session key.
		Use this function when pulling the TGT from ccache file.
		"""
		kc = KerbrosClient(None, target)
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
		
		now = datetime.datetime.now(datetime.timezone.utc)
		#creating timestamp asn1
		timestamp = PA_ENC_TS_ENC({'patimestamp': now.replace(microsecond=0), 'pausec': now.microsecond}).dump()
		
		supp_enc = self.usercreds.get_preferred_enctype(supp_enc_methods)
		logger.debug('Selecting common encryption type: %s' % supp_enc.name)
		self.kerberos_cipher = _enctype_table[supp_enc.value]
		self.kerberos_cipher_type = supp_enc.value
		if 'salt' in enc_info and enc_info['salt'] is not None:
			self.server_salt = enc_info['salt'].encode() 
		self.kerberos_key = Key(self.kerberos_cipher.enctype, self.usercreds.get_key_for_enctype(supp_enc, salt = self.server_salt))
		enc_timestamp = self.kerberos_cipher.encrypt(self.kerberos_key, 1, timestamp, None)
		
		pa_data_2 = {}
		pa_data_2['padata-type'] = int(PADATA_TYPE('ENC-TIMESTAMP'))
		pa_data_2['padata-value'] = EncryptedData({'etype': supp_enc.value, 'cipher': enc_timestamp}).dump()
		
		kdc_req_body = {}
		kdc_req_body['kdc-options'] = KDCOptions(set(['forwardable','renewable','proxiable']))
		kdc_req_body['cname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': [self.usercreds.username]})
		kdc_req_body['realm'] = self.usercreds.domain.upper()
		kdc_req_body['sname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': ['krbtgt', self.usercreds.domain.upper()]})
		kdc_req_body['till']  = (now + datetime.timedelta(days=1)).replace(microsecond=0)
		kdc_req_body['rtime'] = (now + datetime.timedelta(days=1)).replace(microsecond=0)
		kdc_req_body['nonce'] = secrets.randbits(31)
		kdc_req_body['etype'] = [supp_enc.value]

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
		logger.debug('[getTGT] Generating initial TGT without authentication data')
		now = datetime.datetime.now(datetime.timezone.utc)
		kdc_req_body = {}
		kdc_req_body['kdc-options'] = KDCOptions(set(['forwardable','renewable','proxiable']))
		kdc_req_body['cname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': [self.usercreds.username]})
		kdc_req_body['realm'] = self.usercreds.domain.upper()
		kdc_req_body['sname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': ['krbtgt', self.usercreds.domain.upper()]})
		kdc_req_body['till']  = (now + datetime.timedelta(days=1)).replace(microsecond=0)
		kdc_req_body['rtime'] = (now + datetime.timedelta(days=1)).replace(microsecond=0)
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
		
		logger.debug('[getTGT] Sending initial TGT to %s' % self.ksoc.get_addr_str())
		rep = self.ksoc.sendrecv(req.dump(), throw = False)

		if rep.name != 'KRB_ERROR':
			#user can do kerberos auth without preauthentication!
			self.kerberos_TGT = rep.native

			etype = self.kerberos_TGT['enc-part']['etype']

			#if we want to roast the asrep (tgt rep) part then we dont even have the proper keys to decrypt
			#so we just return, the asrep can be extracted from this object anyhow
			if decrypt_tgt == False:
				return

			self.kerberos_cipher = _enctype_table[etype]
			self.kerberos_cipher_type = etype
			encryption_type = EncryptionType(self.kerberos_cipher.enctype)
			enctype = self.usercreds.get_key_for_enctype(encryption_type)
			self.kerberos_key = Key(self.kerberos_cipher.enctype, enctype)
			
		else:
			if rep.native['error-code'] != KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED.value:
				raise KerberosError(rep)
			rep = rep.native
			logger.debug('[getTGT] Got reply from server, asking to provide auth data')
			
			rep = self.do_preauth(rep)
			logger.debug('[getTGT] Got valid response from server')
			rep = rep.native
			self.kerberos_TGT = rep

		cipherText = self.kerberos_TGT['enc-part']['cipher']
		temp = self.kerberos_cipher.decrypt(self.kerberos_key, 3, cipherText)
		try:
			self.kerberos_TGT_encpart = EncASRepPart.load(temp).native
		except Exception as e:
			logger.debug('[getTGT] EncAsRepPart load failed, is this linux?')
			try:
				self.kerberos_TGT_encpart = EncTGSRepPart.load(temp).native
			except Exception as e:
				logger.error('[getTGT] Failed to load decrypted part of the reply!')
				raise e
				
		self.kerberos_session_key = Key(self.kerberos_cipher.enctype, self.kerberos_TGT_encpart['key']['keyvalue'])
		self.ccache.add_tgt(self.kerberos_TGT, self.kerberos_TGT_encpart, override_pp = True)
		logger.debug('[getTGT] Got valid TGT')
		
		return 
		
	def get_TGS(self, spn_user, override_etype = None, is_linux = False):
		"""
		Requests a TGS ticket for the specified user.
		Returns the TGS ticket, end the decrpyted encTGSRepPart.

		spn_user: KerberosTarget: the service user you want to get TGS for.
		override_etype: None or list of etype values (int) Used mostly for kerberoasting, will override the AP_REQ supported etype values (which is derived from the TGT) to be able to recieve whatever tgs tiecket 
		"""

		logger.debug('[getTGS] Constructing request for user %s' % spn_user.get_formatted_pname())
		now = datetime.datetime.now(datetime.timezone.utc)
		kdc_req_body = {}
		kdc_req_body['kdc-options'] = KDCOptions(set(['forwardable','renewable','renewable_ok', 'canonicalize']))
		kdc_req_body['realm'] = spn_user.domain.upper()
		kdc_req_body['sname'] = PrincipalName({'name-type': NAME_TYPE.SRV_INST.value, 'name-string': spn_user.get_principalname()})
		kdc_req_body['till'] = (now + datetime.timedelta(days=1)).replace(microsecond=0)
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
		authenticator_data['ctime'] = now.replace(microsecond=0)
		
		if is_linux:
			ac = AuthenticatorChecksum()
			ac.flags = 0
			ac.channel_binding = b'\x00'*16
			
			chksum = {}
			chksum['cksumtype'] = 0x8003
			chksum['checksum'] = ac.to_bytes()
			print(chksum['checksum'])
			
			authenticator_data['cksum'] = Checksum(chksum)
			authenticator_data['seq-number'] = 0
		
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
		logger.debug('[getTGS] Constructing request to server')
		rep = self.ksoc.sendrecv(req.dump())
		logger.debug('[getTGS] Got reply, decrypting...')
		tgs = rep.native
		
		encTGSRepPart = EncTGSRepPart.load(self.kerberos_cipher.decrypt(self.kerberos_session_key, 8, tgs['enc-part']['cipher'])).native
		key = Key(encTGSRepPart['key']['keytype'], encTGSRepPart['key']['keyvalue'])
		
		self.ccache.add_tgs(tgs, encTGSRepPart)
		logger.debug('[getTGS] Got valid reply')
		self.kerberos_TGS = tgs
		return tgs, encTGSRepPart, key
	
	#https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/6a8dfc0c-2d32-478a-929f-5f9b1b18a169
	def S4U2self(self, user_to_impersonate, supp_enc_methods = [EncryptionType.DES_CBC_CRC,EncryptionType.DES_CBC_MD4,EncryptionType.DES_CBC_MD5,EncryptionType.DES3_CBC_SHA1,EncryptionType.ARCFOUR_HMAC_MD5,EncryptionType.AES256_CTS_HMAC_SHA1_96,EncryptionType.AES128_CTS_HMAC_SHA1_96]):
		"""
		user_to_impersonate : KerberosTarget class
		"""
		
		if not self.kerberos_TGT:
			logger.debug('[S4U2self] TGT is not available! Fetching TGT...')
			self.get_TGT()
		
		supp_enc = self.usercreds.get_preferred_enctype(supp_enc_methods)
		auth_package_name = 'Kerberos'
		now = datetime.datetime.now(datetime.timezone.utc)
		
		
		###### Calculating authenticator data
		authenticator_data = {}
		authenticator_data['authenticator-vno'] = krb5_pvno
		authenticator_data['crealm'] = Realm(self.kerberos_TGT['crealm'])
		authenticator_data['cname'] = self.kerberos_TGT['cname']
		authenticator_data['cusec'] = now.microsecond
		authenticator_data['ctime'] = now.replace(microsecond=0)
		
		authenticator_data_enc = self.kerberos_cipher.encrypt(self.kerberos_session_key, 7, Authenticator(authenticator_data).dump(), None)
		
		ap_req = {}
		ap_req['pvno'] = krb5_pvno
		ap_req['msg-type'] = MESSAGE_TYPE.KRB_AP_REQ.value
		ap_req['ap-options'] = APOptions(set())
		ap_req['ticket'] = Ticket(self.kerberos_TGT['ticket'])
		ap_req['authenticator'] = EncryptedData({'etype': self.kerberos_cipher_type, 'cipher': authenticator_data_enc})
		
		pa_data_auth = {}
		pa_data_auth['padata-type'] = PaDataType.TGS_REQ.value
		pa_data_auth['padata-value'] = AP_REQ(ap_req).dump()
		
		###### Calculating checksum data
		
		S4UByteArray = NAME_TYPE.PRINCIPAL.value.to_bytes(4, 'little', signed = False)
		S4UByteArray += user_to_impersonate.username.encode()
		S4UByteArray += user_to_impersonate.domain.encode()
		S4UByteArray += auth_package_name.encode()
		logger.debug('[S4U2self] S4UByteArray: %s' % S4UByteArray.hex())
		logger.debug('[S4U2self] S4UByteArray: %s' % S4UByteArray)
		
		chksum_data = _HMACMD5.checksum(self.kerberos_session_key, 17, S4UByteArray)
		logger.debug('[S4U2self] chksum_data: %s' % chksum_data.hex())
		
		
		chksum = {}
		chksum['cksumtype'] = int(CKSUMTYPE('HMAC_MD5'))
		chksum['checksum'] = chksum_data

		
		###### Filling out PA-FOR-USER data for impersonation
		pa_for_user_enc = {}
		pa_for_user_enc['userName'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': user_to_impersonate.get_principalname()})
		pa_for_user_enc['userRealm'] = user_to_impersonate.domain
		pa_for_user_enc['cksum'] = Checksum(chksum)
		pa_for_user_enc['auth-package'] = auth_package_name
		
		pa_for_user = {}
		pa_for_user['padata-type'] = int(PADATA_TYPE('PA-FOR-USER'))
		pa_for_user['padata-value'] = PA_FOR_USER_ENC(pa_for_user_enc).dump()
	
		###### Constructing body
		
		krb_tgs_body = {}
		krb_tgs_body['kdc-options'] = KDCOptions(set(['forwardable','renewable','canonicalize']))
		krb_tgs_body['sname'] = PrincipalName({'name-type': NAME_TYPE.UNKNOWN.value, 'name-string': [self.usercreds.username]})
		krb_tgs_body['realm'] = self.usercreds.domain.upper()
		krb_tgs_body['till']  = (now + datetime.timedelta(days=1)).replace(microsecond=0)
		krb_tgs_body['nonce'] = secrets.randbits(31)
		krb_tgs_body['etype'] = [supp_enc.value] #selecting according to server's preferences
		
		
		krb_tgs_req = {}
		krb_tgs_req['pvno'] = krb5_pvno
		krb_tgs_req['msg-type'] = MESSAGE_TYPE.KRB_TGS_REQ.value
		krb_tgs_req['padata'] = [pa_data_auth, pa_for_user]
		krb_tgs_req['req-body'] = KDC_REQ_BODY(krb_tgs_body)
		
		req = TGS_REQ(krb_tgs_req)
		
		logger.debug('[S4U2self] Sending request to server')
		try:
			reply = self.ksoc.sendrecv(req.dump())
		except KerberosError as e:
			if e.errorcode.value == 16:
				logger.error('[S4U2self] Failed to get S4U2self! Error code (16) indicates that delegation is not enabled for this account! Full error: %s' % e)
			
			raise e
		
		logger.debug('[S4U2self] Got reply, decrypting...')
		tgs = reply.native
		
		encTGSRepPart = EncTGSRepPart.load(self.kerberos_cipher.decrypt(self.kerberos_session_key, 8, tgs['enc-part']['cipher'])).native
		key = Key(encTGSRepPart['key']['keytype'], encTGSRepPart['key']['keyvalue'])
		
		self.ccache.add_tgs(tgs, encTGSRepPart)
		logger.debug('[S4U2self] Got valid TGS reply')
		self.kerberos_TGS = tgs
		return tgs, encTGSRepPart, key
				
		
	# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/c920c148-8a9c-42e9-b8e9-db5755cd281b
	def S4U2proxy(self, s4uself_ticket, spn_user, supp_enc_methods = [EncryptionType.DES_CBC_CRC,EncryptionType.DES_CBC_MD4,EncryptionType.DES_CBC_MD5,EncryptionType.DES3_CBC_SHA1,EncryptionType.ARCFOUR_HMAC_MD5,EncryptionType.AES256_CTS_HMAC_SHA1_96,EncryptionType.AES128_CTS_HMAC_SHA1_96]):
		logger.debug('[S4U2proxy] Impersonating %s' % '/'.join(spn_user.get_principalname()))
		now = datetime.datetime.now(datetime.timezone.utc)
		supp_enc = self.usercreds.get_preferred_enctype(supp_enc_methods)
		
		pa_pac_opts = {}
		pa_pac_opts['padata-type'] = int(PADATA_TYPE('PA-PAC-OPTIONS'))
		pa_pac_opts['padata-value'] = PA_PAC_OPTIONS({'value' : PA_PAC_OPTIONSTypes(set(['resource-based constrained delegation']))}).dump()

		
		authenticator_data = {}
		authenticator_data['authenticator-vno'] = krb5_pvno
		authenticator_data['crealm'] = Realm(self.kerberos_TGT['crealm'])
		authenticator_data['cname'] = self.kerberos_TGT['cname']
		authenticator_data['cusec'] = now.microsecond
		authenticator_data['ctime'] = now.replace(microsecond=0)
		
		authenticator_data_enc = self.kerberos_cipher.encrypt(self.kerberos_session_key, 7, Authenticator(authenticator_data).dump(), None)
		
		ap_req = {}
		ap_req['pvno'] = krb5_pvno
		ap_req['msg-type'] = MESSAGE_TYPE.KRB_AP_REQ.value
		ap_req['ap-options'] = APOptions(set())
		ap_req['ticket'] = Ticket(self.kerberos_TGT['ticket'])
		ap_req['authenticator'] = EncryptedData({'etype': self.kerberos_cipher_type, 'cipher': authenticator_data_enc})
		
		pa_tgs_req = {}
		pa_tgs_req['padata-type'] = PaDataType.TGS_REQ.value
		pa_tgs_req['padata-value'] = AP_REQ(ap_req).dump()
		
		
		krb_tgs_body = {}
		krb_tgs_body['kdc-options'] = KDCOptions(set(['forwardable','renewable','constrained-delegation', 'canonicalize']))
		krb_tgs_body['sname'] = PrincipalName({'name-type': NAME_TYPE.SRV_INST.value, 'name-string': spn_user.get_principalname()})
		krb_tgs_body['realm'] = self.usercreds.domain.upper()
		krb_tgs_body['till']  = (now + datetime.timedelta(days=1)).replace(microsecond=0)
		krb_tgs_body['nonce'] = secrets.randbits(31)
		krb_tgs_body['etype'] = [supp_enc.value] #selecting according to server's preferences
		krb_tgs_body['additional-tickets'] = [s4uself_ticket]
		
		
		krb_tgs_req = {}
		krb_tgs_req['pvno'] = krb5_pvno
		krb_tgs_req['msg-type'] = MESSAGE_TYPE.KRB_TGS_REQ.value
		krb_tgs_req['padata'] = [pa_tgs_req, pa_pac_opts]
		krb_tgs_req['req-body'] = KDC_REQ_BODY(krb_tgs_body)
		
		req = TGS_REQ(krb_tgs_req)
		logger.debug('[S4U2proxy] Sending request to server')
		try:
			reply = self.ksoc.sendrecv(req.dump())
		except KerberosError as e:
			if e.errorcode.value == 16:
				logger.error('S4U2proxy: Failed to get S4U2proxy! Error code (16) indicates that delegation is not enabled for this account! Full error: %s' % e)
			
			raise e
		logger.debug('[S4U2proxy] Got server reply, decrypting...')
		tgs = reply.native
		
		encTGSRepPart = EncTGSRepPart.load(self.kerberos_cipher.decrypt(self.kerberos_session_key, 8, tgs['enc-part']['cipher'])).native
		key = Key(encTGSRepPart['key']['keytype'], encTGSRepPart['key']['keyvalue'])
		
		self.ccache.add_tgs(tgs, encTGSRepPart)
		logger.debug('[S4U2proxy] Got valid TGS reply')

		return tgs, encTGSRepPart, key
		
	#def get_something(self, tgs, encTGSRepPart, sessionkey):
	#	now = datetime.datetime.now(datetime.timezone.utc)
	#	authenticator_data = {}
	#	authenticator_data['authenticator-vno'] = krb5_pvno
	#	authenticator_data['crealm'] = Realm(self.kerberos_TGT['crealm'])
	#	authenticator_data['cname'] = self.kerberos_TGT['cname']
	#	authenticator_data['cusec'] = now.microsecond
	#	authenticator_data['ctime'] = now.replace(microsecond=0)
	#	
	#	cipher = _enctype_table[encTGSRepPart['key']['keytype']]
	#	authenticator_data_enc = cipher.encrypt(sessionkey, 11, Authenticator(authenticator_data).dump(), None)
	#	
	#	ap_req = {}
	#	ap_req['pvno'] = krb5_pvno
	#	ap_req['msg-type'] = MESSAGE_TYPE.KRB_AP_REQ.value
	#	ap_req['ticket'] = Ticket(tgs['ticket'])
	#	ap_req['ap-options'] = APOptions(set([]))
	#	ap_req['authenticator'] = EncryptedData({'etype': self.kerberos_cipher_type, 'cipher': authenticator_data_enc})
	#
	#	return AP_REQ(ap_req).dump()

	def construct_apreq(self, tgs, encTGSRepPart, sessionkey, flags = None, seq_number = 0, ap_opts = []):
		now = datetime.datetime.now(datetime.timezone.utc)
		authenticator_data = {}
		authenticator_data['authenticator-vno'] = krb5_pvno
		authenticator_data['crealm'] = Realm(self.kerberos_TGT['crealm'])
		authenticator_data['cname'] = self.kerberos_TGT['cname']
		authenticator_data['cusec'] = now.microsecond
		authenticator_data['ctime'] = now.replace(microsecond=0)
		if flags is not None:
			ac = AuthenticatorChecksum()
			ac.flags = flags
			ac.channel_binding = b'\x00'*16
			
			chksum = {}
			chksum['cksumtype'] = 0x8003
			chksum['checksum'] = ac.to_bytes()
			
			authenticator_data['cksum'] = Checksum(chksum)
			authenticator_data['seq-number'] = seq_number
		
		cipher = _enctype_table[encTGSRepPart['key']['keytype']]
		authenticator_data_enc = cipher.encrypt(sessionkey, 11, Authenticator(authenticator_data).dump(), None)
		
		ap_req = {}
		ap_req['pvno'] = krb5_pvno
		ap_req['msg-type'] = MESSAGE_TYPE.KRB_AP_REQ.value
		ap_req['ticket'] = Ticket(tgs['ticket'])
		ap_req['ap-options'] = APOptions(set(ap_opts))
		ap_req['authenticator'] = EncryptedData({'etype': self.kerberos_cipher_type, 'cipher': authenticator_data_enc})

		return AP_REQ(ap_req).dump()

	@staticmethod
	def construct_apreq_from_ticket(ticket_data, sessionkey, crealm, cname, flags = None, seq_number = 0, ap_opts = []):
		"""
		ticket: bytes of Ticket
		"""
		now = datetime.datetime.now(datetime.timezone.utc)
		authenticator_data = {}
		authenticator_data['authenticator-vno'] = krb5_pvno
		authenticator_data['crealm'] = Realm(crealm)
		authenticator_data['cname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': [cname]})
		authenticator_data['cusec'] = now.microsecond
		authenticator_data['ctime'] = now.replace(microsecond=0)
		if flags is not None:
			ac = AuthenticatorChecksum()
			ac.flags = flags
			ac.channel_binding = b'\x00'*16
			
			chksum = {}
			chksum['cksumtype'] = 0x8003
			chksum['checksum'] = ac.to_bytes()
			
			authenticator_data['cksum'] = Checksum(chksum)
			authenticator_data['seq-number'] = seq_number
		
		cipher = _enctype_table[sessionkey.enctype]
		authenticator_data_enc = cipher.encrypt(sessionkey, 11, Authenticator(authenticator_data).dump(), None)
		
		ap_req = {}
		ap_req['pvno'] = krb5_pvno
		ap_req['msg-type'] = MESSAGE_TYPE.KRB_AP_REQ.value
		ap_req['ticket'] = Ticket.load(ticket_data)
		ap_req['ap-options'] = APOptions(set(ap_opts))
		ap_req['authenticator'] = EncryptedData({'etype': sessionkey.enctype, 'cipher': authenticator_data_enc})

		return AP_REQ(ap_req).dump()
		

	def getST(self, target_user, service_spn):
		tgs, encTGSRepPart, key = self.S4U2self(target_user)
		return self.S4U2proxy(tgs['ticket'], service_spn)
