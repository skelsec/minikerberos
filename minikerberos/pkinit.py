
# Kudos:
# Parts of this code was inspired by the following project by @rubin_mor
# https://github.com/morRubin/AzureADJoinedMachinePTC
# 

# TODO: code currently supports RSA+DH+SHA1 , add support for other mechanisms


import os
import datetime
import secrets
import platform

from unicrypto import hashlib
from asn1crypto import cms
from asn1crypto import algos
from asn1crypto import core
from asn1crypto import x509
from asn1crypto import keys

from cryptography.hazmat.primitives.asymmetric.dh import generate_parameters
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding

from minikerberos.protocol.constants import NAME_TYPE, MESSAGE_TYPE, PaDataType
from minikerberos.protocol.encryption import Enctype, _checksum_table, _enctype_table, Key
from minikerberos.protocol.structures import AuthenticatorChecksum
from minikerberos.protocol.asn1_structs import KDC_REQ_BODY, PrincipalName, HostAddress, \
	KDCOptions, EncASRepPart, AP_REQ, AuthorizationData, Checksum, krb5_pvno, Realm, \
	EncryptionKey, Authenticator, Ticket, APOptions, EncryptedData, AS_REQ, AP_REP
from minikerberos.protocol.rfc4556 import PKAuthenticator, AuthPack, Dunno1, Dunno2, MetaData, Info, CertIssuer, CertIssuers, PA_PK_AS_REP, KDCDHKeyInfo
from minikerberos.protocol.rfc_iakerb import KRB_FINISHED
from minikerberos.protocol.mskile import LSAP_TOKEN_INFO_INTEGRITY, KERB_AD_RESTRICTION_ENTRY, KERB_AD_RESTRICTION_ENTRYS
from minikerberos.gssapi.gssapi import GSSAPIFlags

def length_encode(x):
	if x <= 127:
		return x.to_bytes(1, 'big', signed = False)
	else:
		lb = x.to_bytes((x.bit_length() + 7) // 8, 'big')
		t = (0x80 | len(lb)).to_bytes(1, 'big', signed = False)
		return t+lb


class DirtyDH:
	def __init__(self):
		self.p = None
		self.g = None
		self.shared_key = None
		self.shared_key_int = None
		self.private_key = os.urandom(32)
		self.private_key_int = int(self.private_key.hex(), 16)
		self.dh_nonce = os.urandom(32)

	@staticmethod
	def from_params(p, g):
		dd = DirtyDH()
		dd.p = p
		dd.g = g
		return dd

	@staticmethod
	def from_dict(dhp):
		dd = DirtyDH()
		dd.p = dhp['p']
		dd.g = dhp['g']
		return dd

	@staticmethod
	def from_asn1(asn1_bytes):
		dhp = algos.DHParameters.load(asn1_bytes).native
		return DirtyDH.from_dict(dhp)
		
	
	def get_public_key(self):
		#y = g^x mod p
		return pow(self.g, self.private_key_int, self.p)
	
	def exchange(self, bob_int):
		self.shared_key_int = pow(bob_int, self.private_key_int, self.p)
		x = hex(self.shared_key_int)[2:]
		if len(x) % 2 != 0:
			x = '0' + x
		self.shared_key = bytes.fromhex(x)
		return self.shared_key


class PKINIT:
	def __init__(self):
		self.certificate = None
		self.extra_certs = None
		self.user_sid = None
		self.user_name = None
		self.issuer = None
		self.cname = None
		self.diffie = None
		self.__hcert = None


	def init_windows_cert(self, username, certstore_name = 'MY', cert_serial = None):
		from minikerberos.common.windows.crypt32 import find_cert_by_cn
		self.certificate, self.__hcert = find_cert_by_cn(username, certstore_name)
		

	@staticmethod
	def from_windows_certstore(username, certstore_name = 'MY', cert_serial = None, dh_params = None):
		pkinit = PKINIT()
		pkinit.init_windows_cert(username, certstore_name = certstore_name, cert_serial = cert_serial)
		pkinit.setup(dh_params = dh_params)
		return pkinit


	@staticmethod
	def from_pfx(pfxfile, pfxpass, dh_params = None):
		pkinit = PKINIT()
		#print('Loading pfx12')		
		if isinstance(pfxpass, str):
			pfxpass = pfxpass.encode()
		with open(pfxfile, 'rb') as f:
			pkinit.privkey, cert, pkinit.extra_certs = pkcs12.load_key_and_certificates(f.read(), password = pfxpass)
			cert_der = cert.public_bytes(encoding=Encoding.DER)
			pkinit.certificate = x509.Certificate.load(cert_der)

		#print('pfx12 loaded!')
		pkinit.setup(dh_params = dh_params)
		return pkinit
	
	def setup(self, dh_params = None):
		# In Microsoft ecosystem there seem to be two main naming conventions for their certificates' subjects:
		# - For AD, the principal's distinguished name a.k.a NT-X500-PRINCIPAL (there are others too but not supported here)
		# - For EntraID, something not standard like "<principal SID>/<principal EntraID GUID>/login.windows.net/<tenant GUID>/<principal email>" e.g:
		# 	S-1-12-1-2190073739-1304874406-157446548-3757931170/c26d6885-f0df-4642-8207-5a38c93d2347/login.windows.net/e5bdbab1-eaba-4c81-b953-67e45605e0d8/testuser@bloody.corp
		#
		# minkrb doesn't handle as-req with NT-X500-PRINCIPAL so we'll try to extract the UPN/DNS in the SAN or the sAMAccountName in the CN as last resort hoping they're identical
		#
		# Mapping reference: "[MS-PKCA] 3.1.5.2.1 Certificate Mapping"
		upn = None
		dnsname = None
		cert_domain = None
		UPN_OID = "1.3.6.1.4.1.311.20.2.3"

		if self.certificate.subject_alt_name_value:
			for san in self.certificate.subject_alt_name_value:
				if san.native.get("type_id") == UPN_OID:
					upn = san.native["value"]
					break
				elif san.name == "dns_name":
					dnsname = san.native["value"]
					break
		else:
			# Multiple cn is possible, e.g. "CN=Test User,CN=Users,DC=corp,DC=local"
			# but only the last one can possibly be the sAMAccountName
			cn = self.certificate.subject.native["common_name"]
			if isinstance(cn, list):
				cn = cn[-1]
			# potentially an Azure AD certificate, in this case domain is AzureAD
			if '@' in cn:
				upn = cn.rsplit('/', 1)[-1]
			else:
				self.cname = cn
		if upn:
			# Even if self.username doesn't match sAMAccountName but match the first part of the UPN, kerberos will find the principal
			self.cname, cert_domain = upn.rsplit('@', 1)[1]
		elif dnsname:
			self.cname, cert_domain = dnsname.split('.', 1)
			self.cname += '$'

		if not self.target:
			if cert_domain:
				self.target = cert_domain
			else:
				dc = None
				if 'domain_component' in self.certificate.subject.native:
					dc = self.certificate.subject.native['domain_component']
				elif 'domain_component' in self.certificate.issuer.native:
					dc = self.certificate.issuer.native['domain_component']
				if dc is not None:
					self.target = '.'.join(dc[::-1])
				else:
					raise Exception('Could\'t find proper domain name in the certificate! Please set it manually!')
		
		if dh_params is None:
			print('Generating DH params...')
			# Or maybe use set_dhparams?
			# Generate DH parameters
			parameters = generate_parameters(generator=2, key_size=1024)
			# Convert the parameters to a dictionary
			dh_params = {
				"p": parameters.parameter_numbers().p,
				"g": parameters.parameter_numbers().g
			}
			# Use the generated parameters
			self.diffie = DirtyDH.from_dict(dh_params)
			print('DH params generated.')
		else:
			#print('Loading default DH params...')
			if isinstance(dh_params, dict):
				self.diffie = DirtyDH.from_dict(dh_params)
			elif isinstance(dh_params, bytes):
				self.diffie = DirtyDH.from_asn1(dh_params)
			elif isinstance(dh_params, DirtyDH):
				self.diffie = dh_params
			else:
				raise Exception('DH params must be either a bytearray or a dict')


	def build_asreq(self, target = None, cname = None, kdcopts = ['forwardable','renewable','proxiable', 'canonicalize']):
		if isinstance(kdcopts, list):
			kdcopts = set(kdcopts)
		if cname is not None:
			if isinstance(cname, str):
				cname = [cname]
		else:
			cname = [self.cname]
		
		if target is not None:
			if isinstance(target, str):
				target = [target]
		else:
			target = ['127.0.0.1']

		now = datetime.datetime.now(datetime.timezone.utc)

		kdc_req_body_data = {}
		kdc_req_body_data['kdc-options'] = KDCOptions(kdcopts)
		kdc_req_body_data['cname'] = PrincipalName({'name-type': NAME_TYPE.MS_PRINCIPAL.value, 'name-string': cname})
		kdc_req_body_data['realm'] = 'WELLKNOWN:PKU2U'
		kdc_req_body_data['sname'] = PrincipalName({'name-type': NAME_TYPE.MS_PRINCIPAL.value, 'name-string': target})
		kdc_req_body_data['till']  = (now + datetime.timedelta(days=1)).replace(microsecond=0)
		kdc_req_body_data['rtime'] = (now + datetime.timedelta(days=1)).replace(microsecond=0)
		kdc_req_body_data['nonce'] = secrets.randbits(31)
		kdc_req_body_data['etype'] = [18,17] # 23 breaks...
		kdc_req_body_data['addresses'] = [HostAddress({'addr-type': 20, 'address': b'127.0.0.1'})] # not sure if this is needed
		kdc_req_body = KDC_REQ_BODY(kdc_req_body_data)


		checksum = hashlib.sha1(kdc_req_body.dump()).digest()
		
		authenticator = {}
		authenticator['cusec'] = now.microsecond
		authenticator['ctime'] = now.replace(microsecond=0)
		authenticator['nonce'] = secrets.randbits(31)
		authenticator['paChecksum'] = checksum
		

		dp = {}
		dp['p'] = self.diffie.p
		dp['g'] = self.diffie.g
		dp['q'] = 0 # mandatory parameter, but it is not needed

		pka = {}
		pka['algorithm'] = '1.2.840.10046.2.1'
		pka['parameters'] = keys.DomainParameters(dp)
		
		spki = {}
		spki['algorithm'] = keys.PublicKeyAlgorithm(pka)
		spki['public_key'] = self.diffie.get_public_key()

		
		authpack = {}
		authpack['pkAuthenticator'] = PKAuthenticator(authenticator)
		authpack['clientPublicValue'] = keys.PublicKeyInfo(spki)
		authpack['clientDHNonce'] = self.diffie.dh_nonce
		
		authpack = AuthPack(authpack)
		signed_authpack = self.sign_authpack(authpack.dump(), wrap_signed = False)
		
		# ??????? This is absolutely nonsense, 
		payload = length_encode(len(signed_authpack)) + signed_authpack
		payload = b'\x80' + payload
		signed_authpack = b'\x30' + length_encode(len(payload)) + payload
		
		pa_data_1 = {}
		pa_data_1['padata-type'] = PaDataType.PK_AS_REQ.value
		pa_data_1['padata-value'] = signed_authpack 

		asreq = {}
		asreq['pvno'] = 5
		asreq['msg-type'] = 10
		asreq['padata'] = [pa_data_1]
		asreq['req-body'] = kdc_req_body

		return AS_REQ(asreq).dump()	

	def build_apreq(self, asrep, session_key, cipher, subkey_data, krb_finished_data, flags = GSSAPIFlags.GSS_C_MUTUAL_FLAG | GSSAPIFlags.GSS_C_INTEG_FLAG  | GSSAPIFlags.GSS_C_EXTENDED_ERROR_FLAG):
		

		# TODO: https://www.ietf.org/rfc/rfc4757.txt
		#subkey_data = {}
		#subkey_data['keytype'] = Enctype.AES256
		#subkey_data['keyvalue'] = os.urandom(32)

		subkey_cipher = _enctype_table[subkey_data['keytype']]
		subkey_key = Key(subkey_cipher.enctype, subkey_data['keyvalue'])
		subkey_checksum = _checksum_table[16] # ChecksumTypes.hmac_sha1_96_aes256

		krb_finished_checksum_data = {}
		krb_finished_checksum_data['cksumtype'] = 16
		krb_finished_checksum_data['checksum'] = subkey_checksum.checksum(subkey_key, 41, krb_finished_data)

		krb_finished_data = {}
		krb_finished_data['gss-mic'] = Checksum(krb_finished_checksum_data)

		krb_finished = KRB_FINISHED(krb_finished_data).dump()

		a = 2
		extensions_data = a.to_bytes(4, byteorder='big', signed=True) + len(krb_finished).to_bytes(4, byteorder='big', signed=True) + krb_finished

		ac = AuthenticatorChecksum()
		ac.flags = flags
		ac.channel_binding = b'\x00'*16
		chksum = {}
		chksum['cksumtype'] = 0x8003
		chksum['checksum'] = ac.to_bytes() + extensions_data

		tii = LSAP_TOKEN_INFO_INTEGRITY()
		tii.Flags = 1
		tii.TokenIL = 0x00002000 # Medium integrity
		tii.MachineID = bytes.fromhex('7e303fffe6bff25146addca4fbddf1b94f1634178eb4528fb2731c669ca23cde')

		restriction_data = {}
		restriction_data['restriction-type'] = 0
		restriction_data['restriction'] = tii.to_bytes()
		restriction_data = KERB_AD_RESTRICTION_ENTRY(restriction_data)

		x = KERB_AD_RESTRICTION_ENTRYS([restriction_data]).dump()
		restrictions = AuthorizationData([{ 'ad-type' : 141, 'ad-data' : x}]).dump()

		

		now = datetime.datetime.now(datetime.timezone.utc)
		authenticator_data = {}
		authenticator_data['authenticator-vno'] = krb5_pvno 
		authenticator_data['crealm'] = Realm(asrep['crealm'])
		authenticator_data['cname'] = asrep['cname']
		authenticator_data['cusec'] = now.microsecond
		authenticator_data['ctime'] = now.replace(microsecond=0)
		authenticator_data['subkey'] = EncryptionKey(subkey_data)
		authenticator_data['seq-number'] = 682437742 #??? TODO: check this!
		authenticator_data['authorization-data'] = AuthorizationData([{'ad-type': 1, 'ad-data' : restrictions}])
		authenticator_data['cksum'] = Checksum(chksum)
		
		
		#print('Authenticator(authenticator_data).dump()')
		#print(Authenticator(authenticator_data).dump().hex())

		authenticator_data_enc = cipher.encrypt(session_key, 11, Authenticator(authenticator_data).dump(), None)
		
		ap_opts = ['mutual-required']

		ap_req = {}
		ap_req['pvno'] = krb5_pvno
		ap_req['msg-type'] = MESSAGE_TYPE.KRB_AP_REQ.value
		ap_req['ticket'] = Ticket(asrep['ticket'])
		ap_req['ap-options'] = APOptions(set(ap_opts))
		ap_req['authenticator'] = EncryptedData({'etype': session_key.enctype, 'cipher': authenticator_data_enc})
		
		#pprint('AP_REQ \r\n%s' % AP_REQ(ap_req).native)
		
		#print(AP_REQ(ap_req).dump().hex())
		#input()

		return AP_REQ(ap_req).dump()

	def sign_authpack(self, data, wrap_signed = False):
		if self.__hcert is not None:
			from minikerberos.common.windows.crypt32 import pkcs7_sign

			return pkcs7_sign(self.__hcert, data)
		return self.sign_authpack_native(self, data, wrap_signed)

	def sign_authpack_native(self, data, wrap_signed = False):
		"""
		Creating PKCS7 blob which contains the following things:

		1. 'data' blob which is an ASN1 encoded "AuthPack" structure
		2. the certificate used to sign the data blob
		3. the singed 'signed_attrs' structure (ASN1) which points to the "data" structure (in point 1)
		"""
		
		da = {}
		da['algorithm'] = algos.DigestAlgorithmId('1.3.14.3.2.26') # for sha1

		si = {}
		si['version'] = 'v1'
		si['sid'] = cms.IssuerAndSerialNumber({
			'issuer':  self.certificate.issuer,
			'serial_number':  self.certificate.serial_number,
		})


		si['digest_algorithm'] = algos.DigestAlgorithm(da)
		si['signed_attrs'] = [
			cms.CMSAttribute({'type': 'content_type', 'values': ['1.3.6.1.5.2.3.1']}), # indicates that the encap_content_info's authdata struct (marked with OID '1.3.6.1.5.2.3.1' is signed )
			cms.CMSAttribute({'type': 'message_digest', 'values': [hashlib.sha1(data).digest()]}), ### hash of the data, the data itself will not be signed, but this block of data will be.
		]
		si['signature_algorithm'] = algos.SignedDigestAlgorithm({'algorithm' : '1.2.840.113549.1.1.1'})
		si['signature'] = self.privkey.sign(cms.CMSAttributes(si['signed_attrs']).dump(), padding.PKCS1v15() , hashes.SHA1())

		ec = {}
		ec['content_type'] = '1.3.6.1.5.2.3.1'
		ec['content'] = data

		sd = {}
		sd['version'] = 'v3'
		sd['digest_algorithms'] = [algos.DigestAlgorithm(da)] # must have only one
		sd['encap_content_info'] = cms.EncapsulatedContentInfo(ec)
		sd['certificates'] = [self.certificate]
		sd['signer_infos'] = cms.SignerInfos([cms.SignerInfo(si)])
		
		if wrap_signed is True:
			ci = {}
			ci['content_type'] = '1.2.840.113549.1.7.2' # signed data OID
			ci['content'] = cms.SignedData(sd)
			return cms.ContentInfo(ci).dump()

		return cms.SignedData(sd).dump()
		
	
	
	
	
	def decrypt_asrep(self, as_rep):
		

		
		def truncate_key(value, keysize):
			output = b''
			currentNum = 0
			while len(output) < keysize:
				currentDigest = hashlib.sha1(bytes([currentNum]) + value).digest()
				if len(output) + len(currentDigest) > keysize:
					output += currentDigest[:keysize - len(output)]
					break
				output += currentDigest
				currentNum += 1
			
			return output

		for pa in as_rep['padata']:
			if pa['padata-type'] == 17:
				pkasrep = PA_PK_AS_REP.load(pa['padata-value']).native
				break
		else:
			raise Exception('PA_PK_AS_REP not found!')

		sd = cms.SignedData.load(pkasrep['dhSignedData']).native
		keyinfo = sd['encap_content_info']
		if keyinfo['content_type'] != '1.3.6.1.5.2.3.2':
			raise Exception('Keyinfo content type unexpected value')
		authdata = KDCDHKeyInfo.load(keyinfo['content']).native
		pubkey = int(''.join(['1'] + [str(x) for x in authdata['subjectPublicKey']]), 2)		

		pubkey = int.from_bytes(core.BitString(authdata['subjectPublicKey']).dump()[7:], 'big', signed = False)
		shared_key = self.diffie.exchange(pubkey)
		
		server_nonce = pkasrep['serverDHNonce']
		fullKey = shared_key + self.diffie.dh_nonce + server_nonce

		etype = as_rep['enc-part']['etype']
		cipher = _enctype_table[etype]
		if etype == Enctype.AES256:
			t_key = truncate_key(fullKey, 32)
		elif etype == Enctype.AES128:
			t_key = truncate_key(fullKey, 16)
		elif etype == Enctype.RC4:
			raise NotImplementedError('RC4 key truncation documentation missing. it is different from AES')
			#t_key = truncate_key(fullKey, 16)
		

		key = Key(cipher.enctype, t_key)
		enc_data = as_rep['enc-part']['cipher']
		dec_data = cipher.decrypt(key, 3, enc_data)
		encasrep = EncASRepPart.load(dec_data).native
		cipher = _enctype_table[ int(encasrep['key']['keytype'])]
		session_key = Key(cipher.enctype, encasrep['key']['keyvalue'])
		return encasrep, session_key, cipher

	
	def get_metadata(self, target = None):
		


		if target is not None:
			if isinstance(target, str):
				target = [target]
		else:
			target = ['127.0.0.1']

		
		ci = {}
		ci['type'] = '2.5.4.3'
		ci['value'] = self.issuer

		a = Dunno1([ci])
		ci = Dunno2([a])

		info = {}
		info['pku2u'] = 'WELLKNOWN:PKU2U'
		info['clientInfo'] = PrincipalName({'name-type': NAME_TYPE.MS_PRINCIPAL.value, 'name-string': target})

		md = {}
		md['Info'] = Info(info)
		md['1'] = [CertIssuer({'data' : ci.dump()})]

		return MetaData(md).dump()