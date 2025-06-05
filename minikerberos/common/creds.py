from __future__ import annotations
import getpass
import collections
import base64
import platform
import copy
from typing import List
import os


from unicrypto import hashlib

from cryptography import x509 as cryptoX509
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding

from minikerberos.common.constants import KerberosSecretType
from minikerberos.protocol.encryption import string_to_key, Enctype
from minikerberos.protocol.constants import EncryptionType
from minikerberos.common.ccache import CCACHE
from minikerberos.common.keytab import Keytab
from minikerberos.common.kirbi import Kirbi
from asn1crypto import cms
from asn1crypto import algos
from asn1crypto import x509
from minikerberos.protocol.dirtydh import DirtyDH


def get_encoded_data(data:bytes or str, encoding = 'file') -> bytes:
	if encoding == 'file':
		with open(data, 'rb') as kf:
			return kf.read()
	elif encoding == 'hex':
		return bytes.fromhex(data)
	elif encoding == 'b64' or encoding == 'base64':
		if isinstance(data, str):
			data = data.encode()
		return base64.b64decode(data)
	elif encoding == 'raw':
		if isinstance(data, str):
			data = data.encode()
		return data
	raise Exception('Unknown encoding "%s"!' % encoding)

class KerberosCredential:
	def __init__(self):
		self.username:str = None
		self.domain:str = None
		self.password:str = None
		self.nt_hash:str = None
		self.lm_hash:str = None
		self.kerberos_key_aes_256:str = None
		self.kerberos_key_aes_128:str = None
		self.kerberos_key_des:str = None
		self.kerberos_key_rc4:str = None
		self.kerberos_key_des3:str = None
		self.certificate = None
		self.private_key = None
		self.__hcert = None #handle on the windows certificate store
		self.__use_windows_certstore:bool = False
		self.commonname:str = None
		self.certstore_name:str = None
		self.dhparams:DirtyDH = None
		self.ccache:CCACHE = None
		self.ccache_spn_strict_check:bool = False
		self.nopreauth = False
		self.override_etypes:List[EncryptionType] = []

	def get_preferred_enctype(self, server_enctypes:List[EncryptionType]) -> EncryptionType:
		client_enctypes = self.get_supported_enctypes(as_int=False)
		common_enctypes = list(set([s_enctype for s_enctype in server_enctypes]) & set(client_enctypes))

		for c_enctype in client_enctypes:
			if c_enctype in common_enctypes:
				return c_enctype

		raise Exception('No common supported enctypes! Server: %s Client: %s' % (
				', '.join([s_enctype.name for s_enctype in server_enctypes]),
				', '.join([c_enctype.name for c_enctype in client_enctypes])
			)
		)

	def get_key_for_enctype(self, etype:EncryptionType, salt:bytes = None) -> bytes:
		"""
		Returns the encryption key bytes for the enctryption type.
		"""
		if etype == EncryptionType.AES256_CTS_HMAC_SHA1_96:
			if self.kerberos_key_aes_256:
				return bytes.fromhex(self.kerberos_key_aes_256)
			if self.password is not None:
				if not salt:
					salt = (self.domain.upper() + self.username).encode()
				return string_to_key(Enctype.AES256, self.password, salt).contents
			raise Exception('There is no key for AES256 encryption')
		elif etype == EncryptionType.AES128_CTS_HMAC_SHA1_96:
			if self.kerberos_key_aes_128:
				return bytes.fromhex(self.kerberos_key_aes_128)
			if self.password is not None:
				if not salt:
					salt = (self.domain.upper() + self.username).encode()
				return string_to_key(Enctype.AES128, self.password, salt).contents
			raise Exception('There is no key for AES128 encryption')
		elif etype == EncryptionType.ARCFOUR_HMAC_MD5:
			if self.kerberos_key_rc4:
				return bytes.fromhex(self.kerberos_key_rc4)
			if self.nt_hash:
				return bytes.fromhex(self.nt_hash)
			elif self.password:
				if isinstance(self.password, str):
					pw = self.password.encode('utf-16-le')
				self.nt_hash = hashlib.md4(pw).hexdigest().upper()
				return bytes.fromhex(self.nt_hash)
			else:
				raise Exception('There is no key for RC4 encryption')
		elif etype == EncryptionType.DES3_CBC_SHA1:
			if self.kerberos_key_des3:
				return bytes.fromhex(self.kerberos_key_des3)
			elif self.password:
				if not salt:
					salt = (self.domain.upper() + self.username).encode()
				return string_to_key(Enctype.DES3, self.password, salt).contents
			else:
				raise Exception('There is no key for DES3 encryption')

		elif etype == EncryptionType.DES_CBC_MD5: #etype == EncryptionType.DES_CBC_CRC or etype == EncryptionType.DES_CBC_MD4 or 
			if self.kerberos_key_des:
				return bytes.fromhex(self.kerberos_key_des)
			elif self.password:
				if not salt:
					salt = (self.domain.upper() + self.username).encode()
				return string_to_key(Enctype.DES_MD5, self.password, salt).contents
			else:
				raise Exception('There is no key for DES encryption')
		
		elif etype == EncryptionType.ARCFOUR_MD4:
			if self.kerberos_key_rc4:
				return bytes.fromhex(self.kerberos_key_rc4)[:8]
			if self.nt_hash:
				return bytes.fromhex(self.nt_hash)[:8]
			elif self.password:
				pw = self.password
				if isinstance(self.password, str):
					pw = self.password.encode('utf-16-le')
				self.nt_hash = hashlib.md4(pw).hexdigest().upper()
				return bytes.fromhex(self.nt_hash)[:8]
			else:
				raise Exception('There is no key for RC4 encryption')

		else:
			raise Exception('Unsupported encryption type: %s' % etype.name)

	def get_supported_enctypes(self, as_int = True) -> List[EncryptionType]:
		"""
		Returns a list of all EncryptionTypes this credentials can use for authentication
		"""
		supp_enctypes = collections.OrderedDict()
		if self.override_etypes is not None and len(self.override_etypes) > 0:
			for etype in self.override_etypes:
				if isinstance(etype, int):
					etype = EncryptionType(etype)
				supp_enctypes[etype] = 1
		
		else:
			if self.nopreauth:
				supp_enctypes[EncryptionType.ARCFOUR_HMAC_MD5] = 1
				supp_enctypes[EncryptionType.AES256_CTS_HMAC_SHA1_96] = 1
				supp_enctypes[EncryptionType.AES128_CTS_HMAC_SHA1_96] = 1
				supp_enctypes[EncryptionType.DES3_CBC_SHA1] = 1
				supp_enctypes[EncryptionType.DES_CBC_MD5] = 1
				supp_enctypes[EncryptionType.ARCFOUR_MD4] = 1
				#supp_enctypes[EncryptionType.DES_CBC_MD4] = 1
				#supp_enctypes[EncryptionType.DES_CBC_CRC] = 1

			if self.kerberos_key_aes_256:
				supp_enctypes[EncryptionType.AES256_CTS_HMAC_SHA1_96] = 1
			if self.kerberos_key_aes_128:
				supp_enctypes[EncryptionType.AES128_CTS_HMAC_SHA1_96] = 1

			if self.password:
				supp_enctypes[EncryptionType.ARCFOUR_HMAC_MD5] = 1
				supp_enctypes[EncryptionType.AES256_CTS_HMAC_SHA1_96] = 1
				supp_enctypes[EncryptionType.AES128_CTS_HMAC_SHA1_96] = 1
				supp_enctypes[EncryptionType.DES3_CBC_SHA1] = 1
				supp_enctypes[EncryptionType.DES_CBC_MD5] = 1
				supp_enctypes[EncryptionType.ARCFOUR_MD4] = 1
				#supp_enctypes[EncryptionType.DES_CBC_MD4] = 1
				#supp_enctypes[EncryptionType.DES_CBC_CRC] = 1

			if self.password or self.nt_hash or self.kerberos_key_rc4:
				supp_enctypes[EncryptionType.ARCFOUR_HMAC_MD5] = 1
				supp_enctypes[EncryptionType.ARCFOUR_MD4] = 1

			if self.kerberos_key_des:
				supp_enctypes[EncryptionType.DES3_CBC_SHA1] = 1
			
			if self.certificate:
				supp_enctypes[EncryptionType.AES256_CTS_HMAC_SHA1_96] = 1
				supp_enctypes[EncryptionType.AES128_CTS_HMAC_SHA1_96] = 1


		if as_int == True:
			return [etype.value for etype in supp_enctypes]
		return [etype for etype in supp_enctypes]

	@staticmethod
	def from_keytab(keytab_file_path: str, principal: str, realm: str, encoding = 'file') -> KerberosCredential:
		"""Returns a kerberos credential object from Keytab file/data"""
		cred = KerberosCredential()
		cred.username = principal
		cred.domain = realm
		data = get_encoded_data(keytab_file_path, encoding=encoding)
		return KerberosCredential.from_keytab_string(data, principal, realm)

	@staticmethod
	def from_ccache(data, principal: str = None, realm: str = None, encoding = 'file') -> KerberosCredential:
		"""Returns a kerberos credential object with CCACHE database"""
		if data is None:
			ccache_path = os.environ.get('KRB5CCNAME')
			if ccache_path is None:
				raise Exception('No CCACHE data or path provided!')
			data = ccache_path
		data = get_encoded_data(data, encoding=encoding)
		k = KerberosCredential()
		k.username = principal
		k.domain = realm
		k.ccache = CCACHE.from_bytes(data)
		return k

	@staticmethod
	def from_kirbi(keytab_file_path: str, principal: str = None, realm: str = None, encoding = 'file') -> KerberosCredential:
		"""Returns a kerberos credential object from .kirbi file"""
		if encoding != 'kirbi':
			data = get_encoded_data(keytab_file_path, encoding=encoding)
			kirbi = Kirbi.from_bytes(data)
		else:
			kirbi = copy.deepcopy(keytab_file_path)
		cred = KerberosCredential()
		cred.username = principal if principal is not None else kirbi.get_username()
		cred.domain = realm if realm is not None else kirbi.kirbiobj.native['tickets'][0]['realm']
		cred.ccache = CCACHE.from_kirbi(kirbi)
		cred.ccache_spn_strict_check = False
		return cred
	
	@staticmethod
	def from_pfx(data:str, password:str, dhparams:DirtyDH = None, username:str = None, domain:str = None, encoding = 'file') -> KerberosCredential:
		"""
		Retruns a credential object from data found in the PFX file
		Username and domain will override the values found in the certificate
		"""
		data = get_encoded_data(data, encoding=encoding)
		return KerberosCredential.from_pfx_string(data, password, dhparams = dhparams, username = username, domain = domain)
	
	@staticmethod
	def from_krbcred(keytab_file_path: str, principal: str = None, realm: str = None) -> KerberosCredential:
		return KerberosCredential.from_kirbi(keytab_file_path, principal, realm)
	
	@staticmethod
	def from_keytab_string(keytabdata: str or bytes, principal: str, realm: str) -> KerberosCredential:
		cred = KerberosCredential()
		if principal is None:
			raise Exception('Principal is required')
		if realm is None:
			raise Exception('Realm is required')
		
		cred.username = principal
		cred.domain = realm

		if isinstance(keytabdata, str):
			keytabdata = base64.b64decode(keytabdata.replace(' ','').replace('\r','').replace('\n','').replace('\t','').replace('','').encode())
		
		keytab = Keytab.from_bytes(keytabdata)
		if len(keytab.entries) == 0:
			raise Exception('No entries found in keytab')
		if len(keytab.entries) == 1:
			keytab_entry = keytab.entries[0]
		else:
			for entry in keytab.entries:
				if entry.principal.to_pname().lower().find(principal.lower()) != -1:
					keytab_entry = entry
					break
			else:
				# No match found
				keytab_entry = keytab.entries[0]

		if Enctype.AES256 == keytab_entry.enctype:
			enctype = KerberosSecretType.AES256
		elif Enctype.AES128 == keytab_entry.enctype:
			enctype = KerberosSecretType.AES128
		elif Enctype.DES3 == keytab_entry.enctype:
			enctype = KerberosSecretType.DES3
		elif Enctype.DES_CRC == keytab_entry.enctype:
			enctype = KerberosSecretType.DES
		elif Enctype.DES_MD4 == keytab_entry.enctype:
			enctype = KerberosSecretType.DES
		elif Enctype.DES_MD5 == keytab_entry.enctype:
			enctype = KerberosSecretType.DES
		elif Enctype.RC4 == keytab_entry.enctype:
			enctype = KerberosSecretType.RC4
		if enctype:
			cred.add_secret(enctype, keytab_entry.key_contents.hex())
		
		return cred

	def set_user_and_domain_from_cert(self, username:str = None, domain:str = None):
		"""
		Tries to guess the correct username and domain from the current certificate,
		if 'username' and/or 'domain' is set it will set those
		"""
		# In Microsoft ecosystem there seem to be two main naming conventions for their certificates' subjects:
		# - For AD, the principal's distinguished name a.k.a NT-X500-PRINCIPAL (there are others too but not supported here)
		# - For EntraID, something not standard like "<principal SID>/<principal EntraID GUID>/login.windows.net/<tenant GUID>/<principal email>" e.g:
		# 	S-1-12-1-2190073739-1304874406-157446548-3757931170/c26d6885-f0df-4642-8207-5a38c93d2347/login.windows.net/e5bdbab1-eaba-4c81-b953-67e45605e0d8/testuser@bloody.corp
		#
		# minkrb doesn't handle as-req with NT-X500-PRINCIPAL so we'll try to extract the UPN/DNS in the SAN or the sAMAccountName in the CN as last resort hoping they're identical
		#
		# Mapping reference: "[MS-PKCA] 3.1.5.2.1 Certificate Mapping"

		self.username = username
		upn = None
		dnsname = None
		cert_domain = None
		UPN_OID = "1.3.6.1.4.1.311.20.2.3"
		if not username:
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
				if '@' in cn:
					upn = cn.rsplit('/', 1)[-1]
				else:
					self.username = cn
			if upn:
				# Even if self.username doesn't match sAMAccountName but match the first part of the UPN, kerberos will find the principal
				self.username, cert_domain = upn.rsplit('@', 1)
			elif dnsname:
				self.username, cert_domain = dnsname.split('.', 1)
				self.username += '$'
		self.domain = domain
		if not domain:
			if cert_domain:
				self.domain = cert_domain
			else:
				dc = None
				if 'domain_component' in self.certificate.subject.native:
					dc = self.certificate.subject.native['domain_component']
				elif 'domain_component' in self.certificate.issuer.native:
					dc = self.certificate.issuer.native['domain_component']
				if dc is not None:
					self.domain = '.'.join(dc[::-1])
				else:
					raise Exception('Could\'t find proper domain name in the certificate! Please set it manually!')

	@staticmethod
	def from_pem_data(certdata: str or bytes, keydata:str or bytes, dhparams:DirtyDH = None, username:str = None, domain:str = None) -> KerberosCredential:
		if isinstance(certdata, str):
			certdata = base64.b64decode(certdata.replace(' ','').replace('\r','').replace('\n','').replace('\t',''))
		if isinstance(keydata, str):
			keydata = base64.b64decode(keydata.replace(' ','').replace('\r','').replace('\n','').replace('\t',''))
		k = KerberosCredential()
		cert = cryptoX509.load_pem_x509_certificate(certdata)
		cert_der = cert.public_bytes(encoding=Encoding.DER)
		k.certificate = x509.Certificate.load(cert_der)
		k.private_key = serialization.load_pem_private_key(keydata, password=None)
		k.set_user_and_domain_from_cert(username = username, domain = domain)
		k.set_dhparams(dhparams)
		return k

	@staticmethod
	def from_pem_file(certpath:str, keypath: str, dhparams:DirtyDH = None, username:str = None, domain:str = None) -> KerberosCredential:
		
		with open(certpath, 'rb') as f:
			certdata = f.read()

		with open(keypath, 'rb') as f:
			keydata = f.read()
		
		return KerberosCredential.from_pem_data(certdata, keydata, dhparams = dhparams, username = username, domain = domain)


	@staticmethod
	def from_windows_certstore(commonname:str, certstore_name:str = 'MY', dhparams:DirtyDH = None, username:str = None, domain:str = None) -> KerberosCredential:
		if platform.system().lower() != 'windows':
			raise Exception('Only works on windows (obviously)')
		from minikerberos.common.windows.crypt32 import find_cert_by_cn, CertCloseStore, CertFreeCertificateContext

		k = KerberosCredential()
		k.commonname = commonname
		k.certstore_name = certstore_name
		k.certificate, chandle, shandle = find_cert_by_cn(commonname, certstore_name)
		CertFreeCertificateContext(chandle)
		CertCloseStore(shandle)

		k.__use_windows_certstore = True
		k.set_user_and_domain_from_cert(username = username, domain = domain)
		k.set_dhparams(dhparams)
		return k

	@staticmethod
	def from_pfx_string(data: str or bytes, password:str, dhparams:DirtyDH = None, username:str = None, domain:str = None) -> KerberosCredential:

		k = KerberosCredential()
		if password is None:
			password = b''
		if isinstance(password, str):
			password = password.encode()
		
		if isinstance(data, str):
			data = base64.b64decode(data.replace(' ', '').replace('\r','').replace('\n','').encode())


		k.private_key, cert, extra_certs = pkcs12.load_key_and_certificates(data, password = password)
		cert_der = cert.public_bytes(encoding=Encoding.DER)
		k.certificate = x509.Certificate.load(cert_der)
		
		k.set_user_and_domain_from_cert(username = username, domain = domain)
		k.set_dhparams(dhparams)
		return k

	@staticmethod
	def from_pfx_file(filepath:str, password:str, dhparams:DirtyDH = None, username:str = None, domain:str = None) -> KerberosCredential:
		"""
		Username and domain will override the values found in the certificate
		"""
		with open(filepath, 'rb') as f:
			data = f.read()
		return KerberosCredential.from_pfx_string(data, password, dhparams = dhparams, username = username, domain = domain)
	
	def set_dhparams(self, dhparams):
		# windows default params, don't look at me...
		self.dhparams = DirtyDH.from_dict({
			'p':int('00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff', 16),
			'g':2
		})
		
		if dhparams is not None:
			if isinstance(dhparams, dict):
				self.dhparams = DirtyDH.from_dict(dhparams)
			elif isinstance(dhparams, bytes):
				self.dhparams = DirtyDH.from_asn1(dhparams)
			elif isinstance(dhparams, DirtyDH):
				self.dhparams= dhparams
			else:
				raise Exception('DH params must be either a bytearray or a dict')
		

	def sign_authpack(self, data, wrap_signed = False):
		if self.__use_windows_certstore is True:
			from minikerberos.common.windows.crypt32 import pkcs7_sign, CertCloseStore, find_cert_by_cn, CertFreeCertificateContext
			_, chandle, shandle  = find_cert_by_cn(self.commonname, self.certstore_name)
			res = pkcs7_sign(chandle, data)
			CertFreeCertificateContext(chandle)
			CertCloseStore(shandle)
			return res
		return self.sign_authpack_native(data, wrap_signed)

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
		si['signature'] = self.private_key.sign(cms.CMSAttributes(si['signed_attrs']).dump(), padding.PKCS1v15() , hashes.SHA1())

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

	def add_secret(self, st: KerberosSecretType, secret: str):
		if st == KerberosSecretType.PASSWORD or st == KerberosSecretType.PW or st == KerberosSecretType.PASS:
			if secret == '' or secret is None:
				self.password = getpass.getpass('Enter Kerberos credential password:')
			else:
				self.password = secret
		elif st == KerberosSecretType.NT or st == KerberosSecretType.RC4:
			self.nt_hash = secret
			self.kerberos_key_rc4 = secret
		elif st == KerberosSecretType.AES128:
			self.kerberos_key_aes_128 = secret
		elif st == KerberosSecretType.AES256:
			self.kerberos_key_aes_256 = secret
		elif st == KerberosSecretType.AES:
			bytes.fromhex(secret)
			if len(secret) == 32:
				self.kerberos_key_aes_128 = secret
			elif len(secret) == 64:
				self.kerberos_key_aes_256 = secret
			else:
				raise Exception('AES key incorrect length!')
		elif st == KerberosSecretType.DES:
			self.kerberos_key_des = secret
		elif st == KerberosSecretType.DES3 or st == KerberosSecretType.TDES:
			self.kerberos_key_des3 = secret
		elif st == KerberosSecretType.CCACHE:
			self.ccache = CCACHE.from_file(secret)

	@staticmethod
	def from_tgt(tgt, override_realm = None, override_etypes:List[int] = [17,18,23]):
		"""Returns a new KerberosCredential object with user matching the TGT"""
		new_cred = KerberosCredential()
		new_cred.username = tgt['cname']['name-string'][0]
		if len(tgt['cname']['name-string']) > 1:
			new_cred.domain = tgt['cname']['name-string'][1]
		new_cred.domain = tgt['crealm']
		if override_realm is not None:
			new_cred.domain = override_realm
		if override_etypes is not None:
			for etype in override_etypes:
				new_cred.override_etypes.append(EncryptionType(etype))
		return new_cred

	def __str__(self):
		t = '===KerberosCredential===\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				t += '%s: %s\r\n' % (k, ','.join([str(x) for x in self.__dict__[k]]))
			else:
				t += '%s: %s\r\n' % (k, self.__dict__[k])
		return t
		
