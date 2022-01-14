#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import getpass
import hashlib
import collections
import base64
import platform

from minikerberos.common.constants import KerberosSecretType
from minikerberos.protocol.encryption import string_to_key, Enctype
from minikerberos.protocol.constants import EncryptionType
from minikerberos.common.ccache import CCACHE
from minikerberos.common.keytab import Keytab
from minikerberos.crypto.hashing import md4
from asn1crypto import cms
from asn1crypto import algos
from minikerberos.protocol.dirtydh import DirtyDH

if platform.system().lower() != 'emscripten':
	from oscrypto.asymmetric import rsa_pkcs1v15_sign, load_private_key
	from oscrypto.keys import parse_pkcs12, parse_certificate, parse_private
else:
	print('pyodide not supporting openssl...')




class KerberosCredential:
	def __init__(self):
		self.username = None
		self.domain = None
		self.password = None
		self.nt_hash = None
		self.lm_hash = None
		self.kerberos_key_aes_256 = None
		self.kerberos_key_aes_128 = None
		self.kerberos_key_des = None
		self.kerberos_key_rc4 = None
		self.kerberos_key_des3 = None
		self.certificate = None
		self.private_key = None
		self.__hcert = None #handle on the windows certificate store
		self.__use_windows_certstore = False
		self.commonname = None
		self.certstore_name = None
		self.dhparams:DirtyDH = None
		self.ccache = None
		self.ccache_spn_strict_check = True

	def get_preferred_enctype(self, server_enctypes):
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

	def get_key_for_enctype(self, etype, salt = None):
		"""
		Returns the encryption key bytes for the enctryption type.
		"""
		if etype == EncryptionType.AES256_CTS_HMAC_SHA1_96:
			if self.kerberos_key_aes_256:
				return bytes.fromhex(self.kerberos_key_aes_256)
			if self.password is not None:
				if not salt:
					salt = (self.domain.upper() + self.username).encode()
				return string_to_key(Enctype.AES256, self.password.encode(), salt).contents
			raise Exception('There is no key for AES256 encryption')
		elif etype == EncryptionType.AES128_CTS_HMAC_SHA1_96:
			if self.kerberos_key_aes_128:
				return bytes.fromhex(self.kerberos_key_aes_128)
			if self.password is not None:
				if not salt:
					salt = (self.domain.upper() + self.username).encode()
				return string_to_key(Enctype.AES128, self.password.encode(), salt).contents
			raise Exception('There is no key for AES128 encryption')
		elif etype == EncryptionType.ARCFOUR_HMAC_MD5:
			if self.kerberos_key_rc4:
				return bytes.fromhex(self.kerberos_key_rc4)
			if self.nt_hash:
				return bytes.fromhex(self.nt_hash)
			elif self.password:
				self.nt_hash = md4(self.password.encode('utf-16-le')).hexdigest().upper()
				#self.nt_hash = hashlib.new('md4', self.password.encode('utf-16-le')).hexdigest().upper()
				return bytes.fromhex(self.nt_hash)
			else:
				raise Exception('There is no key for RC4 encryption')
		elif etype == EncryptionType.DES3_CBC_SHA1:
			if self.kerberos_key_des3:
				return bytes.fromhex(self.kerberos_key_des)
			elif self.password:
				if not salt:
					salt = (self.domain.upper() + self.username).encode()
				return string_to_key(Enctype.DES3, self.password.encode(), salt).contents
			else:
				raise Exception('There is no key for DES3 encryption')

		elif etype == EncryptionType.DES_CBC_MD5: #etype == EncryptionType.DES_CBC_CRC or etype == EncryptionType.DES_CBC_MD4 or 
			if self.kerberos_key_des:
				return bytes.fromhex(self.kerberos_key_des)
			elif self.password:
				if not salt:
					salt = (self.domain.upper() + self.username).encode()
				return string_to_key(Enctype.DES_MD5, self.password.encode(), salt).contents
			else:
				raise Exception('There is no key for DES3 encryption')

		else:
			raise Exception('Unsupported encryption type: %s' % etype.name)

	def get_supported_enctypes(self, as_int = True):
		supp_enctypes = collections.OrderedDict()
		if self.kerberos_key_aes_256:
			supp_enctypes[EncryptionType.AES256_CTS_HMAC_SHA1_96] = 1
		if self.kerberos_key_aes_128:
			supp_enctypes[EncryptionType.AES128_CTS_HMAC_SHA1_96] = 1

		if self.password:
			supp_enctypes[EncryptionType.DES_CBC_CRC] = 1
			supp_enctypes[EncryptionType.DES_CBC_MD4] = 1
			supp_enctypes[EncryptionType.DES_CBC_MD5] = 1
			supp_enctypes[EncryptionType.DES3_CBC_SHA1] = 1
			supp_enctypes[EncryptionType.ARCFOUR_HMAC_MD5] = 1
			supp_enctypes[EncryptionType.AES256_CTS_HMAC_SHA1_96] = 1
			supp_enctypes[EncryptionType.AES128_CTS_HMAC_SHA1_96] = 1

		if self.password or self.nt_hash or self.kerberos_key_rc4:
			supp_enctypes[EncryptionType.ARCFOUR_HMAC_MD5] = 1

		if self.kerberos_key_des:
			supp_enctypes[EncryptionType.DES3_CBC_SHA1] = 1
		
		if self.certificate is not None:
			supp_enctypes = collections.OrderedDict()
			supp_enctypes[EncryptionType.AES256_CTS_HMAC_SHA1_96] = 1
			supp_enctypes[EncryptionType.AES128_CTS_HMAC_SHA1_96] = 1


		if as_int == True:
			return [etype.value for etype in supp_enctypes]
		return [etype for etype in supp_enctypes]
	
	@staticmethod
	def from_krbcred(keytab_file_path: str, principal: str = None, realm: str = None):
		return KerberosCredential.from_kirbi(keytab_file_path, principal, realm)

	@staticmethod
	def from_kirbi(keytab_file_path: str, principal: str = None, realm: str = None):
		cred = KerberosCredential()
		cred.username = principal
		cred.domain = realm
		cred.ccache = CCACHE.from_kirbifile(keytab_file_path)
		cred.ccache_spn_strict_check = False
		return cred

	@staticmethod
	def from_keytab(keytab_file_path: str, principal: str, realm: str):
		cred = KerberosCredential()
		cred.username = principal
		cred.domain = realm

		with open(keytab_file_path, 'rb') as kf:
			#keytab_bytes = kf.read()
			#keytab = Keytab.from_bytes(keytab_bytes)
			keytab = Keytab.from_buffer(kf)

			for keytab_entry in keytab.entries:
				if realm == keytab_entry.principal.realm.to_string():
					for keytab_principal in keytab_entry.principal.components:
						if principal == keytab_principal.to_string():
							enctype = None
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

	@staticmethod
	def from_ccache_file(filepath, principal: str = None, realm: str = None):
		k = KerberosCredential()
		k.username = principal
		k.domain = realm
		k.ccache = CCACHE.from_file(filepath)
		return k

	def set_user_and_domain_from_cert(self, username = None, domain = None):
		self.username = username
		if username is None:
			self.username = self.certificate.subject.native['common_name'][1]
		self.domain = domain
		if domain is None:
			self.domain = '.'.join(self.certificate.subject.native['domain_component'][::-1])

	@staticmethod
	def from_pem_data(certdata, keydata, dhparams = None, username = None, domain = None):
		if isinstance(certdata, str):
			certdata = base64.b64decode(certdata.replace(' ','').replace('\r','').replace('\n','').replace('\t',''))
		if isinstance(keydata, str):
			keydata = base64.b64decode(keydata.replace(' ','').replace('\r','').replace('\n','').replace('\t',''))
		k = KerberosCredential()
		k.certificate = parse_certificate(certdata)
		k.private_key = parse_private(keydata)
		k.set_user_and_domain_from_cert(username = username, domain = username)
		k.set_dhparams(dhparams)

	@staticmethod
	def from_pem_file(certpath, keypath, dhparams = None, username = None, domain = None):
		with open(certpath, 'rb') as f:
			certdata = f.read()

		with open(keypath, 'rb') as f:
			keydata = f.read()
		
		return KerberosCredential.from_pem_data(certdata, keydata, dhparams = dhparams, username = username, domain = domain)


	@staticmethod
	def from_windows_certstore(commonname, certstore_name = 'MY', dhparams = None, username = None, domain = None):
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
		k.set_user_and_domain_from_cert(username = username, domain = username)
		k.set_dhparams(dhparams)
		return k

	@staticmethod
	def from_pfx_string(data, password, dhparams = None, username = None, domain = None):
		k = KerberosCredential()
		if password is None:
			password = b''
		if isinstance(password, str):
			password = password.encode()
		
		if isinstance(data, str):
			data = base64.b64decode(data.replace(' ', '').replace('\r','').replace('\n','').encode())

		# private_key is not actually the private key object but the privkey data because oscrypto privkey 
		# cant be serialized so we cant make copy of it.
		k.private_key, k.certificate, extra_certs = parse_pkcs12(data, password = password)
		#k.private_key = load_private_key(privkeyinfo)
		
		k.set_user_and_domain_from_cert(username = username, domain = username)
		k.set_dhparams(dhparams)
		return k

	@staticmethod
	def from_pfx_file(filepath, password, dhparams = None, username = None, domain = None):
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
		si['signature'] = rsa_pkcs1v15_sign(load_private_key(self.private_key),  cms.CMSAttributes(si['signed_attrs']).dump(), "sha1")

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

	def __str__(self):
		t = '===KerberosCredential===\r\n'
		t += 'username: %s\r\n' % self.username
		t += 'domain: %s\r\n' % self.domain
		t += 'password: %s\r\n' % self.password
		t += 'nt_hash: %s\r\n' % self.nt_hash
		t += 'lm_hash: %s\r\n' % self.lm_hash
		if self.kerberos_key_aes_256:
			t += 'kerberos_key_aes_256: %s\r\n' % self.kerberos_key_aes_256
		if self.kerberos_key_aes_128:
			t += 'kerberos_key_aes_128: %s\r\n' % self.kerberos_key_aes_128
		if self.kerberos_key_des:
			t += 'kerberos_key_des: %s\r\n' % self.kerberos_key_des
		if self.kerberos_key_rc4:
			t += 'kerberos_key_rc4: %s\r\n' % self.kerberos_key_rc4
		if self.kerberos_key_des3:
			t += 'kerberos_key_des3: %s\r\n' % self.kerberos_key_des3
		return t
		
