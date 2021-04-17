#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import getpass
import hashlib
import collections

from minikerberos.common.constants import KerberosSecretType
from minikerberos.protocol.encryption import string_to_key, Enctype
from minikerberos.protocol.constants import EncryptionType
from minikerberos.common.ccache import CCACHE
from minikerberos.common.keytab import Keytab
from minikerberos.crypto.hashing import md4


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
		
