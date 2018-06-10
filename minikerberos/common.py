import secrets
import datetime
import hashlib
from constants import *


# this is from impacket, a bit modified
windows_epoch = datetime.datetime(1970,1,1, tzinfo=datetime.timezone.utc)
def dt_to_kerbtime(dt):
	td = dt - windows_epoch
	return int((td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / 1e6)
	

class UserCredential:
	def __init__(self):
		self.username = None
		self.domain = None
		self.password = None
		self.NT = None
		self.LM = None
		self.kerberos_key_aes_256 = None
		self.kerberos_key_aes_128 = None
		self.kerberos_key_des = None
		self.kerberos_key_rc4 = None
		
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
		
	def get_key_for_enctype(self, etype):
		if etype == EncryptionType.AES256_CTS_HMAC_SHA1_96:
			if self.kerberos_key_aes_256:
				return bytes.fromhex(self.kerberos_key_aes_256)
			raise Exception('There is no key for AES256 encryption')
		elif etype == EncryptionType.AES128_CTS_HMAC_SHA1_96:
			if self.kerberos_key_aes_128:
				return bytes.fromhex(self.kerberos_key_aes_128)
			raise Exception('There is no key for AES128 encryption')
		elif etype == EncryptionType.ARCFOUR_HMAC_MD5:
			if self.NT:
				return bytes.fromhex(self.NT)
			elif self.password:
				self.NT = hashlib.new('md4', self.password.encode('utf-16-le')).hexdigest().upper()
				return bytes.fromhex(self.NT)
			else:
				raise Exception('There is no key for RC4 encryption')
		elif etype == EncryptionType.DES3_CBC_SHA1:
			if self.kerberos_key_des:
				return bytes.fromhex(self.kerberos_key_des)
			elif self.password:
				return self.password.encode()
			else:
				raise Exception('There is no key for DES3 encryption')
				
		elif etype == EncryptionType.DES_CBC_CRC or etype == EncryptionType.DES_CBC_MD4 or EncryptionType.DES_CBC_MD5:
			if self.kerberos_key_des:
				return bytes.fromhex(self.kerberos_key_des)
			elif self.password:
				return self.password.encode()
			else:
				raise Exception('There is no key for DES3 encryption')
		
		else:
			raise Exception('Unsupported encryption type: %s' % etype.name)
		
	def get_supported_enctypes(self, as_int = True):
		supp_enctypes = {}
		if self.password:
			supp_enctypes[EncryptionType.DES_CBC_CRC] = 1
			supp_enctypes[EncryptionType.DES_CBC_MD4] = 1
			supp_enctypes[EncryptionType.DES_CBC_MD5] = 1
			supp_enctypes[EncryptionType.DES3_CBC_SHA1] = 1
		if self.password or self.NT:
			supp_enctypes[EncryptionType.ARCFOUR_HMAC_MD5] = 1
		if self.kerberos_key_aes_256:
			supp_enctypes[EncryptionType.AES256_CTS_HMAC_SHA1_96] = 1
		if self.kerberos_key_aes_128:
			supp_enctypes[EncryptionType.AES128_CTS_HMAC_SHA1_96] = 1
		if self.kerberos_key_des:
			supp_enctypes[EncryptionType.DES3_CBC_SHA1] = 1
		
		if as_int == True:
			return [etype.value for etype in supp_enctypes]
		return [etype for etype in supp_enctypes]
		
class TargetServer:
	def __init__(self):
		self.ip = None
		self.hostname = None
		self.service = None #the service we are trying to get a ticket for (eg. cifs/mssql...)
		self.domain = None #the kerberos realm
		self.kerberos_ip = None #IP address of the kerberos server (active directory)


