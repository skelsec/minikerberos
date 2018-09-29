#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import secrets
import datetime
import hashlib
import collections
from minikerberos.constants import *


# this is from impacket, a bit modified
windows_epoch = datetime.datetime(1970,1,1, tzinfo=datetime.timezone.utc)
def dt_to_kerbtime(dt):
	td = dt - windows_epoch
	return int((td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / 1e6)

def TGSTicket2hashcat(res):		
	tgs_encryption_type    = int(res['ticket']['enc-part']['etype'])
	tgs_name_string        = res['ticket']['sname']['name-string'][0]
	tgs_realm              = res['ticket']['realm']
	tgs_checksum           = res['ticket']['enc-part']['cipher'][:16]
	tgs_encrypted_data2    = res['ticket']['enc-part']['cipher'][16:]
		
	return '$krb5tgs$%s$*%s$%s$spn*$%s$%s' % (tgs_encryption_type,tgs_name_string,tgs_realm, tgs_checksum.hex(), tgs_encrypted_data2.hex() )
	
def TGTTicket2hashcat(res):
	tgt_encryption_type    = int(res['enc-part']['etype'])
	tgt_name_string        = res['cname']['name-string'][0]
	tgt_realm              = res['crealm']
	tgt_checksum           = res['enc-part']['cipher'][:16]
	tgt_encrypted_data2    = res['enc-part']['cipher'][16:]
	
	return '$krb5asrep$%s$%s$%s$%s$%s' % (tgt_encryption_type,tgt_name_string, tgt_realm, tgt_checksum.hex(), tgt_encrypted_data2.hex())
	#$krb5asrep$23$checksum$edata2

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
		"""
		Returns the encryption key bytes for the enctryption type.
		"""
		if etype == EncryptionType.AES256_CTS_HMAC_SHA1_96:
			if self.kerberos_key_aes_256:
				return bytes.fromhex(self.kerberos_key_aes_256)
			if self.password is not None:
				salt = (self.domain.upper() + self.username).encode()
				return string_to_key(Enctype.AES256, self.password, salt).contents
			raise Exception('There is no key for AES256 encryption')
		elif etype == EncryptionType.AES128_CTS_HMAC_SHA1_96:
			if self.kerberos_key_aes_128:
				return bytes.fromhex(self.kerberos_key_aes_128)
			if self.password is not None:
				salt = (self.domain.upper() + self.username).encode()
				return string_to_key(Enctype.AES128, self.password, salt).contents
			raise Exception('There is no key for AES128 encryption')
		elif etype == EncryptionType.ARCFOUR_HMAC_MD5:
			if self.kerberos_key_rc4:
				return bytes.fromhex(self.kerberos_key_rc4)
			if self.nt_hash:
				return bytes.fromhex(self.nt_hash)
			elif self.password:
				self.nt_hash = hashlib.new('md4', self.password.encode('utf-16-le')).hexdigest().upper()
				return bytes.fromhex(self.nt_hash)
			else:
				raise Exception('There is no key for RC4 encryption')
		elif etype == EncryptionType.DES3_CBC_SHA1:
			if self.kerberos_key_des3:
				return bytes.fromhex(self.kerberos_key_des)
			elif self.password:
				salt = (self.domain.upper() + self.username).encode()
				return string_to_key(Enctype.DES3, self.password, salt).contents
			else:
				raise Exception('There is no key for DES3 encryption')
				
		elif etype == EncryptionType.DES_CBC_MD5: #etype == EncryptionType.DES_CBC_CRC or etype == EncryptionType.DES_CBC_MD4 or 
			if self.kerberos_key_des:
				return bytes.fromhex(self.kerberos_key_des)
			elif self.password:
				salt = (self.domain.upper() + self.username).encode()
				return string_to_key(Enctype.DES_MD5, self.password, salt).contents
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
	def add_args(parser):
		group = parser.add_argument_group('authentication')

		group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
		group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
		group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
								 '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use'
								 ' the ones specified in the command line')
		group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication'
																				' (128 or 256 bits)')
	

	@staticmethod
	def from_args(args):
		cred = KerberosCredential()
		cred.from_target_string(args.target)
		if args.hashes is not None:
			cred.lm_hash, cred.nt_hash = args.hashes.split(':')
		
		if args.aesKey is not None:
			try:
				bytes.fromhex(args.aesKey)
			except Exception as e:
				logging.exception('Kerberos AES key format incorrect!')

			t = len(args.aesKey)
			if t == 64:
				cred.kerberos_key_aes_256 = args.aesKey.lower()
			elif t == 32:
				cred.kerberos_key_aes_128 = args.aesKey.lower()
			else:
				raise Exception('Kerberos AES key length incorrect!')

		if args.k is True:
			if cred.has_kerberos_secret() == False:
				raise Exception('Trying to perform Kerberos authentication with no usable kerberos secrets!')
			cred.force_kerberos = True
		
		if args.no_pass == False and cred.has_secret() == False:
			cred.password = getpass.getpass()

		return cred
		
class KerberosTarget:
	def __init__(self):
		self.username = None
		self.service  = None #the service we are trying to get a ticket for (eg. cifs/mssql...)
		self.domain   = None #the kerberos realm

	def get_principalname(self):
		if self.service:
			return [self.service, self.username]
		return [self.username]

	def get_formatted_pname(self):
		if self.service:
			return '%s/%s@%s' % (self.service, self.username, self.domain)
		return '%s@%s' % (self.username, self.domain)

def print_table(lines, separate_head=True):
	"""Prints a formatted table given a 2 dimensional array"""
	#Count the column width
	widths = []
	for line in lines:
			for i,size in enumerate([len(x) for x in line]):
					while i >= len(widths):
							widths.append(0)
					if size > widths[i]:
							widths[i] = size
	   
	#Generate the format string to pad the columns
	print_string = ""
	for i,width in enumerate(widths):
			print_string += "{" + str(i) + ":" + str(width) + "} | "
	if (len(print_string) == 0):
			return
	print_string = print_string[:-3]
	   
	#Print the actual data
	for i,line in enumerate(lines):
			print(print_string.format(*line))
			if (i == 0 and separate_head):
					print("-"*(sum(widths)+3*(len(widths)-1)))
