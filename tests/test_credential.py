import shutil
import os
import pathlib
import pytest
import base64
from minikerberos.common.factory import KerberosClientFactory
from minikerberos.common.creds import KerberosCredential
from minikerberos.common.constants import KerberosSecretType
from minikerberos.common.ccache import CCACHE
from minikerberos.protocol.constants import EncryptionType 
from minikerberos.common.keytab import Keytab
from minikerberos.protocol.encryption import Enctype 
from .config import *

def test_url_nt_1():
	urlstr = 'kerberos+nt://domain\\user:921a7fece11f4d8c72432e41e40d0372@127.0.0.1'
	url = KerberosClientFactory.from_url(urlstr)
	cred = url.get_creds()
	assert cred.domain == 'domain'
	assert cred.username == 'user'
	assert cred.nt_hash == '921a7fece11f4d8c72432e41e40d0372'
	assert cred.kerberos_key_rc4 == '921a7fece11f4d8c72432e41e40d0372'

	target = url.get_target()
	assert target.ip == '127.0.0.1'
	assert target.port == 88

def test_addsecret_password():
	cred = KerberosCredential()
	cred.domain = 'domain'
	cred.username = 'user'
	cred.add_secret(KerberosSecretType.PASSWORD, 'password')
	assert cred.password == 'password'

def test_addsecret_rc4():
	cred = KerberosCredential()
	cred.domain = 'domain'
	cred.username = 'user'
	cred.add_secret(KerberosSecretType.RC4, '921a7fece11f4d8c72432e41e40d0372')
	assert cred.nt_hash == '921a7fece11f4d8c72432e41e40d0372'
	assert cred.kerberos_key_rc4 == '921a7fece11f4d8c72432e41e40d0372'

def test_addsecret_aes128():
	cred = KerberosCredential()
	cred.domain = 'domain'
	cred.username = 'user'
	cred.add_secret(KerberosSecretType.AES128, '921a7fece11f4d8c72432e41e40d0372')
	assert cred.kerberos_key_aes_128 == '921a7fece11f4d8c72432e41e40d0372'
	ret = cred.get_key_for_enctype(EncryptionType.AES128_CTS_HMAC_SHA1_96)
	assert ret == bytes.fromhex('921a7fece11f4d8c72432e41e40d0372')

def test_addsecret_aes128_wrongtype():
	cred = KerberosCredential()
	cred.domain = 'domain'
	cred.username = 'user'
	cred.add_secret(KerberosSecretType.AES128, '921a7fece11f4d8c72432e41e40d0372')
	assert cred.kerberos_key_aes_128 == '921a7fece11f4d8c72432e41e40d0372'
	with pytest.raises(Exception):
		ret = cred.get_key_for_enctype(EncryptionType.AES256_CTS_HMAC_SHA1_96)

def test_addsecret_aes256():
	cred = KerberosCredential()
	cred.domain = 'domain'
	cred.username = 'user'
	cred.add_secret(KerberosSecretType.AES256, '921a7fece11f4d8c72432e41e40d0372921a7fece11f4d8c72432e41e40d0372')
	assert cred.kerberos_key_aes_256 == '921a7fece11f4d8c72432e41e40d0372921a7fece11f4d8c72432e41e40d0372'
	ret = cred.get_key_for_enctype(EncryptionType.AES256_CTS_HMAC_SHA1_96)
	assert ret == bytes.fromhex('921a7fece11f4d8c72432e41e40d0372921a7fece11f4d8c72432e41e40d0372')

def test_addsecret_aes256_wrongtype():
	cred = KerberosCredential()
	cred.domain = 'domain'
	cred.username = 'user'
	cred.add_secret(KerberosSecretType.AES256, '921a7fece11f4d8c72432e41e40d0372921a7fece11f4d8c72432e41e40d0372')
	assert cred.kerberos_key_aes_256 == '921a7fece11f4d8c72432e41e40d0372921a7fece11f4d8c72432e41e40d0372'
	ret = cred.get_key_for_enctype(EncryptionType.AES256_CTS_HMAC_SHA1_96)
	assert ret == bytes.fromhex('921a7fece11f4d8c72432e41e40d0372921a7fece11f4d8c72432e41e40d0372')
	with pytest.raises(Exception):
		ret = cred.get_key_for_enctype(EncryptionType.AES128_CTS_HMAC_SHA1_96)

def test_addsecret_aes_1():
	cred = KerberosCredential()
	cred.domain = 'domain'
	cred.username = 'user'
	cred.add_secret(KerberosSecretType.AES, '921a7fece11f4d8c72432e41e40d0372')
	assert cred.kerberos_key_aes_128 == '921a7fece11f4d8c72432e41e40d0372'

def test_addsecret_aes_2():
	cred = KerberosCredential()
	cred.domain = 'domain'
	cred.username = 'user'
	cred.add_secret(KerberosSecretType.AES, '921a7fece11f4d8c72432e41e40d0372921a7fece11f4d8c72432e41e40d0372')
	assert cred.kerberos_key_aes_256 == '921a7fece11f4d8c72432e41e40d0372921a7fece11f4d8c72432e41e40d0372'

def test_addsecret_aes_wrong():
	cred = KerberosCredential()
	cred.domain = 'domain'
	cred.username = 'user'	
	with pytest.raises(Exception) as e_info:
		cred.add_secret(KerberosSecretType.AES, '921a7fece11f4d8c732e41e40d0372921a7fece11f4d8c72432e41e40d0372')


def test_addsecret_des():
	cred = KerberosCredential()
	cred.domain = 'domain'
	cred.username = 'user'
	cred.add_secret(KerberosSecretType.DES, '921a7fece11f4d8c')
	assert cred.kerberos_key_des == '921a7fece11f4d8c'
	ret = cred.get_key_for_enctype(EncryptionType.DES_CBC_MD5)
	assert ret == bytes.fromhex('921a7fece11f4d8c')

def test_addsecret_des3():
	cred = KerberosCredential()
	cred.domain = 'domain'
	cred.username = 'user'
	cred.add_secret(KerberosSecretType.DES3, '921a7fece11f4d8c72432e41e40d0372')
	assert cred.kerberos_key_des3 == '921a7fece11f4d8c72432e41e40d0372'
	ret = cred.get_key_for_enctype(EncryptionType.DES3_CBC_SHA1)
	assert ret == bytes.fromhex('921a7fece11f4d8c72432e41e40d0372')

def test_stringtokey_des3():
	cred = KerberosCredential()
	cred.domain = 'domain'
	cred.username = 'user'
	cred.password = 'password'
	ret = cred.get_key_for_enctype(EncryptionType.DES3_CBC_SHA1)

def test_stringtokey_des():
	cred = KerberosCredential()
	cred.domain = 'domain'
	cred.username = 'user'
	cred.password = 'password'
	ret = cred.get_key_for_enctype(EncryptionType.DES_CBC_MD5)

def test_addsecret_ccache():
	cred = KerberosCredential()
	cred.domain = 'domain'
	cred.username = 'user'
	cred.add_secret(KerberosSecretType.CCACHE, CCACHE_DIR.joinpath('administrator.ccache'))
	assert len(cred.ccache.get_all_tgt()) > 0

def test_load_ccache_hex():
	ccachedata = CCACHE_DIR.joinpath('administrator.ccache').read_bytes().hex()
	cred = KerberosCredential.from_ccache(ccachedata, encoding = 'hex')
	assert len(cred.ccache.get_all_tgt()) > 0

def test_load_ccache_base64():
	ccachedata = base64.b64encode(CCACHE_DIR.joinpath('administrator.ccache').read_bytes()).decode()
	cred = KerberosCredential.from_ccache(ccachedata, encoding = 'base64')
	assert len(cred.ccache.get_all_tgt()) > 0

def test_load_ccache_file():
	cred = KerberosCredential.from_ccache(CCACHE_DIR.joinpath('administrator.ccache'), encoding = 'file')
	assert len(cred.ccache.get_all_tgt()) > 0

def test_load_ccache_bytes():
	ccachedata = CCACHE_DIR.joinpath('administrator.ccache').read_bytes()
	cred = KerberosCredential.from_ccache(ccachedata, encoding = 'raw')
	assert len(cred.ccache.get_all_tgt()) > 0

def test_load_ccache_wrong():
	with pytest.raises(Exception) as e_info:
		cred = KerberosCredential.from_ccache('wrongasdfafdsf', encoding = 'raw12123123')
#def test_load_ccache_wrong():
#    with pytest.raises(Exception) as e_info:
#        cred = KerberosCredential.from_ccache('wrongasdfafdsf', encoding = 'raw')

def test_load_keytab():
	for keytabfile in get_testfiles_keytab():
		keytab = Keytab.from_file(keytabfile)
		kenctype = [keytabentry.enctype for keytabentry in keytab.entries][0]
		cred = KerberosCredential.from_keytab(keytabfile, 'administrator', 'domain.local')
		assert cred.username == 'administrator'
		assert cred.domain == 'domain.local'
		if Enctype.AES256 == kenctype:
			enctype = EncryptionType.AES256_CTS_HMAC_SHA1_96
		elif Enctype.AES128 == kenctype:
			enctype = EncryptionType.AES128_CTS_HMAC_SHA1_96
		elif Enctype.DES3 == kenctype:
			enctype = EncryptionType.DES3_CBC_SHA1
		elif Enctype.DES_MD5 == kenctype:
			enctype = EncryptionType.DES_CBC_MD5
		elif Enctype.RC4 == kenctype:
			enctype = EncryptionType.ARCFOUR_HMAC_MD5
		
		assert cred.get_key_for_enctype(enctype) is not None

def test_load_keytab_hex():
	for keytabfile in get_testfiles_keytab():
		keytab = Keytab.from_file(keytabfile)
		kenctype = [keytabentry.enctype for keytabentry in keytab.entries][0]
		keytabdata = keytabfile.read_bytes().hex()
		cred = KerberosCredential.from_keytab(keytabdata, 'administrator', 'domain.local', encoding = 'hex')
		assert cred.username == 'administrator'
		assert cred.domain == 'domain.local'
		if Enctype.AES256 == kenctype:
			enctype = EncryptionType.AES256_CTS_HMAC_SHA1_96
		elif Enctype.AES128 == kenctype:
			enctype = EncryptionType.AES128_CTS_HMAC_SHA1_96
		elif Enctype.DES3 == kenctype:
			enctype = EncryptionType.DES3_CBC_SHA1
		elif Enctype.DES_MD5 == kenctype:
			enctype = EncryptionType.DES_CBC_MD5
		elif Enctype.RC4 == kenctype:
			enctype = EncryptionType.ARCFOUR_HMAC_MD5
		
		assert cred.get_key_for_enctype(enctype) is not None

def test_load_keytab_b64_1():
	for keytabfile in get_testfiles_keytab():
		keytab = Keytab.from_file(keytabfile)
		kenctype = [keytabentry.enctype for keytabentry in keytab.entries][0]
		keytabdata = base64.b64encode(keytabfile.read_bytes()).decode()
		cred = KerberosCredential.from_keytab(keytabdata, 'administrator', 'domain.local', encoding = 'base64')
		assert cred.username == 'administrator'
		assert cred.domain == 'domain.local'
		if Enctype.AES256 == kenctype:
			enctype = EncryptionType.AES256_CTS_HMAC_SHA1_96
		elif Enctype.AES128 == kenctype:
			enctype = EncryptionType.AES128_CTS_HMAC_SHA1_96
		elif Enctype.DES3 == kenctype:
			enctype = EncryptionType.DES3_CBC_SHA1
		elif Enctype.DES_MD5 == kenctype:
			enctype = EncryptionType.DES_CBC_MD5
		elif Enctype.RC4 == kenctype:
			enctype = EncryptionType.ARCFOUR_HMAC_MD5
		
		assert cred.get_key_for_enctype(enctype) is not None

def test_load_keytab_b64_2():
	for keytabfile in get_testfiles_keytab():
		keytab = Keytab.from_file(keytabfile)
		kenctype = [keytabentry.enctype for keytabentry in keytab.entries][0]
		keytabdata = base64.b64encode(keytabfile.read_bytes()).decode()
		cred = KerberosCredential.from_keytab_string(keytabdata, 'administrator', 'domain.local')
		assert cred.username == 'administrator'
		assert cred.domain == 'domain.local'
		if Enctype.AES256 == kenctype:
			enctype = EncryptionType.AES256_CTS_HMAC_SHA1_96
		elif Enctype.AES128 == kenctype:
			enctype = EncryptionType.AES128_CTS_HMAC_SHA1_96
		elif Enctype.DES3 == kenctype:
			enctype = EncryptionType.DES3_CBC_SHA1
		elif Enctype.DES_MD5 == kenctype:
			enctype = EncryptionType.DES_CBC_MD5
		elif Enctype.RC4 == kenctype:
			enctype = EncryptionType.ARCFOUR_HMAC_MD5
		
		assert cred.get_key_for_enctype(enctype) is not None