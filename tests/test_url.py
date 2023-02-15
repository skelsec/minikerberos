import shutil
import os

from minikerberos.common.factory import KerberosClientFactory
from minikerberos.common.ccache import CCACHE
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


def test_url_pw_1():
	urlstr = 'kerberos+password://domain\\user:pass@word34tnk;adfs@127.0.0.1'
	url = KerberosClientFactory.from_url(urlstr)
	cred = url.get_creds()
	assert cred.domain == 'domain'
	assert cred.username == 'user'
	assert cred.password == 'pass@word34tnk;adfs'

	target = url.get_target()
	assert target.ip == '127.0.0.1'
	assert target.port == 88

def test_url_aes():
	urlstr = 'kerberos+aes://domain\\user:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@dc_ip'
	url = KerberosClientFactory.from_url(urlstr)
	cred = url.get_creds()
	assert cred.domain == 'domain'
	assert cred.username == 'user'
	assert cred.kerberos_key_aes_128 == 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
	assert cred.kerberos_key_aes_256 == None
	
	target = url.get_target()
	assert target.hostname == 'dc_ip'
	assert target.port == 88

def test_url_aes_256():
	urlstr = 'kerberos+aes256://domain\\user:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@dc_ip'
	url = KerberosClientFactory.from_url(urlstr)
	cred = url.get_creds()
	assert cred.domain == 'domain'
	assert cred.username == 'user'
	assert cred.kerberos_key_aes_128 == None
	assert cred.kerberos_key_aes_256 == 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
	
	target = url.get_target()
	assert target.hostname == 'dc_ip'
	assert target.port == 88

def test_url_rc4():
	urlstr = 'kerberos+rc4://domain\\user:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@dc_ip'
	url = KerberosClientFactory.from_url(urlstr)
	cred = url.get_creds()
	assert cred.domain == 'domain'
	assert cred.username == 'user'
	assert cred.kerberos_key_rc4 == 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
	
	target = url.get_target()
	assert target.hostname == 'dc_ip'
	assert target.port == 88

def test_url_ccachefile():
	ccache1 = CCACHE.from_file(ADMIN_CCACHE)
	targets = [x for x in ccache1.list_targets()]
	try:
		shutil.copy(ADMIN_CCACHE, 'a.ccache')
		urlstr = 'kerberos+ccache://domain\\user:a.ccache@dc_ip'
		url = KerberosClientFactory.from_url(urlstr)
		cred = url.get_creds()
		assert cred.domain == 'domain'
		assert cred.username == 'user'
		targets2 = [x for x in cred.ccache.list_targets()]
		assert listcompare(targets, targets2)
		
		target = url.get_target()
		assert target.hostname == 'dc_ip'
		assert target.port == 88
	finally:
		os.remove('a.ccache')

def test_url_kirbi():
	for kirbifile in get_testfiles_kirbi():
		try:
			shutil.copy(kirbifile, 'a.kirbi')
			urlstr = 'kerberos+kirbi://domain\\user:a.kirbi@dc_ip'
			url = KerberosClientFactory.from_url(urlstr)
			cred = url.get_creds()
			assert cred.domain.upper() == 'TEST.CORP'
			assert cred.username.upper().find('VICTIM') != -1

			target = url.get_target()
			assert target.hostname == 'dc_ip'
			assert target.port == 88

		finally:
			os.remove('a.kirbi')

def test_url_string():
	urlstr = 'kerberos+nt://domain\\user:921a7fece11f4d8c72432e41e40d0372@127.0.0.1'
	url = KerberosClientFactory.from_url(urlstr)
	cred1 = url.get_creds()
	target1 = url.get_target()
	url2 = KerberosClientFactory.from_url(urlstr)
	cred2 = url2.get_creds()
	target2 = url2.get_target()
	assert str(cred1) == str(cred2)
	assert str(target1) == str(target2)

def test_url_nopreauth():
	urlstr = 'kerberos+none://domain\\user@127.0.0.1'
	url = KerberosClientFactory.from_url(urlstr)
	cred1 = url.get_creds()
	target1 = url.get_target()
	url2 = KerberosClientFactory.from_url(urlstr)
	cred2 = url2.get_creds()
	target2 = url2.get_target()
	assert str(cred1) == str(cred2)
	assert str(target1) == str(target2)

def test_url_nopreauth():
	urlstr = 'kerberos+none://domain\\user@127.0.0.1'
	url = KerberosClientFactory.from_url(urlstr)
	cred1 = url.get_creds()
	target1 = url.get_target()
	url2 = KerberosClientFactory.from_url(urlstr)
	cred2 = url2.get_creds()
	target2 = url2.get_target()
	assert str(cred1) == str(cred2)
	assert str(target1) == str(target2)

#def test_url_certstore():
#	urlstr = 'kerberos+certstore://127.0.0.1/?cn=whoami@domain&certstore=MY'
#	url = KerberosClientFactory.from_url(urlstr)
#	cred1 = url.get_creds()
#	target1 = url.get_target()
#	url2 = KerberosClientFactory.from_url(urlstr)
#	cred2 = url2.get_creds()
#	target2 = url2.get_target()
#	assert str(cred1) == str(cred2)
#	assert str(target1) == str(target2)

if __name__ == '__main__':
	test_url_certstore()