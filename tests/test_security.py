from minikerberos.common.factory import KerberosClientFactory
from minikerberos.common.spn import KerberosSPN
from minikerberos.common.creds import KerberosCredential
from minikerberos.common.kirbi import Kirbi
from minikerberos.security import krb5userenum, asreproast, kerberoast
from minikerberos.common.target import KerberosTarget
import asyncio
import pytest 



# TEST DATA
##
KERBEROS_SERVER = '10.10.10.2'
KERBEROS_DOMAIN = 'TEST.CORP'
KERBEROS_USER = 'victim'
KERBEROS_PASSWORD = 'Passw0rd!1'

## Generic user account with valid credentials
KERBEROS_CONN_URL_PW = 'kerberos+password://TEST\\victim:Passw0rd!1@10.10.10.2'
KERBEROS_CONN_URL_RC4 = 'kerberos+rc4://TEST\\victim:f8963568a1ec62a3161d9d6449baba93@10.10.10.2'
KERBEROS_CONN_URL_RC4MD4 = 'kerberos+password://TEST\\victim:Passw0rd!1@10.10.10.2/?etype=-128'
KERBEROS_CONN_URL_AES128 = 'kerberos+password://TEST\\victim:Passw0rd!1@10.10.10.2/?etype=17'
KERBEROS_CONN_URL_AES256 = 'kerberos+password://TEST\\victim:Passw0rd!1@10.10.10.2/?etype=18'
KERBEROS_CONN_URL_PKINIT_PFX = 'kerberos+pfx://TEST\\victim:admin@10.10.10.2/?certdata=a.pfx'
KERBEROS_CONN_URL_PKINIT_PEM = 'kerberos+pem://TEST\\victim@10.10.10.2/?certdata=a.pem&keydata=a.key'


# SPN string for a valid TGS request
KERBEROS_TGS_SPN = 'cifs/win2019ad.test.corp@test.corp'

# Machine account for delegation tests
KERBEROS_CONN_URL_MACHINE = 'kerberos+password://TEST\\delegationtest$:TESTPassw0rd!1TESTPassw0rd!1@10.10.10.2'

# SPN string for a valid TGS request
KERBEROS_DELEGATION_USER_SELF = 'Administrator@test.corp'
KERBEROS_DELEGATION_SPN_SELF = 'cifs/delegationtest.test.corp@test.corp'

KERBEROS_DELEGATION_USER_PROXY = 'victim@test.corp'
KERBEROS_DELEGATION_SPN_PROXY = 'cifs/win2019ad.test.corp@test.corp'

KERBEROS_KERBEROAST_USER = 'srv_http'
KERBEROS_USERNAMES_VALID = [
	'Administrator',
	'victim',
	'asreptest', # this one is a bit special, it's a service account that can be used to request TGT without password
]
KERBEROS_USERNAMES_NONEXISTENT = [
	'nonexistent123',
	'nonexistent456',
	'nonexistent789'
]

KERBEROS_USERNAMES_KERBEROAST = [
	'krbtgt',
	'srv_mssql',
]
KERBEROS_USERNAMES_ASREP = [
	'asreptest', # this one is a bit special, it's a service account that can be used to request TGT without password
]


@pytest.mark.asyncio
async def test_userenum_valid():
	target = KerberosTarget(KERBEROS_SERVER)
	found = 0
	async for username, res, response, err in krb5userenum(target, KERBEROS_USERNAMES_VALID, KERBEROS_DOMAIN):
		assert err is None
		assert res is True
		found += 1
	assert found == len(KERBEROS_USERNAMES_VALID)
		

@pytest.mark.asyncio
async def test_userenum_invalid():
	target = KerberosTarget(KERBEROS_SERVER)
	found = 0
	async for username, res, response, err in krb5userenum(target, KERBEROS_USERNAMES_NONEXISTENT, KERBEROS_DOMAIN):
		assert err is None
		assert res is False
		found += 1
	assert found == len(KERBEROS_USERNAMES_NONEXISTENT)
	
@pytest.mark.asyncio
async def test_kerberoast_linux():
	cu = KerberosClientFactory.from_url(KERBEROS_CONN_URL_PW)
	async for username, res, err in kerberoast(cu, KERBEROS_USERNAMES_KERBEROAST, KERBEROS_DOMAIN):
		assert res is not None
		assert err is None
		assert username is not None


@pytest.mark.asyncio
async def test_kerberoast_linux_override():
	cu = KerberosClientFactory.from_url(KERBEROS_CONN_URL_PW)
	async for username, res, err in kerberoast(cu, KERBEROS_USERNAMES_KERBEROAST, KERBEROS_DOMAIN, override_etype=23):
		assert res is not None
		assert err is None
		assert username is not None

@pytest.mark.asyncio
async def test_apreproast_valid():
	target = KerberosTarget(KERBEROS_SERVER)
	async for username, res, err in asreproast(target, KERBEROS_USERNAMES_ASREP, KERBEROS_DOMAIN):
		assert err is None
		assert res is not None

@pytest.mark.asyncio
async def test_apreproast_invalid():
	target = KerberosTarget(KERBEROS_SERVER)
	async for username, res, err in asreproast(target, KERBEROS_USERNAMES_KERBEROAST, KERBEROS_DOMAIN):
		assert err is not None


if __name__ == '__main__':
	asyncio.run(test_userenum_invalid())