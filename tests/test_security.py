from minikerberos.common.factory import KerberosClientFactory
from minikerberos.common.spn import KerberosSPN
from minikerberos.common.creds import KerberosCredential
from minikerberos.common.kirbi import Kirbi
from minikerberos.security import krb5userenum, asreproast, kerberoast
from minikerberos.common.target import KerberosTarget
import asyncio
import pytest 
from .config import *


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