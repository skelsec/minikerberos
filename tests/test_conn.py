from minikerberos.common.factory import KerberosClientFactory
from minikerberos.common.spn import KerberosSPN
from minikerberos.common.creds import KerberosCredential
from minikerberos.common.kirbi import Kirbi
from minikerberos.protocol.external.ticketutil import get_NT_from_PAC
from minikerberos.protocol.ticketutils import construct_apreq_from_tgs_tgt
import tempfile
import asyncio
import pathlib
import shutil
import os

import pytest 
from .config import *


@pytest.mark.asyncio
async def test_tgt_pw():
	cu = KerberosClientFactory.from_url(KERBEROS_CONN_URL_PW)
	client = cu.get_client()
	await client.get_TGT()
	assert client.kerberos_TGT is not None
	assert client.kerberos_TGT_encpart is not None

@pytest.mark.asyncio
async def test_tgt_pw_incorrect_realm():
	cu = KerberosClientFactory.from_url('kerberos+password://NONEXISTENT\\%s:%s@10.10.10.2' % (KERBEROS_USER, KERBEROS_PASSWORD))
	client = cu.get_client()
	with pytest.raises(Exception) as e_info:
		await client.get_TGT()

@pytest.mark.asyncio
async def test_tgt_pw_incorrect_user():
	cu = KerberosClientFactory.from_url('kerberos+password://%s\\NOTVALIDUSER:%s@10.10.10.2' % (KERBEROS_DOMAIN, KERBEROS_PASSWORD))
	client = cu.get_client()
	with pytest.raises(Exception) as e_info:
		await client.get_TGT()


@pytest.mark.asyncio
async def test_tgt_pw_incorrect_pw():
	cu = KerberosClientFactory.from_url('kerberos+password://%s\\%s:blablaThisiswrong12@10.10.10.2' % (KERBEROS_DOMAIN, KERBEROS_USER))
	client = cu.get_client()
	with pytest.raises(Exception) as e_info:
		await client.get_TGT()
	


@pytest.mark.asyncio
async def test_tgt_rc4():
	cu = KerberosClientFactory.from_url(KERBEROS_CONN_URL_RC4)
	cred = cu.get_creds()
	assert len(cred.get_supported_enctypes()) == 2
	assert 23 in cred.get_supported_enctypes(as_int=True)
	assert -128 in cred.get_supported_enctypes(as_int=True)
	client = cu.get_client()
	await client.get_TGT()
	assert client.kerberos_TGT is not None
	assert client.kerberos_TGT_encpart is not None

@pytest.mark.asyncio
async def test_tgt_aes128():
	cu = KerberosClientFactory.from_url(KERBEROS_CONN_URL_AES128)
	cred = cu.get_creds()
	assert len(cred.override_etypes) == 1
	assert cred.override_etypes[0].value == 17
	assert cred.get_supported_enctypes(as_int=True) == [17]
	client = cu.get_client()
	await client.get_TGT()
	assert client.kerberos_TGT is not None
	assert client.kerberos_TGT_encpart is not None

@pytest.mark.asyncio
async def test_tgt_aes256():
	cu = KerberosClientFactory.from_url(KERBEROS_CONN_URL_AES256)
	cred = cu.get_creds()
	assert len(cred.override_etypes) == 1
	assert cred.override_etypes[0].value == 18
	assert cred.get_supported_enctypes(as_int=True) == [18]
	client = cu.get_client()
	await client.get_TGT()
	assert client.kerberos_TGT is not None
	assert client.kerberos_TGT_encpart is not None

# TODO: need keytab to test
#@pytest.mark.asyncio
#async def test_tgt_keytab():
#    cu = KerberosClientFactory.from_url(KERBEROS_CONN_URL_AES256)
#    cred = cu.get_creds()
#    assert len(cred.override_etypes) == 1
#    assert cred.override_etypes[0].value == 18
#    assert cred.get_supported_enctypes(as_int=True) == [18]
#    client = cu.get_client()
#    await client.get_TGT()
#    assert client.kerberos_TGT is not None
#    assert client.kerberos_TGT_encpart is not None

@pytest.mark.asyncio
async def test_tgs_direct():
	cu = KerberosClientFactory.from_url(KERBEROS_CONN_URL_PW)
	client = cu.get_client()
	await client.get_TGT()
	assert client.kerberos_TGT is not None
	assert client.kerberos_TGT_encpart is not None
	spn = KerberosSPN.from_spn(KERBEROS_TGS_SPN)
	tgs, encTGSRepPart, key = await client.get_TGS(spn)
	assert tgs is not None
	assert encTGSRepPart is not None
	assert key is not None

@pytest.mark.asyncio
async def test_tgs_direct_asreq():
	cu = KerberosClientFactory.from_url(KERBEROS_CONN_URL_PW)
	client = cu.get_client()
	await client.get_TGT()
	assert client.kerberos_TGT is not None
	assert client.kerberos_TGT_encpart is not None
	spn = KerberosSPN.from_spn(KERBEROS_TGS_SPN)
	tgs, encTGSRepPart, key = await client.get_TGS(spn)
	assert tgs is not None
	assert encTGSRepPart is not None
	assert key is not None
	asreq = construct_apreq_from_tgs_tgt(tgs, key, client.kerberos_TGT, flags = None, seq_number = 0, ap_opts = [], cb_data = None)
	assert asreq is not None

@pytest.mark.asyncio
async def test_tgs_direct_asreq_1():
	cu = KerberosClientFactory.from_url(KERBEROS_CONN_URL_PW)
	client = cu.get_client()
	await client.get_TGT()
	assert client.kerberos_TGT is not None
	assert client.kerberos_TGT_encpart is not None
	spn = KerberosSPN.from_spn(KERBEROS_TGS_SPN)
	tgs, encTGSRepPart, key = await client.get_TGS(spn)
	assert tgs is not None
	assert encTGSRepPart is not None
	assert key is not None
	asreq = client.construct_apreq(tgs, None, key, flags = None, seq_number = 0, ap_opts = [], cb_data = None)
	assert asreq is not None

@pytest.mark.asyncio
async def test_tgs_direct_incorrect_spn():
	cu = KerberosClientFactory.from_url(KERBEROS_CONN_URL_PW)
	client = cu.get_client()
	await client.get_TGT()
	assert client.kerberos_TGT is not None
	assert client.kerberos_TGT_encpart is not None
	spn = KerberosSPN.from_spn('whatis/noserver.%s@%s' % (KERBEROS_DOMAIN, KERBEROS_DOMAIN))
	with pytest.raises(Exception) as e_info:
		tgs, encTGSRepPart, key = await client.get_TGS(spn)


@pytest.mark.asyncio
async def test_tgs_ccache_tgt():
	cu = KerberosClientFactory.from_url(KERBEROS_CONN_URL_PW)
	client = cu.get_client()
	await client.get_TGT()
	assert client.kerberos_TGT is not None
	assert client.kerberos_TGT_encpart is not None
	with tempfile.NamedTemporaryFile() as file:
		client.ccache.to_file(file.name)
		spn = KerberosSPN.from_spn(KERBEROS_TGS_SPN)
		creds = KerberosCredential.from_ccache(file.name, encoding = 'file')
		client2 = cu.get_client_newcred(creds)
		tgs, encTGSRepPart, key = await client2.get_TGS(spn)
		assert tgs is not None
		assert encTGSRepPart is not None
		assert key is not None

@pytest.mark.asyncio
async def test_tgs_ccache_tgs():
	cu = KerberosClientFactory.from_url(KERBEROS_CONN_URL_PW)
	client = cu.get_client()
	await client.get_TGT()
	assert client.kerberos_TGT is not None
	assert client.kerberos_TGT_encpart is not None
	spn = KerberosSPN.from_spn(KERBEROS_TGS_SPN)
	tgs, encTGSRepPart, key = await client.get_TGS(spn)
	assert tgs is not None
	assert encTGSRepPart is not None
	assert key is not None
	with tempfile.NamedTemporaryFile() as file:
		client.ccache.to_file(file.name)
		creds = KerberosCredential.from_ccache(file.name, encoding = 'file')
		client2 = cu.get_client_newcred(creds)
		tgs, encTGSRepPart, key = await client2.get_TGS(spn)
		assert tgs is not None
		assert encTGSRepPart is not None
		assert key is not None

@pytest.mark.asyncio
async def test_tgs_kirbi():
	cu = KerberosClientFactory.from_url(KERBEROS_CONN_URL_PW)
	client = cu.get_client()
	await client.get_TGT()
	assert client.kerberos_TGT is not None
	assert client.kerberos_TGT_encpart is not None
	kirbi = Kirbi.from_ticketdata(client.kerberos_TGT, client.kerberos_TGT_encpart)
	spn = KerberosSPN.from_spn(KERBEROS_TGS_SPN)
	creds = KerberosCredential.from_kirbi(kirbi, encoding = 'kirbi')
	client2 = cu.get_client_newcred(creds)
	tgs, encTGSRepPart, key = await client2.get_TGS(spn)
	assert tgs is not None
	assert encTGSRepPart is not None
	assert key is not None

@pytest.mark.asyncio
async def test_delegation_self():
	cu = KerberosClientFactory.from_url(KERBEROS_CONN_URL_MACHINE)
	client = cu.get_client()
	await client.get_TGT()
	assert client.kerberos_TGT is not None
	assert client.kerberos_TGT_encpart is not None

	service_spn = KerberosSPN.from_spn(KERBEROS_DELEGATION_SPN_SELF)
	target_user = KerberosSPN.from_upn(KERBEROS_DELEGATION_USER_SELF)

	tgs, encTGSRepPart, key = await client.S4U2self(target_user, service_spn)
	assert tgs is not None
	assert encTGSRepPart is not None
	assert key is not None

@pytest.mark.asyncio
async def test_delegation_proxy():
	#moving certificate to current path...
	current_file_path = pathlib.Path(__file__).parent.absolute()
	pfx_file_path = current_file_path.joinpath('testdata', 'test.pfx')
	try:
		shutil.copy(pfx_file_path, 'a.pfx')
		cu = KerberosClientFactory.from_url(KERBEROS_CONN_URL_MACHINE)
		client = cu.get_client()
		await client.get_TGT()
		assert client.kerberos_TGT is not None
		assert client.kerberos_TGT_encpart is not None

		service_spn = KerberosSPN.from_spn(KERBEROS_DELEGATION_SPN_PROXY)
		target_user = KerberosSPN.from_upn(KERBEROS_DELEGATION_USER_PROXY)

		tgs, encTGSRepPart, key = await client.getST(target_user, service_spn)
		assert tgs is not None
		assert encTGSRepPart is not None
		assert key is not None
	finally:
		os.remove('a.pfx')

@pytest.mark.asyncio
async def test_pkinit_pfx():
	#moving certificate to current path...
	current_file_path = pathlib.Path(__file__).parent.absolute()
	cert_file_path = current_file_path.joinpath('testdata', 'test.pfx')
	try:
		shutil.copy(cert_file_path, 'a.pfx')
		cu = KerberosClientFactory.from_url(KERBEROS_CONN_URL_PKINIT_PFX)
		client = cu.get_client()
		await client.get_TGT()

		assert client.kerberos_TGT is not None
		assert client.kerberos_TGT_encpart is not None
	finally:
		os.remove('a.pfx')

@pytest.mark.asyncio
async def test_pkinit_pem():
	current_file_path = pathlib.Path(__file__).parent.absolute()
	cert_file_path = current_file_path.joinpath('testdata', 'test.pem')
	key_file_path = current_file_path.joinpath('testdata', 'test.key')
	try:
		shutil.copy(cert_file_path, 'a.pem')
		shutil.copy(key_file_path, 'a.key')
		cu = KerberosClientFactory.from_url(KERBEROS_CONN_URL_PKINIT_PEM)
		client = cu.get_client()
		await client.get_TGT()

		assert client.kerberos_TGT is not None
		assert client.kerberos_TGT_encpart is not None
	finally:
		os.remove('a.pem')
		os.remove('a.key')

@pytest.mark.asyncio
async def test_pkinit_u2u():
	#moving certificate to current path...
	current_file_path = pathlib.Path(__file__).parent.absolute()
	cert_file_path = current_file_path.joinpath('testdata', 'test.pfx')
	try:
		shutil.copy(cert_file_path, 'a.pfx')
		cu = KerberosClientFactory.from_url(KERBEROS_CONN_URL_PKINIT_PFX)
		client = cu.get_client()
		tgs, enctgs, key, decticket = await client.U2U()
		results = get_NT_from_PAC(client.pkinit_tkey, decticket)
		assert len(results) > 0
		
	finally:
		os.remove('a.pfx')

@pytest.mark.asyncio
async def test_smb_kerberos_login():
	from aiosmb.commons.connection.factory import SMBConnectionFactory
	url = 'smb2+kerberos-password://TEST\\victim:Passw0rd!1@win2019ad.test.corp/?dc=10.10.10.2'
	factory = SMBConnectionFactory.from_url(url)
	connection = factory.get_connection()
	async with connection:
		_, err = await connection.login()
		assert err is None

@pytest.mark.asyncio
async def test_smb_kerberos_dcsync():
	try:
		from aiosmb.commons.connection.factory import SMBConnectionFactory
		from aiosmb.commons.interfaces.machine import SMBMachine
		url = 'smb2+kerberos-password://TEST\\Administrator:Passw0rd!1@win2019ad.test.corp/?dc=10.10.10.2'
		factory = SMBConnectionFactory.from_url(url)
		connection = factory.get_connection()
		async with connection:
			_, err = await connection.login()
			assert err is None
			return
			machine = SMBMachine(connection)
			async for secret, err in machine.dcsync(None, 'krbtgt'):
				print(secret)
				if err is not None:
					raise err
	except Exception as e:
		import traceback
		traceback.print_exc()
			

@pytest.mark.asyncio
async def test_md4():
	cu = KerberosClientFactory.from_url(KERBEROS_CONN_URL_RC4MD4)
	cred = cu.get_creds()
	assert len(cred.get_supported_enctypes()) == 1
	assert -128 in cred.get_supported_enctypes(as_int=True)
	client = cu.get_client()
	await client.get_TGT()
	assert client.kerberos_TGT is not None
	assert client.kerberos_TGT_encpart is not None

#@pytest.mark.asyncio
#async def test_keytab_1():
#	cu = KerberosClientFactory.from_url('kerberos+keytab://www.test.corp:app2.keytab@10.10.10.2')
#	cred = cu.get_creds()
#	print(str(cred))
#	print(cred.get_supported_enctypes())
#	client = cu.get_client()
#	await client.get_TGT()
#	assert client.kerberos_TGT is not None
#	assert client.kerberos_TGT_encpart is not None
	

async def amain():
	await test_smb_kerberos_dcsync()

if __name__ == '__main__':
	asyncio.run(amain())