import tempfile
import pathlib
import asyncio
from minikerberos.common.ccache import CCACHE
from minikerberos.common.kirbi import Kirbi
import pytest
import shutil
import os



# TEST DATA
##
KERBEROS_SERVER = '10.10.10.2'
KERBEROS_DOMAIN = 'TEST.CORP'
KERBEROS_USER = 'victim'
KERBEROS_PASSWORD = 'Passw0rd!1'

## Generic user account with valid credentials
KERBEROS_CONN_URL_PW = 'kerberos+password://TEST\\victim:Passw0rd!1@10.10.10.2'
KERBEROS_CONN_URL_RC4 = 'kerberos+rc4://TEST\\victim:f8963568a1ec62a3161d9d6449baba93@10.10.10.2'
KERBEROS_CONN_URL_AES128 = 'kerberos+password://TEST\\victim:Passw0rd!1@10.10.10.2/?etype=17'
KERBEROS_CONN_URL_AES256 = 'kerberos+password://TEST\\victim:Passw0rd!1@10.10.10.2/?etype=18'
KERBEROS_CONN_URL_PKINIT_PFX = 'kerberos+pfx://TEST\\victim:admin@10.10.10.2/?certdata=a.pfx'


# SPN string for a valid TGS request
KERBEROS_TGS_SPN = 'cifs/win2019ad.test.corp@test.corp'

# Machine account for delegation tests
KERBEROS_CONN_URL_MACHINE = 'kerberos+password://TEST\\delegationtest$:TESTPassw0rd!1TESTPassw0rd!1@10.10.10.2'
KERBEROS_CONN_URL_MACHINE_CCACHE = 'kerberos+ccache://TEST\\delegationtest$:test.ccache@10.10.10.2'


# SPN string for a valid TGS request
KERBEROS_DELEGATION_USER_SELF = 'Administrator@test.corp'
KERBEROS_DELEGATION_SPN_SELF = 'cifs/delegationtest.test.corp@test.corp'

KERBEROS_DELEGATION_USER_PROXY = 'victim@test.corp'
KERBEROS_DELEGATION_SPN_PROXY = 'cifs/win2019ad.test.corp@test.corp'

KERBEROS_KERBEROAST_USER = 'srv_mssql'

KERBEROS_CONN_URL_ASREP_MD4ARC4 = 'kerberos+none://TEST\\asreptest@10.10.10.2'

def get_testfiles():
	current_file_path = pathlib.Path(__file__).parent.absolute()
	kirbi_file_path = current_file_path.joinpath('testdata', 'kirbi')
	for kirbifile in kirbi_file_path.glob('*.kirbi'):
		yield kirbifile


def test_ccacheroast():
	from minikerberos.examples.ccacheroast import ccacheroast
	ccache = CCACHE()
	with tempfile.NamedTemporaryFile() as f:
		for kirbifile in get_testfiles():
			kirbi = Kirbi.from_file(kirbifile)
			ccache.add_kirbi(kirbi)
		
		ccache.to_file(f.name)
		ccacheroast(f.name)
		assert len(ccache.get_hashes()) > 0

# testcases for spnroast
@pytest.mark.asyncio
async def test_spnroast_1():
	from minikerberos.examples.spnroast import spnroast
	with tempfile.NamedTemporaryFile() as f:
		x = await spnroast(KERBEROS_CONN_URL_PW, KERBEROS_KERBEROAST_USER, KERBEROS_DOMAIN, f.name)
		f.flush()
		f.seek(0,0)
		data = f.read()
		assert len(data) > 0

@pytest.mark.asyncio
async def test_spnroast_2():
	from minikerberos.examples.spnroast import spnroast
	with tempfile.NamedTemporaryFile() as f:
		x = await spnroast(KERBEROS_CONN_URL_PW, KERBEROS_KERBEROAST_USER, KERBEROS_DOMAIN, f.name, etypes=23)
		f.flush()
		f.seek(0,0)
		data = f.read()
		assert len(data) > 0

@pytest.mark.asyncio
async def test_spnroast_2():
	from minikerberos.examples.spnroast import spnroast
	with tempfile.NamedTemporaryFile() as f:
		x = await spnroast(KERBEROS_CONN_URL_PW, KERBEROS_KERBEROAST_USER, KERBEROS_DOMAIN, f.name, etypes=18)
		f.flush()
		f.seek(0,0)
		data = f.read()
		assert len(data) > 0

@pytest.mark.asyncio
async def test_spnroast_2():
	from minikerberos.examples.spnroast import spnroast
	with tempfile.NamedTemporaryFile() as f:
		x = await spnroast(KERBEROS_CONN_URL_PW, KERBEROS_KERBEROAST_USER, KERBEROS_DOMAIN, f.name, etypes='23,17,18')
		f.flush()
		f.seek(0,0)
		data = f.read()
		assert len(data) > 0

@pytest.mark.asyncio
async def test_spnroast_3():
	from minikerberos.examples.spnroast import spnroast
	with tempfile.NamedTemporaryFile() as f:
		x = await spnroast(KERBEROS_CONN_URL_PW, [KERBEROS_KERBEROAST_USER], KERBEROS_DOMAIN, f.name)
		f.flush()
		f.seek(0,0)
		data = f.read()
		assert len(data) > 0

@pytest.mark.asyncio
async def test_spnroast_3():
	from minikerberos.examples.spnroast import spnroast
	with tempfile.NamedTemporaryFile('w') as d:
		d.write(KERBEROS_KERBEROAST_USER)
		d.flush()
		with tempfile.NamedTemporaryFile() as f:
			x = await spnroast(KERBEROS_CONN_URL_PW, d.name, KERBEROS_DOMAIN, f.name)
			f.flush()
			f.seek(0,0)
			data = f.read()
			assert len(data) > 0

@pytest.mark.asyncio
async def test_spnroast_3():
	from minikerberos.examples.spnroast import spnroast
	with tempfile.NamedTemporaryFile('w') as d:
		d.write(KERBEROS_KERBEROAST_USER + '@' + KERBEROS_DOMAIN)
		d.flush()
		with tempfile.NamedTemporaryFile() as f:
			x = await spnroast(KERBEROS_CONN_URL_PW, d.name, None, f.name)
			f.flush()
			f.seek(0,0)
			data = f.read()
			assert len(data) > 0

@pytest.mark.asyncio
async def test_spnroast_3():
	from minikerberos.examples.spnroast import spnroast
	with tempfile.NamedTemporaryFile() as f:
		x = await spnroast(KERBEROS_CONN_URL_PW, [KERBEROS_KERBEROAST_USER + '@' + KERBEROS_DOMAIN], KERBEROS_DOMAIN, f.name)
		f.flush()
		f.seek(0,0)
		data = f.read()
		assert len(data) > 0

def test_kirbi2ccache():
	from minikerberos.examples.kirbi2ccache import kirbi2ccache
	ccache = CCACHE()
	for kirbifile in get_testfiles():
		kirbi = Kirbi.from_file(kirbifile)
		ccache.add_kirbi(kirbi)
	with tempfile.NamedTemporaryFile() as f:
		kirbi2ccache(kirbifile, f.name)
		ccache2 = CCACHE.from_file(f.name)
		assert len(ccache2.get_hashes()) > 0

@pytest.mark.asyncio
async def test_gettgt():
	from minikerberos.examples.getTGT import getTGT
	with tempfile.NamedTemporaryFile() as d:
		with tempfile.NamedTemporaryFile() as f:
			await getTGT(KERBEROS_CONN_URL_PW, d.name, f.name)
			ccache = CCACHE.from_file(f.name)
			assert len(ccache.get_hashes()) > 0
		kirbi = Kirbi.from_file(d.name)
		assert kirbi.kirbiobj is not None

@pytest.mark.asyncio
async def test_gettgt_nopac():
	from minikerberos.examples.getTGT import getTGT
	with tempfile.NamedTemporaryFile() as d:
		with tempfile.NamedTemporaryFile() as f:
			await getTGT(KERBEROS_CONN_URL_PW, d.name, f.name, nopac=True)
			ccache = CCACHE.from_file(f.name)
			assert len(ccache.get_hashes()) > 0
		kirbi = Kirbi.from_file(d.name)
		assert kirbi.kirbiobj is not None

@pytest.mark.asyncio
async def test_gettgs():
	from minikerberos.examples.getTGS import getTGS
	with tempfile.NamedTemporaryFile() as d:
		with tempfile.NamedTemporaryFile() as f:
			await getTGS(KERBEROS_CONN_URL_PW, KERBEROS_TGS_SPN ,d.name, f.name)
			ccache = CCACHE.from_file(f.name)
			assert len(ccache.get_hashes()) > 0
		kirbi = Kirbi.from_file(d.name)
		assert kirbi.kirbiobj is not None

@pytest.mark.asyncio
async def test_getS4U2Self():
	from minikerberos.examples.getS4U2self import getS4U2self
	with tempfile.NamedTemporaryFile() as d:
		with tempfile.NamedTemporaryFile() as f:
			await getS4U2self(KERBEROS_CONN_URL_MACHINE, KERBEROS_DELEGATION_SPN_SELF, KERBEROS_DELEGATION_USER_SELF,d.name, f.name)
			ccache = CCACHE.from_file(f.name)
			assert len(ccache.get_hashes()) > 0
		kirbi = Kirbi.from_file(d.name)
		assert kirbi.kirbiobj is not None

@pytest.mark.asyncio
async def test_getS4U2Self_ccache():
	import os
	from minikerberos.examples.getS4U2self import getS4U2self
	from minikerberos.examples.getTGT import getTGT
	try:
		await getTGT(KERBEROS_CONN_URL_MACHINE, ccachefile='test.ccache')
		with tempfile.NamedTemporaryFile() as d:
			with tempfile.NamedTemporaryFile() as f:
				await getS4U2self(KERBEROS_CONN_URL_MACHINE_CCACHE, KERBEROS_DELEGATION_SPN_SELF, KERBEROS_DELEGATION_USER_SELF,d.name, f.name)
				ccache = CCACHE.from_file(f.name)
				assert len(ccache.get_hashes()) > 0
			kirbi = Kirbi.from_file(d.name)
			assert kirbi.kirbiobj is not None
	finally:
		os.remove('test.ccache')

@pytest.mark.asyncio
async def test_getS4U2proxy():
	from minikerberos.examples.getS4U2proxy import getS4U2proxy
	with tempfile.NamedTemporaryFile() as d:
		with tempfile.NamedTemporaryFile() as f:
			await getS4U2proxy(KERBEROS_CONN_URL_MACHINE, KERBEROS_DELEGATION_SPN_PROXY, KERBEROS_DELEGATION_USER_PROXY, d.name, f.name)
			ccache = CCACHE.from_file(f.name)
			assert len(ccache.get_hashes()) > 0
		kirbi = Kirbi.from_file(d.name)
		assert kirbi.kirbiobj is not None

@pytest.mark.asyncio
async def test_getS4U2proxy_ccache():
	import os
	from minikerberos.examples.getS4U2proxy import getS4U2proxy
	from minikerberos.examples.getTGT import getTGT
	try:
		await getTGT(KERBEROS_CONN_URL_MACHINE, ccachefile='test.ccache')
		with tempfile.NamedTemporaryFile() as d:
			with tempfile.NamedTemporaryFile() as f:
				await getS4U2proxy(KERBEROS_CONN_URL_MACHINE_CCACHE, KERBEROS_DELEGATION_SPN_PROXY, KERBEROS_DELEGATION_USER_PROXY,d.name, f.name)
				ccache = CCACHE.from_file(f.name)
				assert len(ccache.get_hashes()) > 0
			kirbi = Kirbi.from_file(d.name)
			assert kirbi.kirbiobj is not None
	finally:
		os.remove('test.ccache')

@pytest.mark.asyncio
async def test_getnt():
	from minikerberos.examples.getNT import get_NT
	#moving certificate to current path...
	current_file_path = pathlib.Path(__file__).parent.absolute()
	cert_file_path = current_file_path.joinpath('testdata', 'test.pfx')
	try:
		shutil.copy(cert_file_path, 'a.pfx')
		results = await get_NT(KERBEROS_CONN_URL_PKINIT_PFX)
		assert len(results) > 0
	finally:
		os.remove('a.pfx')

@pytest.mark.asyncio
async def test_cve_2022_33679():
	from minikerberos.examples.CVE_2022_33679 import exploit
	with tempfile.NamedTemporaryFile() as f:
		await exploit(KERBEROS_CONN_URL_ASREP_MD4ARC4, f.name)
		kirbi = Kirbi.from_file(f.name)
		assert kirbi.kirbiobj is not None




if __name__ == '__main__':
	asyncio.run(test_getnt())