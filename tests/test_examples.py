import tempfile
import pathlib
import asyncio
from minikerberos.common.ccache import CCACHE
from minikerberos.common.kirbi import Kirbi
import pytest
import shutil
import os
from .config import *

def test_ccacheroast():
	from minikerberos.examples.ccacheroast import ccacheroast
	ccache = CCACHE()
	with tempfile.NamedTemporaryFile() as f:
		for kirbifile in get_testfiles_kirbi():
			kirbi = Kirbi.from_file(kirbifile)
			ccache.add_kirbi(kirbi)
		
		ccache.to_file(f.name)
		ccacheroast(f.name)
		assert len(ccache.get_hashes()) > 0

# testcases for spnroast
@pytest.mark.asyncio
async def test_spnroast_base():
	from minikerberos.examples.spnroast import spnroast
	with tempfile.NamedTemporaryFile() as f:
		x = await spnroast(KERBEROS_CONN_URL_PW, KERBEROS_KERBEROAST_USER, KERBEROS_DOMAIN, f.name)
		f.flush()
		f.seek(0,0)
		data = f.read()
		assert len(data) > 0

@pytest.mark.asyncio
async def test_spnroast_23():
	from minikerberos.examples.spnroast import spnroast
	with tempfile.NamedTemporaryFile() as f:
		x = await spnroast(KERBEROS_CONN_URL_PW, KERBEROS_KERBEROAST_USER, KERBEROS_DOMAIN, f.name, etypes=23)
		f.flush()
		f.seek(0,0)
		data = f.read()
		assert len(data) > 0

@pytest.mark.asyncio
async def test_spnroast_all():
	from minikerberos.examples.spnroast import spnroast
	with tempfile.NamedTemporaryFile() as f:
		x = await spnroast(KERBEROS_CONN_URL_PW, KERBEROS_KERBEROAST_USER, KERBEROS_DOMAIN, f.name, etypes='23,17,18')
		f.flush()
		f.seek(0,0)
		data = f.read()
		assert len(data) > 0

@pytest.mark.asyncio
async def test_spnroast_list():
	from minikerberos.examples.spnroast import spnroast
	with tempfile.NamedTemporaryFile() as f:
		x = await spnroast(KERBEROS_CONN_URL_PW, [KERBEROS_KERBEROAST_USER], KERBEROS_DOMAIN, f.name)
		f.flush()
		f.seek(0,0)
		data = f.read()
		assert len(data) > 0

@pytest.mark.asyncio
async def test_spnroast_file():
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
async def test_spnroast_filedomain():
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
async def test_spnroast_listdomain():
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
	for kirbifile in get_testfiles_kirbi():
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
	asyncio.run(test_spnroast_base())