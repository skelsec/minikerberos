# tests for ccache file
import pathlib
import base64
import tempfile
from minikerberos.common.kirbi import Kirbi
from minikerberos.common.ccache import CCACHE, Header, DateTime, Times,\
	Address, CCACHEOctetString, Authdata, Credential
from .config import *

def test_load_ccache():
	for ccachefile in get_testfiles_ccache():
		ccache = CCACHE.from_file(ccachefile)
		assert len(ccache.credentials) > 0
		targets = [x for x in ccache.list_targets()]
		assert len(targets) > 0
		with tempfile.NamedTemporaryFile() as f:
			ccache.to_file(f.name)
			ccache2 = CCACHE.from_file(f.name)
			targets2 = [x for x in ccache2.list_targets()]
			assert targets == targets2
			assert str(ccache) == str(ccache2)

def test_load_bytes():
	for ccachefile in get_testfiles_ccache():
		with open(ccachefile, 'rb') as f:
			ccache_bytes = f.read()
			ccache = CCACHE.from_bytes(ccache_bytes)
		assert len(ccache.credentials) > 0
		targets = [x for x in ccache.list_targets()]
		assert len(targets) > 0
		ccache_bytes = ccache.to_bytes()
		ccache2 = CCACHE.from_bytes(ccache_bytes)
		targets2 = [x for x in ccache2.list_targets()]
		assert listcompare(targets, targets2)

def test_load_hex():
	for ccachefile in get_testfiles_ccache():
		ccache = CCACHE.from_file(ccachefile)
		assert len(ccache.credentials) > 0
		targets = [x for x in ccache.list_targets()]
		assert len(targets) > 0
		ccache_hex = ccache.to_hex()
		ccache2 = CCACHE.from_hex(ccache_hex)
		targets2 = [x for x in ccache2.list_targets()]
		assert listcompare(targets, targets2)

def test_load_b64():
	for ccachefile in get_testfiles_ccache():
		ccache = CCACHE.from_file(ccachefile)
		assert len(ccache.credentials) > 0
		targets = [x for x in ccache.list_targets()]
		assert len(targets) > 0
		ccache_b64 = ccache.to_b64()
		ccache2 = CCACHE.from_b64(ccache_b64)
		targets2 = [x for x in ccache2.list_targets()]
		assert listcompare(targets, targets2)

def test_to_kirbidir():
	for ccachefile in get_testfiles_ccache():
		ccache = CCACHE.from_file(ccachefile)
		assert len(ccache.credentials) > 0
		targets = [x for x in ccache.list_targets()]
		assert len(targets) > 0
		with tempfile.TemporaryDirectory() as d:
			ccache.to_kirbidir(d)
			ccache2 = CCACHE.from_kirbidir(d)
			targets2 = [x for x in ccache2.list_targets()]
			assert listcompare(targets, targets2)

def test_from_kirbidir():
	ccache = CCACHE.from_kirbidir(KIRBI_DIR)
	assert len(ccache.credentials) > 0
	targets = [x for x in ccache.list_targets()]
	assert len(targets) > 0
	with tempfile.TemporaryDirectory() as d:
		ccache.to_kirbidir(d)
		ccache2 = CCACHE.from_kirbidir(d)
		targets2 = [x for x in ccache2.list_targets()]
		assert listcompare(targets, targets2)

def test_from_kirbifile():
	for kirbifile in get_testfiles_kirbi():
		ccache = CCACHE.from_kirbifile(kirbifile)
		assert len(ccache.credentials) > 0
		targets = [x for x in ccache.list_targets()]
		assert len(targets) > 0

def test_stupid_kirbifile():
	for kirbifile in get_testfiles_kirbi():
		with open(kirbifile, 'rb') as f:
			kirbifile = base64.b64encode(f.read())
		with tempfile.NamedTemporaryFile() as f:
			f.write(kirbifile)
			f.flush()
			ccache = CCACHE.from_kirbifile(f.name)
			assert len(ccache.credentials) > 0
			targets = [x for x in ccache.list_targets()]
			assert len(targets) > 0
		
	
def test_get_hashes():
	ccache = CCACHE.from_kirbidir(KIRBI_DIR)
	assert len(ccache.credentials) > 0
	hashes = ccache.get_hashes()
	assert len(hashes) > 0

def test_get_all_tgt():
	for ccachefile in get_testfiles_ccache():
		if ccachefile.name != 'administrator.ccache':
			continue
		ccache = CCACHE.from_file(ccachefile)
		assert len(ccache.credentials) > 0
		tgt = ccache.get_all_tgt()
		assert len(tgt) == 1
		tgt, key = tgt[0]
		assert tgt['pvno'] == 5
		assert tgt['msg-type'] == 11
		assert tgt['crealm'] == 'POUDLARD.WIZARD'
		assert tgt['cname']['name-type'] == 1
		assert tgt['cname']['name-string'] == ['administrator']
		assert key['keytype'] == 18
		assert len(key['keyvalue']) == 32


def test_get_all_tgt_1():
	# TODO: add a test case with multiple TGSs
	# there should be another test case with actual tgs
	for ccachefile in get_testfiles_ccache():
		if ccachefile.name != 'administrator.ccache':
			continue
		ccache = CCACHE.from_file(ccachefile)
		assert len(ccache.credentials) > 0
		tgs = ccache.get_all_tgs()
		assert len(tgs) == 0



def test_header():
	h = Header()
	h.tag = 1
	h.taglen = 4
	h.tagdata = b'abcd'
	assert h.to_bytes() == b'\x00\x01\x00\x04abcd'
	h2 = Header.from_bytes(h.to_bytes())[0]
	assert h2.tag == 1
	assert h2.taglen == 4
	assert h2.tagdata == b'abcd'
	assert str(h) == str(h2)

def test_datetime():
	dt = DateTime()
	dt.time_offset = 1999323
	dt.usec_offset = 1234567890
	dt2 = DateTime.from_bytes(dt.to_bytes())
	assert dt.time_offset == dt2.time_offset
	assert dt.usec_offset == dt2.usec_offset

def test_times():
	time = Times.dummy_time()
	time2 = Times.from_bytes(time.to_bytes())
	assert time.starttime == time2.starttime
	assert time.endtime == time2.endtime
	assert time.renew_till == time2.renew_till
	assert time.authtime == time2.authtime

def test_address():
	os = CCACHEOctetString()
	os.length = 4
	os.data = b'abcd'

	addr = Address()
	addr.addrtype = 2
	addr.addrdata = os
	addr2 = Address.from_bytes(addr.to_bytes())
	assert addr.addrtype == addr2.addrtype
	assert addr.addrdata == addr2.addrdata

def test_authdata():
	os = CCACHEOctetString()
	os.length = 4
	os.data = b'abcd'

	ad = Authdata()
	ad.authtype = 1
	ad.authdata = os
	ad2 = Authdata.from_bytes(ad.to_bytes())
	assert ad.authtype == ad2.authtype
	assert ad.authdata == ad2.authdata

def test_octetstring_string():
	tdata = 'HELLOWORLD!!!!'
	os = CCACHEOctetString.from_string(tdata)
	assert os.length == len(tdata)
	assert os.data == tdata.encode()

def test_credential_summary():
	for ccachefile in get_testfiles_ccache():
		ccache = CCACHE.from_file(ccachefile)
		assert len(ccache.credentials) > 0
		for cred in ccache.credentials:
			assert cred.summary() != ''


#def test_credential_tgs():
#	for ccachefile in get_testfiles_ccache():
#		ccache = CCACHE.from_file(ccachefile)
#		assert len(ccache.credentials) > 0
#		for cred in ccache.credentials:
#			tgs, key = cred.to_tgs()
#			cred2 = Credential.from_asn1(tgs, key)
#			assert cred2.to_bytes() == cred.to_bytes()

#def test_credential_kirbi():
#	for kirbifile in get_testfiles_kirbi():
#		kirbi = Kirbi.from_file(kirbifile)
#		cred = Credential.from_kirbi(kirbi)
#		kirbi2, _ = cred.to_kirbi()
#		assert kirbi2.kirbiobj.dump() == kirbi.kirbiobj.dump()
#
#if __name__ == '__main__':
#	test_credential_kirbi()

def test_times_from_asn1_reads_renew_till():
	# The EncKDCRepPart field is spelled 'renew-till' in the ASN.1 definition
	# (see protocol/asn1_structs.py), so that is the key from_asn1 has to look
	# up. It used to look for 'renew_till', which never matched and silently
	# left renew_till at 0.
	import datetime
	from minikerberos.common.utils import dt_to_kerbtime

	start = datetime.datetime(2025, 8, 8, 12, 0, 0, tzinfo=datetime.timezone.utc)
	end = start + datetime.timedelta(hours=10)
	renew = start + datetime.timedelta(days=7)

	enc_as_rep_part = {
		'authtime': start,
		'starttime': start,
		'endtime': end,
		'renew-till': renew,
	}
	times = Times.from_asn1(enc_as_rep_part)

	assert times.authtime == dt_to_kerbtime(start)
	assert times.starttime == dt_to_kerbtime(start)
	assert times.endtime == dt_to_kerbtime(end)
	assert times.renew_till == dt_to_kerbtime(renew)
	assert times.renew_till != 0


def test_times_from_asn1_without_renew_till_is_zero():
	import datetime

	start = datetime.datetime(2025, 8, 8, 12, 0, 0, tzinfo=datetime.timezone.utc)
	times = Times.from_asn1({'authtime': start, 'starttime': start, 'endtime': start})
	assert times.renew_till == 0


class _StubServer:
	def __init__(self, s):
		self._s = s

	def to_string(self, separator='/'):
		return self._s


class _StubTgtCredential:
	"""Minimal stand-in for Credential, enough for get_all_tgt/get_tgt."""

	def __init__(self, server_names, ticket_realm, cname, crealm):
		self.server = _StubServer('/'.join(server_names))
		self._tgt = {
			'ticket': {'sname': {'name-string': list(server_names)}, 'realm': ticket_realm},
			'cname': {'name-string': list(cname)},
			'crealm': crealm,
		}

	def to_tgt(self):
		return self._tgt, {'keytype': 18, 'keyvalue': b'\x00' * 32}


def _ccache_with_referral_tgts():
	# Same principal throughout: a TGT for the client's own realm, plus a
	# referral ticket for another realm. This is the layout in the issue.
	ccache = CCACHE(empty=True)
	ccache.credentials = [
		_StubTgtCredential(['krbtgt', 'TREE2.LAB'], 'TREE2.LAB', ['jane'], 'TREE2.LAB'),
		_StubTgtCredential(['krbtgt', 'BLOODY.CORP'], 'TREE2.LAB', ['jane'], 'TREE2.LAB'),
	]
	return ccache


def test_get_tgt_selects_by_target_realm():
	ccache = _ccache_with_referral_tgts()

	# No target realm: first TGT wins, exactly as before.
	tgt, key, err = ccache.get_tgt('jane', 'TREE2.LAB')
	assert err is None
	assert tgt['ticket']['sname']['name-string'] == ['krbtgt', 'TREE2.LAB']

	# Referral realm requested: the referral ticket must be picked, otherwise
	# the KDC rejects the resulting service ticket request.
	tgt, key, err = ccache.get_tgt('jane', 'TREE2.LAB', target_realm='BLOODY.CORP')
	assert err is None
	assert tgt['ticket']['sname']['name-string'] == ['krbtgt', 'BLOODY.CORP']

	# Realm that no TGT covers: fall back to the previous behaviour rather than
	# failing, so callers that cannot benefit are unaffected.
	tgt, key, err = ccache.get_tgt('jane', 'TREE2.LAB', target_realm='UNREACHABLE.LAB')
	assert err is None
	assert tgt['ticket']['sname']['name-string'] == ['krbtgt', 'TREE2.LAB']


class _RecordingTgtCCACHE:
	def __init__(self):
		self.seen = []

	def get_tgt(self, username, domain=None, strict=False, target_realm=None):
		self.seen.append(target_realm)
		return None, None, Exception('stop here')


def test_tgt_from_ccache_forwards_target_realm():
	from minikerberos.client import KerbrosClient
	from minikerberos.aioclient import AIOKerberosClient
	from minikerberos.common.creds import KerberosCredential

	for cls in (KerbrosClient, AIOKerberosClient):
		inst = cls.__new__(cls)
		inst.ccache = _RecordingTgtCCACHE()
		inst.credential = KerberosCredential()
		inst.tgt_from_ccache('BLOODY.CORP')
		assert inst.ccache.seen == ['BLOODY.CORP']

		inst = cls.__new__(cls)
		inst.ccache = _RecordingTgtCCACHE()
		inst.credential = KerberosCredential()
		inst.tgt_from_ccache()
		assert inst.ccache.seen == [None]
class _RecordingCCACHE:
	"""Records the strict argument a client forwards to get_tgs."""

	def __init__(self):
		self.seen = []

	def get_tgs(self, spn, strict=False):
		self.seen.append(strict)
		return None, None, Exception('no TGS for %s' % spn)


def _tgs_from_ccache_strict_pass(cls, spn, strict_flag):
	from minikerberos.common.creds import KerberosCredential
	inst = cls.__new__(cls)
	inst.ccache = _RecordingCCACHE()
	inst.credential = KerberosCredential()
	inst.credential.ccache_spn_strict_check = strict_flag
	inst.tgs_from_ccache(spn)
	return inst.ccache.seen


def test_tgs_from_ccache_forwards_strict_flag():
	# get_tgt_from_ccache already forwards credential.ccache_spn_strict_check;
	# tgs_from_ccache called get_tgs without it, so asking for strict matching
	# silently fell back to "return the first TGS available".
	from minikerberos.client import KerbrosClient
	from minikerberos.aioclient import AIOKerberosClient
	from minikerberos.common.spn import KerberosSPN

	spn = KerberosSPN.from_spn('cifs/absent.service@TEST.CORP')
	for cls in (KerbrosClient, AIOKerberosClient):
		assert _tgs_from_ccache_strict_pass(cls, spn, True) == [True]
		assert _tgs_from_ccache_strict_pass(cls, spn, False) == [False]
