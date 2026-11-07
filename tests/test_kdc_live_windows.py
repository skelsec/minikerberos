"""
Live integration tests for enctype selection against a Windows AD KDC.

These exercise the fix for the "RC4 service tickets are always requested"
bug (asyauth#19 / minikerberos): a password login must negotiate an AES
session key, and TGS/S4U/U2U requests must offer AES-first etypes instead
of copying the TGT session-key etype.

They require a live Windows DC and are skipped unless one is reachable.
Configuration is taken from environment variables and defaults to the GOAD
lab (north.sevenkingdoms.local / hodor):

    MINIKERBEROS_WIN_DC         DC IP/host         (default 192.168.56.11)
    MINIKERBEROS_WIN_PORT       Kerberos port      (default 88)
    MINIKERBEROS_WIN_DOMAIN     realm              (default north.sevenkingdoms.local)
    MINIKERBEROS_WIN_USER       username           (default hodor)
    MINIKERBEROS_WIN_PASSWORD   password           (default hodor)
    MINIKERBEROS_WIN_SPN        service SPN to roast
                                (default cifs/winterfell.north.sevenkingdoms.local@NORTH.SEVENKINGDOMS.LOCAL)

Example:

    MINIKERBEROS_WIN_DC=192.168.56.11 pytest tests/test_kdc_live_windows.py
"""
import os
import socket
import asyncio

import pytest

from minikerberos.common.factory import KerberosClientFactory
from minikerberos.common.spn import KerberosSPN
from minikerberos.common.creds import KerberosCredential
from minikerberos.protocol.constants import EncryptionType
from minikerberos.protocol.asn1_structs import TGS_REQ

DC = os.environ.get('MINIKERBEROS_WIN_DC', '192.168.56.11')
PORT = int(os.environ.get('MINIKERBEROS_WIN_PORT', '88') or '88')
DOMAIN = os.environ.get('MINIKERBEROS_WIN_DOMAIN', 'north.sevenkingdoms.local')
USER = os.environ.get('MINIKERBEROS_WIN_USER', 'hodor')
PASSWORD = os.environ.get('MINIKERBEROS_WIN_PASSWORD', 'hodor')
SPN = os.environ.get(
    'MINIKERBEROS_WIN_SPN',
    'cifs/winterfell.north.sevenkingdoms.local@NORTH.SEVENKINGDOMS.LOCAL',
)

AES256 = EncryptionType.AES256_CTS_HMAC_SHA1_96.value  # 18
AES128 = EncryptionType.AES128_CTS_HMAC_SHA1_96.value  # 17
RC4 = EncryptionType.ARCFOUR_HMAC_MD5.value            # 23

# What every TGS-type request should offer now: AES first, RC4 as fallback.
EXPECTED_TGS_ETYPES = [AES256, AES128, RC4]


def _reachable(host, port):
    try:
        with socket.create_connection((host, port), timeout=3):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not _reachable(DC, PORT),
    reason='No Windows KDC reachable at %s:%d; set MINIKERBEROS_WIN_* to enable' % (DC, PORT),
)


def _pw_url():
    return 'kerberos+password://%s\\%s:%s@%s' % (DOMAIN, USER, PASSWORD, DC)


def _nt_hash():
    # Derive the NT hash (== RC4 key) from the password via the library itself,
    # so the RC4 login path needs no hardcoded hash or external md4 dependency.
    cred = KerberosClientFactory.from_url(_pw_url()).get_creds()
    return cred.get_key_for_enctype(EncryptionType.ARCFOUR_HMAC_MD5).hex()


def _rc4_url():
    return 'kerberos+rc4://%s\\%s:%s@%s' % (DOMAIN, USER, _nt_hash(), DC)


def _spy_etypes(client):
    """Record the req-body etype list of every TGS-REQ the client sends,
    while still forwarding the request to the real KDC. Handles both the
    sync and async socket implementations."""
    sent = []
    orig = client.ksoc.sendrecv

    def _record(data):
        try:
            sent.append(TGS_REQ.load(data).native['req-body']['etype'])
        except Exception:
            pass

    if asyncio.iscoroutinefunction(orig):
        async def wrapped(data, *a, **k):
            _record(data)
            return await orig(data, *a, **k)
    else:
        def wrapped(data, *a, **k):
            _record(data)
            return orig(data, *a, **k)

    client.ksoc.sendrecv = wrapped
    return sent


# --------------------------------------------------------------------------
# TGT: a password login must end up with an AES256 session key (issue #19).
# --------------------------------------------------------------------------

def test_tgt_password_prefers_aes_sync():
    client = KerberosClientFactory.from_url(_pw_url()).get_client_blocking()
    client.get_TGT()
    assert client.kerberos_session_key.enctype == AES256


@pytest.mark.asyncio
async def test_tgt_password_prefers_aes_async():
    client = KerberosClientFactory.from_url(_pw_url()).get_client()
    await client.get_TGT()
    assert client.kerberos_session_key.enctype == AES256


# --------------------------------------------------------------------------
# get_TGS: request offers AES-first, resulting service ticket + session key
# are AES256 for a password login.
# --------------------------------------------------------------------------

def test_tgs_password_is_aes_sync():
    client = KerberosClientFactory.from_url(_pw_url()).get_client_blocking()
    client.get_TGT()
    sent = _spy_etypes(client)
    tgs, encpart, key = client.get_TGS(KerberosSPN.from_spn(SPN))
    assert sent == [EXPECTED_TGS_ETYPES]
    assert tgs['ticket']['enc-part']['etype'] == AES256
    assert key.enctype == AES256


@pytest.mark.asyncio
async def test_tgs_password_is_aes_async():
    client = KerberosClientFactory.from_url(_pw_url()).get_client()
    await client.get_TGT()
    sent = _spy_etypes(client)
    tgs, encpart, key = await client.get_TGS(KerberosSPN.from_spn(SPN))
    assert sent == [EXPECTED_TGS_ETYPES]
    assert tgs['ticket']['enc-part']['etype'] == AES256
    assert key.enctype == AES256


# --------------------------------------------------------------------------
# dirkjan's exact case: an RC4 TGT (NT-hash login) must still yield an AES256
# service ticket, because the TGS request no longer copies the TGT etype.
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_tgs_from_rc4_tgt_still_aes_async():
    client = KerberosClientFactory.from_url(_rc4_url()).get_client()
    await client.get_TGT()
    assert client.kerberos_session_key.enctype == RC4  # only an NT hash is available
    sent = _spy_etypes(client)
    tgs, encpart, key = await client.get_TGS(KerberosSPN.from_spn(SPN))
    assert sent == [EXPECTED_TGS_ETYPES]
    assert tgs['ticket']['enc-part']['etype'] == AES256
    assert key.enctype == AES256


# --------------------------------------------------------------------------
# ccache TGT: get_TGS over a reloaded ccache also offers AES-first.
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_tgs_from_ccache_is_aes_async():
    import tempfile
    cu = KerberosClientFactory.from_url(_pw_url())
    client = cu.get_client()
    await client.get_TGT()
    with tempfile.NamedTemporaryFile() as fh:
        client.ccache.to_file(fh.name)
        creds = KerberosCredential.from_ccache(fh.name, encoding='file')
        client2 = cu.get_client_newcred(creds)
        sent = _spy_etypes(client2)
        tgs, encpart, key = await client2.get_TGS(KerberosSPN.from_spn(SPN))
        assert sent == [EXPECTED_TGS_ETYPES]
        assert key.enctype == AES256


# --------------------------------------------------------------------------
# U2U: the request offers AES-first and the round trip succeeds. (The KDC
# still gets the final say on the returned session-key etype.)
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_u2u_offers_aes_and_succeeds_async():
    client = KerberosClientFactory.from_url(_pw_url()).get_client()
    await client.get_TGT()
    sent = _spy_etypes(client)
    tgs, encTGSRepPart, key, decticket = await client.U2U()
    assert sent == [EXPECTED_TGS_ETYPES]
    assert tgs is not None
    assert key is not None


def test_u2u_offers_aes_and_succeeds_sync():
    client = KerberosClientFactory.from_url(_pw_url()).get_client_blocking()
    client.get_TGT()
    sent = _spy_etypes(client)
    tgs, encTGSRepPart, key, decticket = client.U2U()
    assert sent == [EXPECTED_TGS_ETYPES]
    assert tgs is not None
    assert key is not None
