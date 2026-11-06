"""
Integration tests for get_TGS against non-Windows KDCs (MIT + Heimdal).

These require live KDCs and are skipped unless the corresponding ports are
provided via environment variables and reachable:

    MINIKERBEROS_MIT_PORT       TCP port of an MIT.TEST KDC on 127.0.0.1
    MINIKERBEROS_HEIMDAL_PORT   TCP port of a HEIMDAL.TEST KDC on 127.0.0.1

The CI workflow (.github/workflows/tests.yml) builds the KDC images under
tests/ci/ and sets these variables. Locally you can do the same, e.g.:

    docker build -t mk-mit tests/ci/mit
    docker run -d -p 127.0.0.1:18801:88 mk-mit
    MINIKERBEROS_MIT_PORT=18801 pytest tests/test_kdc_integration.py
"""
import os
import socket
import asyncio

import pytest

from minikerberos.common.factory import KerberosClientFactory
from minikerberos.common.spn import KerberosSPN
from minikerberos.protocol.errors import KerberosError, KerberosErrorCode


def _skip_if_etype_unsupported(exc, etype):
    # A KDC may refuse deprecated enctypes (DES3/RC4 are disabled by default on
    # newer MIT/Heimdal builds). That is a property of the KDC, not the client,
    # so treat it as "not applicable here" rather than a failure.
    if isinstance(exc, KerberosError) and exc.errorcode == KerberosErrorCode.KDC_ERR_ETYPE_NOSUPP:
        pytest.skip('KDC does not support etype %d' % etype)
    raise exc


def _reachable(port):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=3):
            return True
    except OSError:
        return False


KDCS = {}
_mit = int(os.environ.get('MINIKERBEROS_MIT_PORT', '0') or '0')
_heimdal = int(os.environ.get('MINIKERBEROS_HEIMDAL_PORT', '0') or '0')
if _mit and _reachable(_mit):
    KDCS['MIT'] = ('MIT.TEST', _mit, 'host/svc.mit.test@MIT.TEST')
if _heimdal and _reachable(_heimdal):
    KDCS['Heimdal'] = ('HEIMDAL.TEST', _heimdal, 'host/svc.heimdal.test@HEIMDAL.TEST')

# AES256, AES128, DES3, RC4 session keys.
ETYPES = [18, 17, 16, 23]

pytestmark = pytest.mark.skipif(
    not KDCS,
    reason='No MIT/Heimdal KDC reachable; set MINIKERBEROS_MIT_PORT / MINIKERBEROS_HEIMDAL_PORT',
)

_PARAMS = [(kdc, et) for kdc in KDCS for et in ETYPES]
_IDS = ['%s-etype%d' % (kdc, et) for kdc, et in _PARAMS]


def _url(realm, port, etype):
    return 'kerberos+password://%s\\victim:Passw0rd!1@127.0.0.1:%d/?etype=%d' % (realm, port, etype)


@pytest.mark.parametrize('kdc,etype', _PARAMS, ids=_IDS)
def test_get_tgs_sync(kdc, etype):
    realm, port, spn = KDCS[kdc]
    client = KerberosClientFactory.from_url(_url(realm, port, etype)).get_client_blocking()
    try:
        client.get_TGT()
    except KerberosError as e:
        _skip_if_etype_unsupported(e, etype)
    assert client.kerberos_session_key.enctype == etype
    tgs, encpart, key = client.get_TGS(KerberosSPN.from_spn(spn))
    assert tgs is not None
    assert encpart is not None
    assert key is not None


@pytest.mark.parametrize('kdc,etype', _PARAMS, ids=_IDS)
def test_get_tgs_async(kdc, etype):
    realm, port, spn = KDCS[kdc]

    async def run():
        client = KerberosClientFactory.from_url(_url(realm, port, etype)).get_client()
        try:
            await client.get_TGT()
        except KerberosError as e:
            _skip_if_etype_unsupported(e, etype)
        assert client.kerberos_session_key.enctype == etype
        return await client.get_TGS(KerberosSPN.from_spn(spn))

    tgs, encpart, key = asyncio.run(run())
    assert tgs is not None
    assert encpart is not None
    assert key is not None
