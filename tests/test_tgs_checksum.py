import asyncio

import pytest
from minikerberos.aioclient import AIOKerberosClient
from minikerberos.client import KerbrosClient
from minikerberos.common.creds import KerberosCredential
from minikerberos.common.spn import KerberosSPN
from minikerberos.common.target import KerberosTarget
from minikerberos.protocol.asn1_structs import AP_REQ, Authenticator, TGS_REQ
from minikerberos.protocol.encryption import (
    InvalidChecksum, Key, _enctype_table, string_to_key, verify_checksum,
)


def verify(enctype, key_bytes, usage, body, checksum_type, checksum):
    # Uses the library crypto profiles, not an independent implementation.
    try:
        verify_checksum(checksum_type, Key(enctype, key_bytes), usage, body, checksum)
    except InvalidChecksum:
        return False
    return True


class Captured(Exception):
    pass


class Capture:
    def __init__(self):
        self.requests = []

    def sendrecv(self, data, *args, **kwargs):
        self.requests.append(data)
        raise Captured()


class AsyncCapture(Capture):
    async def sendrecv(self, data, *args, **kwargs):
        return super().sendrecv(data, *args, **kwargs)


def seed_client(client, enctype=18, salt=b'ATHENA.MIT.EDUraeburn'):
    key = string_to_key(enctype, 'password', salt)
    client.kerberos_session_key = key
    client.kerberos_cipher_type = enctype
    client.kerberos_cipher = _enctype_table[enctype]
    client.kerberos_TGT = {
        'crealm': 'ZSB.TEST',
        'cname': {'name-type': 1, 'name-string': ['user']},
        'ticket': {
            'tkt-vno': 5, 'realm': 'ZSB.TEST',
            'sname': {'name-type': 2, 'name-string': ['krbtgt', 'ZSB.TEST']},
            'enc-part': {'etype': enctype, 'cipher': b'opaque-ticket'},
        },
    }
    return key


def unpack(data, key):
    request = TGS_REQ.load(data)
    padata = [p for p in request['padata'] if p['padata-type'].native == 1]
    assert len(padata) == 1
    ap = AP_REQ.load(padata[0]['padata-value'].native)
    assert ap['authenticator']['etype'].native == key.enctype
    plain = _enctype_table[key.enctype].decrypt(
        key, 7, ap['authenticator']['cipher'].native,
    )
    return request, Authenticator.load(plain)


def assert_wire(data, key, expected_type):
    request, auth = unpack(data, key)
    check = auth['cksum'].native
    assert check is not None
    assert check['cksumtype'] == expected_type
    body = request['req-body'].untag().dump()
    args = (key.enctype, key.contents, 6, body, expected_type, check['checksum'])
    assert verify(*args)
    assert not verify(key.enctype, key.contents, 7, body, expected_type, check['checksum'])
    changed_key = bytes([key.contents[0] ^ 0x80]) + key.contents[1:]
    assert not verify(key.enctype, changed_key, 6, body, expected_type, check['checksum'])
    assert not verify(key.enctype, key.contents, 6, request['req-body'].dump(),
                      expected_type, check['checksum'])
    for field, replacement in [('nonce', request['req-body']['nonce'].native ^ 1),
                               ('sname', {'name-type': 2, 'name-string': ['cifs', 'other']})]:
        changed = TGS_REQ.load(data)
        changed['req-body'][field] = replacement
        assert not verify(key.enctype, key.contents, 6, changed['req-body'].untag().dump(),
                          expected_type, check['checksum'])
    return request, auth


@pytest.mark.parametrize('enctype,checksum_type', [(17, 15), (18, 16), (23, -138), (16, 12)])
@pytest.mark.parametrize('is_linux', [False, True])
@pytest.mark.parametrize('is_async', [False, True])
@pytest.mark.parametrize('override', [None, [17, 23]])
def test_sent_tgs_checksum(enctype, checksum_type, is_linux, is_async, override):
    credential = KerberosCredential()
    credential.username = 'user'
    credential.domain = 'ZSB.TEST'
    client = (AIOKerberosClient if is_async else KerbrosClient)(
        credential, KerberosTarget('127.0.0.1'),
    )
    key = seed_client(client, enctype)
    capture = AsyncCapture() if is_async else Capture()
    client.ksoc = capture
    spn = KerberosSPN.from_spn('cifs/ipa.zsb.test@ZSB.TEST')
    with pytest.raises(Captured):
        if is_async:
            asyncio.run(client.get_TGS(spn, override_etype=override, is_linux=is_linux))
        else:
            client.get_TGS(spn, override_etype=override, is_linux=is_linux)
    assert len(capture.requests) == 1
    request, auth = assert_wire(capture.requests[0], key, checksum_type)
    expected = override or ([enctype, 23] if is_async else [enctype])
    assert request['req-body']['etype'].native == expected
    assert auth['seq-number'].native == (0 if is_linux else None)


@pytest.mark.parametrize('enctype,expected', [
    (17, '42263c6e89f4fc28b8df68ee09799f15'),
    (18, 'fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161'),
])
def test_rfc3962_appendix_b_string_to_key(enctype, expected):
    key = string_to_key(enctype, 'password', b'ATHENA.MIT.EDUraeburn', b'\x00\x00\x00\x01')
    assert key.contents.hex() == expected


@pytest.mark.parametrize('enctype,expected', [
    (23, '8846f7eaee8fb117ad06bdd830b7586c'),
    (16, '850bb51358548cd05e86768c313e3bfef7511937dcf72c3e'),
])
def test_legacy_string_to_key_vectors(enctype, expected):
    assert string_to_key(enctype, 'password', b'ATHENA.MIT.EDUraeburn').contents.hex() == expected


@pytest.mark.parametrize('is_async', [False, True])
@pytest.mark.parametrize('enctype,size', [(3, 8), (-128, 16)])
def test_unsupported_enctype_rejected_before_transport(is_async, enctype, size):
    credential = KerberosCredential()
    client = (AIOKerberosClient if is_async else KerbrosClient)(
        credential, KerberosTarget('127.0.0.1'),
    )
    seed_client(client)
    client.kerberos_session_key = Key(enctype, b'\x01' * size)
    capture = AsyncCapture() if is_async else Capture()
    client.ksoc = capture
    spn = KerberosSPN.from_spn('cifs/ipa.zsb.test@ZSB.TEST')
    with pytest.raises(ValueError, match='Unsupported TGS session key'):
        if is_async:
            asyncio.run(client.get_TGS(spn))
        else:
            client.get_TGS(spn)
    assert not capture.requests


@pytest.mark.parametrize('is_async', [False, True])
def test_service_cache_bypasses_network(is_async):
    client = (AIOKerberosClient if is_async else KerbrosClient)(
        KerberosCredential(), KerberosTarget('127.0.0.1'),
    )
    sentinel = ({'cached': True}, {}, object())
    client.tgs_from_ccache = lambda spn: (*sentinel, None)
    capture = AsyncCapture() if is_async else Capture()
    client.ksoc = capture
    spn = KerberosSPN.from_spn('cifs/ipa.zsb.test@ZSB.TEST')
    result = asyncio.run(client.get_TGS(spn)) if is_async else client.get_TGS(spn)
    assert result == sentinel
    assert not capture.requests


def test_async_custom_flags_preserved():
    client = AIOKerberosClient(KerberosCredential(), KerberosTarget('127.0.0.1'))
    key = seed_client(client)
    capture = AsyncCapture()
    client.ksoc = capture
    spn = KerberosSPN.from_spn('cifs/ipa.zsb.test@ZSB.TEST')
    with pytest.raises(Captured):
        asyncio.run(client.get_TGS(spn, flags=['canonicalize']))
    request, _ = assert_wire(capture.requests[0], key, 16)
    assert request['req-body']['kdc-options'].native == {'canonicalize'}
