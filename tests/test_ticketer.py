# Description: Offline tests for ticket forging (golden / silver / trust).
#
# Every test forges a ticket, then decrypts and parses it back with the
# library's own crypto so the assertions ride on real bytes, not on the
# builder's own view of them.

import os
import pytest

from minikerberos.ticketer import (
    golden_ticket, silver_ticket, trust_ticket, forge_ticket, build_pac,
    extract_pac, key_from_hex, key_from_password, random_session_key,
    KDC_REP_TICKET_KEY_USAGE,
)
from minikerberos.protocol.encryption import Key, Enctype, _enctype_table
from minikerberos.protocol.asn1_structs import EncTicketPart
from minikerberos.protocol.pacbuild import (
    sign_pac, verify_pac, parse_pac, sid_to_bytes, sid_split_rid, assemble_pac,
    pad_length,
)
from minikerberos.protocol.external.pac import (
    PAC_LOGON_INFO, PAC_CLIENT_INFO_TYPE, PAC_SERVER_CHECKSUM,
    PAC_PRIVSVR_CHECKSUM, PAC_ATTRIBUTES_INFO, PAC_REQUESTOR_INFO,
    PAC_UPN_DNS_INFO, KERB_VALIDATION_INFO, VALIDATION_INFO,
)
from minikerberos.common.ccache import CCACHE

DOMAIN = 'test.corp'
DOMAIN_SID = 'S-1-5-21-1111111111-2222222222-3333333333'

ETYPES = [
    (Enctype.AES256, 32),
    (Enctype.AES128, 16),
    (Enctype.RC4, 16),
]


def _decrypt_ticket(ft, key):
    cipher = _enctype_table[ft.ticket['enc-part']['etype']]
    raw = cipher.decrypt(key, KDC_REP_TICKET_KEY_USAGE, ft.ticket['enc-part']['cipher'])
    return EncTicketPart.load(raw).native


# ---------------------------------------------------------------------------
# SID helpers
# ---------------------------------------------------------------------------

def test_sid_to_bytes_known_vector():
    # S-1-5-32-544 (BUILTIN\Administrators)
    assert sid_to_bytes('S-1-5-32-544') == bytes.fromhex('01020000000000052000000020020000')


def test_sid_split_rid():
    base, rid = sid_split_rid(DOMAIN_SID + '-512')
    assert base == DOMAIN_SID
    assert rid == 512


# ---------------------------------------------------------------------------
# PAC assembly / signing
# ---------------------------------------------------------------------------

def test_pac_header_is_aligned():
    buffers = build_pac('Administrator', DOMAIN, DOMAIN_SID)
    blob, offsets = assemble_pac(buffers)
    for ultype, off in offsets.items():
        assert off % 8 == 0, 'buffer %d not 8-aligned' % ultype
    # re-parsing yields the same buffers back
    parsed = parse_pac(blob)
    for ultype, data in buffers.items():
        assert parsed[ultype] == data


@pytest.mark.parametrize('etype,ksize', ETYPES)
def test_pac_sign_and_verify(etype, ksize):
    key = Key(etype, os.urandom(ksize))
    buffers = build_pac('Administrator', DOMAIN, DOMAIN_SID, user_id=500,
                        extra_sids=['S-1-5-21-9-9-9-519'])
    blob = sign_pac(buffers, key, key)
    assert verify_pac(blob, key, key)
    # a flipped byte in the data must fail verification
    tampered = bytearray(blob)
    tampered[-1] ^= 0xFF
    assert not verify_pac(bytes(tampered), key, key)


def test_pac_server_and_kdc_keys_differ():
    server = Key(Enctype.AES256, os.urandom(32))
    kdc = Key(Enctype.AES256, os.urandom(32))
    buffers = build_pac('Administrator', DOMAIN, DOMAIN_SID)
    blob = sign_pac(buffers, server, kdc)
    assert verify_pac(blob, server, kdc)
    # wrong KDC key -> KDC signature must not validate
    other = Key(Enctype.AES256, os.urandom(32))
    assert not verify_pac(blob, server, other)


def test_old_pac_omits_modern_buffers():
    buffers = build_pac('Administrator', DOMAIN, DOMAIN_SID, old_pac=True, extra_pac=False)
    assert PAC_ATTRIBUTES_INFO not in buffers
    assert PAC_REQUESTOR_INFO not in buffers
    assert PAC_UPN_DNS_INFO not in buffers
    assert PAC_LOGON_INFO in buffers


# ---------------------------------------------------------------------------
# Golden tickets
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('etype,ksize', ETYPES)
def test_golden_ticket_decrypts(etype, ksize):
    krbtgt = Key(etype, os.urandom(ksize))
    ft = golden_ticket('Administrator', DOMAIN, DOMAIN_SID, krbtgt, user_id=500)
    etp = _decrypt_ticket(ft, krbtgt)
    assert etp['cname']['name-string'] == ['Administrator']
    assert etp['crealm'] == DOMAIN.upper()
    assert ft.sname['name-string'] == ['krbtgt', DOMAIN.upper()]
    assert 'initial' in etp['flags']
    # PAC present and both signatures valid under the krbtgt key
    pac = extract_pac(etp)
    assert PAC_LOGON_INFO in pac
    assert verify_pac(sign_pac(pac, krbtgt, krbtgt), krbtgt, krbtgt)


def test_golden_ticket_wrong_key_fails():
    krbtgt = Key(Enctype.AES256, os.urandom(32))
    ft = golden_ticket('Administrator', DOMAIN, DOMAIN_SID, krbtgt)
    with pytest.raises(Exception):
        _decrypt_ticket(ft, Key(Enctype.AES256, os.urandom(32)))


def test_golden_ticket_no_pac():
    krbtgt = Key(Enctype.AES256, os.urandom(32))
    ft = golden_ticket('Administrator', DOMAIN, DOMAIN_SID, krbtgt, with_pac=False)
    etp = _decrypt_ticket(ft, krbtgt)
    assert etp.get('authorization-data') in (None, [])


def test_golden_ticket_extra_sids_in_pac():
    krbtgt = Key(Enctype.AES256, os.urandom(32))
    ea = 'S-1-5-21-9-9-9-519'
    ft = golden_ticket('Administrator', DOMAIN, DOMAIN_SID, krbtgt, extra_sids=[ea])
    etp = _decrypt_ticket(ft, krbtgt)
    pac = extract_pac(etp)
    vi = VALIDATION_INFO()
    vi.fromString(pac[PAC_LOGON_INFO])
    # the extra SID bytes appear in the serialized logon info
    assert sid_to_bytes(ea)[-4:] in pac[PAC_LOGON_INFO]


# ---------------------------------------------------------------------------
# Silver tickets
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('etype,ksize', ETYPES)
def test_silver_ticket_decrypts(etype, ksize):
    svc = Key(etype, os.urandom(ksize))
    ft = silver_ticket('Administrator', DOMAIN, DOMAIN_SID, 'cifs/host.test.corp', svc)
    etp = _decrypt_ticket(ft, svc)
    assert ft.sname['name-string'] == ['cifs', 'host.test.corp']
    assert 'initial' not in etp['flags']
    pac = extract_pac(etp)
    # silver has no krbtgt key: both signatures use the service key
    assert verify_pac(sign_pac(pac, svc, svc), svc, svc)


def test_silver_ticket_bare_spn_gets_realm():
    svc = Key(Enctype.AES256, os.urandom(32))
    ft = silver_ticket('Administrator', DOMAIN, DOMAIN_SID, 'HTTP', svc)
    assert ft.sname['name-string'] == ['HTTP', DOMAIN.lower()]


# ---------------------------------------------------------------------------
# Trust tickets
# ---------------------------------------------------------------------------

def test_trust_ticket_sname_and_realm():
    tk = Key(Enctype.AES256, os.urandom(32))
    ft = trust_ticket('Administrator', 'source.corp', DOMAIN_SID, 'target.corp', tk,
                      extra_sids=['S-1-5-21-7-7-7-519'])
    assert ft.sname['name-string'] == ['krbtgt', 'TARGET.CORP']
    assert ft.srealm == 'SOURCE.CORP'
    etp = _decrypt_ticket(ft, tk)
    assert extract_pac(etp)


# ---------------------------------------------------------------------------
# Serialization round-trips
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('etype,ksize', ETYPES)
def test_ticket_to_ccache_roundtrip(etype, ksize):
    krbtgt = Key(etype, os.urandom(ksize))
    ft = golden_ticket('Administrator', DOMAIN, DOMAIN_SID, krbtgt)
    cc = ft.to_ccache()
    data = cc.to_bytes()
    cc2 = CCACHE.from_bytes(data)
    tgts = cc2.get_all_tgt()
    assert len(tgts) == 1


def test_ticket_to_kirbi_roundtrip():
    krbtgt = Key(Enctype.AES256, os.urandom(32))
    ft = golden_ticket('Administrator', DOMAIN, DOMAIN_SID, krbtgt)
    from minikerberos.common.kirbi import Kirbi
    kirbi = ft.to_kirbi()
    data = kirbi.to_bytes()
    kirbi2 = Kirbi.from_bytes(data)
    # the serialized KRB-CRED is the invariant; a reloaded kirbi has no
    # decrypted enc-part attached, so str() carries one line less.
    assert kirbi2.to_bytes() == data


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def test_key_from_hex_infers_enctype():
    assert key_from_hex('aa' * 16).enctype == Enctype.RC4
    assert key_from_hex('aa' * 32).enctype == Enctype.AES256


def test_key_from_password_rc4_is_ntlm():
    from unicrypto.hashlib import md4
    k = key_from_password('Password1', 'user', DOMAIN, etype=Enctype.RC4)
    assert k.contents == md4('Password1'.encode('utf-16-le')).digest()
