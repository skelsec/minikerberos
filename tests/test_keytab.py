# Description: Tests for the keytab module

import tempfile
import pathlib
from minikerberos.common.keytab import Keytab, KeytabPrincipal, KeytabOctetString
from .config import *


def test_keytab_load():
    for keytabfile in get_testfiles_keytab():
        keytab = Keytab.from_file(keytabfile)
        desc = str(keytab)
        with tempfile.NamedTemporaryFile() as f:
            keytab.to_file(f.name)
            keytab2 = Keytab.from_file(f.name)
            desc2 = str(keytab2)
            assert desc == desc2

def test_keytab_load_bytes():
    for keytabfile in get_testfiles_keytab():
        with open(keytabfile, 'rb') as f:
            keytab_bytes = f.read()
            keytab = Keytab.from_bytes(keytab_bytes)
        desc = str(keytab)
        keytab_bytes = keytab.to_bytes()
        keytab2 = Keytab.from_bytes(keytab_bytes)
        desc2 = str(keytab2)
        assert desc == desc2

def test_principal():
    kp = KeytabPrincipal.empty()
    x, realm = kp.to_asn1()
    kp2 = KeytabPrincipal.from_asn1(x, realm)
    assert kp.to_bytes() == kp2.to_bytes()

def test_octetstring():
    kp = KeytabOctetString.empty()
    x = kp.to_asn1()
    kp2 = KeytabOctetString.from_asn1(x)
    assert kp.to_bytes() == kp2.to_bytes()

def test_octetstring2():
    kp = KeytabOctetString.from_string('1234567890')
    x = kp.to_string()
    kp2 = KeytabOctetString.from_string(x)
    assert kp.to_bytes() == kp2.to_bytes()

def test_tostring():
    for keytabfile in get_testfiles_keytab():
        keytab = Keytab.from_file(keytabfile)
        print(str(keytab))
        desc = str(keytab)
        assert desc

if __name__ == '__main__':
    test_tostring()