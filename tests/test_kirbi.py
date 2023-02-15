# Description: Tests for the kirbi module

import tempfile
import pathlib
from minikerberos.common.kirbi import Kirbi
from .config import *


def test_load_kirbi():
    for kirbifile in get_testfiles_kirbi():
        kirbi = Kirbi.from_file(kirbifile)
        desc = str(kirbi)
        with tempfile.NamedTemporaryFile() as f:
            kirbi.to_file(f.name)
            kirbi2 = Kirbi.from_file(f.name)
            desc2 = str(kirbi2)
            assert desc == desc2

def test_kirbi_b64():
    for kirbifile in get_testfiles_kirbi():
        kirbi = Kirbi.from_file(kirbifile)
        desc1 = str(kirbi)
        kirbi_b64 = kirbi.to_b64()
        kirbi2 = Kirbi.from_b64(kirbi_b64)
        desc2 = str(kirbi2)
        assert desc1 == desc2

def test_kirbi_hex():
    for kirbifile in get_testfiles_kirbi():
        kirbi = Kirbi.from_file(kirbifile)
        desc1 = str(kirbi)
        kirbi_hex = kirbi.to_hex()
        kirbi2 = Kirbi.from_hex(kirbi_hex)
        desc2 = str(kirbi2)
        assert desc1 == desc2

def test_kirbi_bytes():
    for kirbifile in get_testfiles_kirbi():
        kirbi = Kirbi.from_file(kirbifile)
        desc1 = str(kirbi)
        kirbi_bytes = kirbi.to_bytes()
        kirbi2 = Kirbi.from_bytes(kirbi_bytes)
        desc2 = str(kirbi2)
        assert desc1 == desc2
