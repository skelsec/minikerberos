from unicrypto import hashlib

import unittest

from minikerberos.common import KerberosCredential
from minikerberos.communication import KerberosSocket, KerberosComm
from minikerberos.encryption import string_to_key, Enctype


class TestKerberosLogin(unittest.TestCase):
    """
    These tests are checking if the getTGT function works correctly.
    TODO: check override_enctype param
    """
    def setUp(self):
        self.username = 'victim'
        self.domain = 'TEST.corp'
        self.password = 'Almaalmaalma!1'
        self.target_ip = '192.168.9.1'
        self.target_user = None
        self.target_service = None

        self.kerberos_socet = KerberosSocket(self.target_ip)

    def test_plaintext(self):
        cred = KerberosCredential()
        cred.username = self.username
        cred.password = self.password
        cred.domain = self.domain
        kcomm = KerberosComm(cred, self.kerberos_socet)
        kcomm.get_TGT()

    def test_aes128(self):
        cred = KerberosCredential()
        cred.username = self.username
        salt = (self.domain.upper() + self.username).encode()
        cred.kerberos_key_aes_128 = string_to_key(
            Enctype.AES128, self.password.encode(), salt).contents.hex()
        cred.domain = self.domain
        kcomm = KerberosComm(cred, self.kerberos_socet)
        kcomm.get_TGT()

    def test_aes256(self):
        cred = KerberosCredential()
        cred.username = self.username
        salt = (self.domain.upper() + self.username).encode()
        cred.kerberos_key_aes_256 = string_to_key(
            Enctype.AES256, self.password.encode(), salt).contents.hex()
        cred.domain = self.domain
        kcomm = KerberosComm(cred, self.kerberos_socet)
        kcomm.get_TGT()

    def test_rc4(self):
        cred = KerberosCredential()
        cred.username = self.username
        salt = (self.domain.upper() + self.username).encode()
        cred.kerberos_key_rc4 = hashlib.new(
            'md4', self.password.encode('utf-16-le')).hexdigest()
        cred.domain = self.domain
        kcomm = KerberosComm(cred, self.kerberos_socet)
        kcomm.get_TGT()

    def test_des(self):
        cred = KerberosCredential()
        cred.username = self.username
        salt = (self.domain.upper() + self.username).encode()
        cred.kerberos_key_des = string_to_key(
            Enctype.DES_MD5, self.password.encode(), salt).contents.hex()
        cred.domain = self.domain
        kcomm = KerberosComm(cred, self.kerberos_socet)
        kcomm.get_TGT()    


if __name__ == '__main__':
    unittest.main()
