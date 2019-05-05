import os
import logging
from minikerberos.common import *
from minikerberos.communication import *
from minikerberos.ccache import CCACHE
from minikerberos.encryption import _enctype_table, Key
import pprint

ccred_krbtgt = KerberosCredential.from_connection_string('DEMO1.FREEIPA.ORG/admin/pass:Secret123@ipa.demo1.freeipa.org')

cipher_data = bytes.fromhex('a4134a8692a021f735418c549daad0ae2f7b309c027f20efebf52e0e0b6d0b269e0ff54c2af22cad5c67de121612e2eef0007d70b5798536a94bf9a4ee87da0de9df15ffc65a9e63eabc96edd4fb9659db8a40cb6fe0ee0336d79bc8f1c8df59287d6d8db1180ca00feb581445f57cf9b22c2cbe83354736ecc230948883db7507f094869dfc98bf2b8331690ed3f9e45760d97db175bfba9232366cb3e5faa38aa5770c5e62aa60c3e829e9c2c9835fa255611310a7364f55e90626714b69d9c03cd5c2ee1fb47590dfa403039803b243149bdfe7c3d9d4859969f7e2e3c96ac89f5cb3a4123ffbf2c35b340afd1ad3e1b32b978901b596901c957ce4894f4939b096051e9d3acf4ef942c5bc7806b39d51d0b08bd4fdd52be0f560af2760914ea814fce7b85a0172')

et = EncryptionType(18)
krbtgt_key = Key(18, ccred_krbtgt.get_key_for_enctype(et, salt = "dc{< 5&c0'85-Y4K".encode()))
krbtgt_cipher = _enctype_table[18]
temp = krbtgt_cipher.decrypt(krbtgt_key, 3, cipher_data)
print(temp.hex())
krbtgt_enc = EncTGSRepPart.load(temp).native
pprint.pprint(krbtgt_enc)

session_key = Key(18, krbtgt_enc['key']['keyvalue'])
session_cipher = _enctype_table[18]

cipherText = bytes.fromhex('351505edf3ecbb9fcf59299f28d23fd514e50b884f729ed43e6abf12451448e1e6db7a6da5dec0a39202eaa69b8be5ef4529e2006021fde7a1239d53904c9e06cdab9ba02fcc6b369d2421cdc21e7ee691c2958e3117159c5f572ba86fdd2208207fd15acd036eb11b18bf3654e344b5322463b6bfca45ee3c6e2f57c560fd8d70450a59e6a9b5499b48953017644f99282979c5220a1f6bc76ef9cdc5153ddd133b2541dee35f7c8e4607dd192eabbf')
temp = session_cipher.decrypt(session_key, 7, cipherText)
print(temp.hex())
auth = Authenticator.load(temp).native
pprint.pprint(auth)