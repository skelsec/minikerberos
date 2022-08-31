from minikerberos.protocol.external.ndr import NDRSTRUCT, NDRUniConformantArray, NDRPOINTER, NDRUniFixedArray
from minikerberos.protocol.external.dtypes import RPC_UNICODE_STRING, ULONG


# 2.2.1.2.2 NL_SITE_NAME_ARRAY
class RPC_UNICODE_STRING_ARRAY(NDRUniConformantArray):
    item = RPC_UNICODE_STRING

class PRPC_UNICODE_STRING_ARRAY(NDRPOINTER):
    referent = (
        ('Data', RPC_UNICODE_STRING_ARRAY),
    )

class UCHAR_ARRAY(NDRUniConformantArray):
    item = 'c'

class PUCHAR_ARRAY(NDRPOINTER):
    referent = (
        ('Data', UCHAR_ARRAY),
    )

class PRPC_UNICODE_STRING_ARRAY(NDRPOINTER):
    referent = (
        ('Data', RPC_UNICODE_STRING_ARRAY),
    )


class PUCHAR_ARRAY(NDRPOINTER):
    referent = (
        ('Data', UCHAR_ARRAY),
    )


# 2.2.1.1.1 CYPHER_BLOCK
class CYPHER_BLOCK(NDRSTRUCT):
    structure = (
        ('Data', '8s=b""'),
    )
    def getAlignment(self):
        return 1
        


# 2.2.1.1.3 LM_OWF_PASSWORD
class CYPHER_BLOCK_ARRAY(NDRUniFixedArray):
    def getDataLen(self, data, offset=0):
        return len(CYPHER_BLOCK())*2

class LM_OWF_PASSWORD(NDRSTRUCT):
    structure = (
        ('Data', CYPHER_BLOCK_ARRAY),
    )

# 2.2.1.1.4 NT_OWF_PASSWORD
NT_OWF_PASSWORD = LM_OWF_PASSWORD
ENCRYPTED_NT_OWF_PASSWORD = NT_OWF_PASSWORD


# 2.2.1.4.1 LM_CHALLENGE
class CHAR_FIXED_8_ARRAY(NDRUniFixedArray):
    def getDataLen(self, data, offset=0):
        return 8

# 2.2.1.4.9 USER_SESSION_KEY
USER_SESSION_KEY = LM_OWF_PASSWORD

# 2.2.1.4.10 GROUP_MEMBERSHIP
class GROUP_MEMBERSHIP(NDRSTRUCT):
    structure = (
        ('RelativeId', ULONG),
        ('Attributes', ULONG),
    )

class GROUP_MEMBERSHIP_ARRAY(NDRUniConformantArray):
    item = GROUP_MEMBERSHIP

class PGROUP_MEMBERSHIP_ARRAY(NDRPOINTER):
    referent = (
        ('Data', GROUP_MEMBERSHIP_ARRAY),
    )