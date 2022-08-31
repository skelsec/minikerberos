
from minikerberos.protocol.external.ndr import NDRSTRUCT
from minikerberos.protocol.external.dtypes import UCHAR,USHORT, ULONG

# 2.2.6 Type Serialization Version 1
class CommonHeader(NDRSTRUCT):
    structure = (
        ('Version', UCHAR),
        ('Endianness', UCHAR),
        ('CommonHeaderLength', USHORT),
        ('Filler', ULONG),
    )
    def __init__(self, data = None,isNDR64 = False):
        NDRSTRUCT.__init__(self, data, isNDR64)
        if data is None:
            self['Version'] = 1
            self['Endianness'] = 0x10
            self['CommonHeaderLength'] = 8
            self['Filler'] = 0xcccccccc

class PrivateHeader(NDRSTRUCT):
    structure = (
        ('ObjectBufferLength', ULONG),
        ('Filler', ULONG),
    )
    def __init__(self, data = None,isNDR64 = False):
        NDRSTRUCT.__init__(self, data, isNDR64)
        if data is None:
            self['Filler'] = 0xcccccccc

class TypeSerialization1(NDRSTRUCT):
    commonHdr = (
        ('CommonHeader', CommonHeader),
        ('PrivateHeader', PrivateHeader),
    )
    def getData(self, soFar = 0):
        self['PrivateHeader']['ObjectBufferLength'] = len(NDRSTRUCT.getData(self, soFar)) + len(
            NDRSTRUCT.getDataReferents(self, soFar)) - len(self['CommonHeader']) - len(self['PrivateHeader'])
        return NDRSTRUCT.getData(self, soFar)