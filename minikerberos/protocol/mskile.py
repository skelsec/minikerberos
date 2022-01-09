import os
import io

from asn1crypto import core
from minikerberos.protocol.asn1_structs import EncryptionKey, Checksum, KerberosTime, Realm

TAG = 'explicit'

# class
UNIVERSAL = 0
APPLICATION = 1
CONTEXT = 2


########
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/1aeca7fb-d6b4-4402-8fa4-6ec3e955c16e
class KERB_AD_RESTRICTION_ENTRY(core.Sequence):
    _fields = [
        ('restriction-type', core.Integer, {'tag_type': TAG, 'tag': 0}),
        ('restriction', core.OctetString, {'tag_type': TAG, 'tag': 1}),
    ]
    
class KERB_AD_RESTRICTION_ENTRYS(core.SequenceOf):
    _child_spec = KERB_AD_RESTRICTION_ENTRY


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/25fabd02-560d-4c1f-8f42-b32e9d97996a
class KERB_ERROR_DATA(core.Sequence):
    _fields = [
        ('data-type', core.Integer, {'tag_type': TAG, 'tag': 1}),
        ('data-value', core.OctetString, {'tag_type': TAG, 'tag': 2, 'optional': True}),
    ]

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/765795ba-9e05-4220-9bd3-b34464e413a7
class KERB_PA_PAC_REQUEST(core.Sequence):
    _fields = [
        ('include-pac', core.Boolean, {'tag_type': TAG, 'tag': 0}),
    ]


## implementation specific??????
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/2a01b297-c47f-4547-9268-cf589aedd063
#class KERB_LOCAL(core.Sequence):
#    _fields = [
#    ]


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/ec551137-c5e5-476a-9c89-e0029473c41b
class LSAP_TOKEN_INFO_INTEGRITY:
	def __init__(self, machine_id = os.urandom(32)):
		self.Flags = None # unsigned long
		self.TokenIL = None # unsigned long
		self.MachineID = machine_id # KILE implements a 32-byte binary random string machine ID.

	def to_bytes(self):
		t = self.Flags.to_bytes(4, byteorder='little', signed = False)
		t += self.TokenIL.to_bytes(4, byteorder='little', signed = False)
		t += self.MachineID
		return t
	
	@staticmethod
	def from_bytes(data):
		return LSAP_TOKEN_INFO_INTEGRITY.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		msg = LSAP_TOKEN_INFO_INTEGRITY()
		msg.Flags = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.TokenIL = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		msg.MachineID = buff.read(32)
		return msg


class KERB_KEY_LIST_REP(core.SequenceOf):
	_child_spec = EncryptionKey

class KERB_KEY_LIST_REQ(core.SequenceOf):
	_child_spec = core.Integer



#### TODO
"""
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/15fa77fb-deaa-487d-b685-1310afe45ca1
 typedef struct KERB_EXT_ERROR {
     unsigned long status;
     unsigned long reserved;
     unsigned long flags;
 } KERB_EXT_ERROR;

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/25fabd02-560d-4c1f-8f42-b32e9d97996a



"""