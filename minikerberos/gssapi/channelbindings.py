
import enum
import io

# https://www.ietf.org/rfc/rfc2744.txt   3.11. Channel Bindings

class GSS_C_AF(enum.Enum):
	UNSPEC = 0     #Unspecified address type
	LOCAL = 1      #Host-local address type
	INET = 2       #Internet address type (e.g. IP)
	IMPLINK = 3    #ARPAnet IMP address type
	PUP = 4        #pup protocols (eg BSP) address type
	CHAOS = 5      #MIT CHAOS protocol address type
	NS = 6         #XEROX NS address type
	NBS = 7        #nbs address type
	ECMA  = 8      #ECMA address type
	DATAKIT = 9    #datakit protocols address type
	CCITT = 10     #CCITT protocols
	SNA = 11       #IBM SNA address type
	DECnet = 12    #DECnet address type
	DLI = 13       #Direct data link interface address type
	LAT = 14       #LAT address type
	HYLINK = 15    #NSC Hyperchannel address type
	APPLETALK= 16  #AppleTalk address type
	BSC = 17       #BISYNC 2780/3780 address type
	DSS = 18       #Distributed system services address type
	OSI = 19       #OSI TP4 address type
	X25 = 21       #X.25
	NULLADDR = 255 #No address specified

class ChannelBindingsStruct:
	def __init__(self):
		self.initiator_addrtype = None #GSS_C_AF
		self.initiator_address = None #bytes
		self.acceptor_addrtype = None #GSS_C_AF
		self.acceptor_address = None #bytes
		self.application_data = None #bytes

	@staticmethod
	def from_bytes(data):
		return ChannelBindingsStruct.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		# TODO: parse the addresses
		cb = ChannelBindingsStruct()
		t = buff.read(8)
		if t != b'\x00' * 8:
			cb.initiator_addrtype = GSS_C_AF(int.from_bytes(t, byteorder='little', signed = False))
			initiator_address_length = int.from_bytes(buff.read(4), byteorder='little', signed = False)
			cb.initiator_address  = buff.read(initiator_address_length)
		t = buff.read(8)
		if t != b'\x00' * 8:
			cb.acceptor_addrtype  = GSS_C_AF(int.from_bytes(buff.read(4), byteorder='little', signed = False))
			acceptor_address_length = int.from_bytes(buff.read(4), byteorder='little', signed = False)
			cb.acceptor_address   = buff.read(acceptor_address_length)
		t = buff.read(8)
		if t != b'\x00' * 8:
			application_data_length = int.from_bytes(buff.read(4), byteorder='little', signed = False)
			cb.application_data   = buff.read(application_data_length)
		return cb

	def to_bytes(self):
		if self.initiator_address is None:
			t = b'\x00' * 8
		else:
			t = self.initiator_addrtype.value.to_bytes(4, byteorder='little', signed = False)
			t += len(self.initiator_address).to_bytes(4, byteorder='little', signed = False)
			t += self.initiator_address
		if self.acceptor_address is None:
			t += b'\x00' * 8
		else:
			t += self.acceptor_addrtype
			t += len(self.acceptor_address).to_bytes(4, byteorder='little', signed = False)
			t += self.acceptor_address
		if self.application_data is None:
			t += b'\x00' * 8
		else:
			t += len(self.application_data).to_bytes(4, byteorder='little', signed = False)
			t += self.application_data
		return t