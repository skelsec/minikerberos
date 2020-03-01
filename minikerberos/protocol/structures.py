import io
import enum

#https://tools.ietf.org/html/rfc4121#section-4.1.1.1
class ChecksumFlags(enum.IntFlag):
	GSS_C_DELEG_FLAG = 1
	GSS_C_MUTUAL_FLAG = 2
	GSS_C_REPLAY_FLAG = 4
	GSS_C_SEQUENCE_FLAG = 8
	GSS_C_CONF_FLAG = 16
	GSS_C_INTEG_FLAG = 32
	GSS_C_DCE_STYLE = 0x1000
		  
#https://tools.ietf.org/html/rfc4121#section-4.1.1
class AuthenticatorChecksum:
	def __init__(self):
		self.length_of_binding = None
		self.channel_binding = None #MD5 hash of gss_channel_bindings_struct
		self.flags = None #ChecksumFlags
		self.delegation = None
		self.delegation_length = None
		self.delegation_data = None
		self.extensions = None
		
	@staticmethod
	def from_bytes(data):
		AuthenticatorChecksum.from_buffer(io.BytesIO(data))
		
	@staticmethod
	def from_buffer(buffer):
		ac = AuthenticatorChecksum()
		ac.length_of_binding = int.from_bytes(buffer.read(4), byteorder = 'little', signed = False)
		ac.channel_binding = buffer.read(ac.length_of_binding) #according to the latest RFC this is 16 bytes long always
		ac.flags = ChecksumFlags(int.from_bytes(buffer.read(4), byteorder = 'little', signed = False))
		if ac.flags & ChecksumFlags.GSS_C_DELEG_FLAG:
			ac.delegation = bool(int.from_bytes(buffer.read(1), byteorder = 'little', signed = False))
			ac.delegation_length = int.from_bytes(2, byteorder = 'little', signed = False)
			ac.delegation_data = int.from_bytes(ac.delegation_length, byteorder = 'little', signed = False)
		ac.extensions = buffer.read()
		return ac
		
		
	def to_bytes(self):
		t = len(self.channel_binding).to_bytes(4, byteorder = 'little', signed = False)
		t += self.channel_binding
		t += self.flags.to_bytes(4, byteorder = 'little', signed = False)
		if self.flags & ChecksumFlags.GSS_C_DELEG_FLAG:
			t += int(self.delegation).to_bytes(1, byteorder = 'little', signed = False)
			t += len(self.delegation_data.to_bytes()).to_bytes(2, byteorder = 'little', signed = False)
			t += self.delegation_data.to_bytes()
		if self.extensions:
			t += self.extensions.to_bytes()
		return t