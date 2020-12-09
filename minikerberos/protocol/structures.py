import io
import enum
import base64

from minikerberos.protocol.asn1_structs import GSSAPIOID, GSSAPIToken

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
		return AuthenticatorChecksum.from_buffer(io.BytesIO(data))
		
	@staticmethod
	def from_buffer(buffer):
		ac = AuthenticatorChecksum()
		ac.length_of_binding = int.from_bytes(buffer.read(4), byteorder = 'little', signed = False)
		ac.channel_binding = buffer.read(ac.length_of_binding) #according to the latest RFC this is 16 bytes long always
		ac.flags = ChecksumFlags(int.from_bytes(buffer.read(4), byteorder = 'little', signed = False))
		if ac.flags & ChecksumFlags.GSS_C_DELEG_FLAG:
			ac.delegation = bool(int.from_bytes(buffer.read(2), byteorder = 'little', signed = False))
			ac.delegation_length = int.from_bytes(buffer.read(2), byteorder = 'little', signed = False)
			ac.delegation_data = buffer.read(ac.delegation_length)
		ac.extensions = buffer.read()
		return ac
		
		
	def to_bytes(self):
		t = len(self.channel_binding).to_bytes(4, byteorder = 'little', signed = False)
		t += self.channel_binding
		t += self.flags.to_bytes(4, byteorder = 'little', signed = False)
		if self.flags & ChecksumFlags.GSS_C_DELEG_FLAG:
			t += int(self.delegation).to_bytes(2, byteorder = 'little', signed = False)
			t += len(self.delegation_data.to_bytes()).to_bytes(2, byteorder = 'little', signed = False)
			t += self.delegation_data.to_bytes()
		if self.extensions:
			t += self.extensions.to_bytes()
		return t


# KRB5Token TOK_ID values.
class KRB5TokenTokID(enum.IntFlag):
	KRB_AP_REQ = 0x0100
	KRB_AP_REP = 0x0200
	KRB_ERROR = 0x0300

	def get_bytes(self):
		return self.value.to_bytes(2, byteorder='big')


# https://tools.ietf.org/html/rfc4121#section-4.1
class KRB5Token:
	def __init__(self, inner_token):
		self.oid = GSSAPIOID('krb5')
		self.inner_token = inner_token

	def get_apreq_token(self, encoding='utf-8'):
		token = self.oid.dump()
		token += KRB5TokenTokID.KRB_AP_REQ.get_bytes()
		token += self.inner_token
		return str(base64.b64encode(GSSAPIToken(contents=token).dump()), encoding)
