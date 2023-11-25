
import io
import enum

from minikerberos.protocol.asn1_structs import EncKrbPrivPart, KRB_PRIV

class KRB5PasswordPolicyFlags(enum.IntFlag):
	Complex = 0x1
	NoAnonChange = 0x2
	NoClearChange = 0x4
	LockoutAdmins = 0x8
	StoreCleartext = 0x10
	RefusePasswordChange = 0x20

KRB5CHPWResultCode = {
	0 : 'Ok',
	1 : 'Bad request',
	2 : 'Server error',
	3 : 'Client not found',
	4 : 'Rejected',
	5 : 'Access denied',
	6 : 'Protocol version mismatch',
	7 : 'Protocol error',
	0xffff : 'Unknown error'
}
	
class KRB5ChangePassword:
	def __init__(self, ap:bytes, priv:bytes, err:bytes = None):
		self.ap = ap
		self.priv = priv
		self.err = err
		self.version = b'\xFF\x80'

	def to_bytes(self):
		message_length = 2 + 2 + 2 + len(self.ap) + len(self.priv)
		message = message_length.to_bytes(2, byteorder='big', signed=False)
		message += self.version
		message += len(self.ap).to_bytes(2, byteorder='big', signed=False)
		message += self.ap + self.priv
		return message
	
	@staticmethod
	def from_bytes(data):
		return KRB5ChangePassword.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff:io.BytesIO):
		message_length = int.from_bytes(buff.read(2), byteorder='big', signed=False)
		version = buff.read(2)
		ap_len = int.from_bytes(buff.read(2), byteorder='big', signed=False)
		ap = buff.read(ap_len)
		priv = buff.read(message_length - ap_len - 6)
		return KRB5ChangePassword(ap, priv)
	
	def decrypt_priv(self, subkey_cipher, subkey):
		privrep = KRB_PRIV.load(self.priv).native
		privdata = subkey_cipher.decrypt(subkey, 13, privrep["enc-part"]["cipher"])
		privdec = EncKrbPrivPart.load(privdata).native
		return privdec
	
	def parse_reply(self, subkey_cipher, subkey):
		privresponse = self.decrypt_priv(subkey_cipher, subkey)
		return KRB5CHPWReply.from_bytes(privresponse['user-data'])



class KRB5CHPWReply:
	def __init__(self):
		self.result_code = None
		self.result_message = None
		
		self.pw_min_length = None
		self.pw_history = None
		self.pw_max_age = None
		self.pw_min_age = None
		self.pw_flags = None

	
	@staticmethod
	def from_bytes(data):
		ticks = 864000000000
		res = KRB5CHPWReply()
		try:
			res.result_code = int.from_bytes(data[:2], byteorder='big', signed=False)
		except:
			res.result_code = int.from_bytes(data[:2], byteorder='big', signed=False)
		if len(data) == 2:
			return res
		

		res.pw_min_length = int.from_bytes(data[4:8], byteorder='big', signed=False)
		res.pw_history = int.from_bytes(data[8:12], byteorder='big', signed=False)
		res.pw_max_age = int.from_bytes(data[16:24], byteorder='big', signed=False) // ticks
		res.pw_min_age = int.from_bytes(data[24:32], byteorder='big', signed=False) // ticks
		res.pw_flags = KRB5PasswordPolicyFlags(int.from_bytes(data[12:16], byteorder='big', signed=False))
		return res
	
	def __str__(self):
		t = '=== KRB5CHPWReply ===\r\n'
		t += 'Result code: %s %s \r\n' % (self.result_code, KRB5CHPWResultCode.get(self.result_code, 'Unknown error'))
		t += 'Result message: %s\r\n' % self.result_message
		t += 'Password minimum length: %s\r\n' % self.pw_min_length
		t += 'Password history: %s\r\n' % self.pw_history
		t += 'Password maximum age: %s\r\n' % self.pw_max_age
		t += 'Password minimum age: %s\r\n' % self.pw_min_age
		t += 'Password flags: %s\r\n' % self.pw_flags
		return t
