import enum
import io

from minikerberos.constants import EncryptionType
from minikerberos import encryption

#TODO: RC4 support!

# https://tools.ietf.org/html/draft-raeburn-krb-rijndael-krb-05
# https://tools.ietf.org/html/rfc2478
# https://tools.ietf.org/html/draft-ietf-krb-wg-gssapi-cfx-02

GSS_WRAP_HEADER = b'\x60\x2b\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02'

class GSSAPIFlags(enum.IntFlag):
	GSS_C_DCE_STYLE     = 0x1000
	GSS_C_DELEG_FLAG    = 1
	GSS_C_MUTUAL_FLAG   = 2
	GSS_C_REPLAY_FLAG   = 4
	GSS_C_SEQUENCE_FLAG = 8
	GSS_C_CONF_FLAG     = 0x10
	GSS_C_INTEG_FLAG    = 0x20
	
class KG_USAGE(enum.Enum):
	ACCEPTOR_SEAL  = 22
	ACCEPTOR_SIGN  = 23
	INITIATOR_SEAL = 24
	INITIATOR_SIGN = 25
	
class FlagsField(enum.IntFlag):
	SentByAcceptor = 0
	Sealed = 2
	AcceptorSubkey = 4
	
# 4.2.6.1. MIC Tokens
class GSSMIC:
	def __init__(self):
		self.TOK_ID = b'\x04\x04'
		self.Flags = None
		self.Filler = b'\xFF' * 5
		self.SND_SEQ = None
		self.SGN_CKSUM = None
		
	@staticmethod
	def from_bytes(data):
		return GSSMIC.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		m = GSSMIC()
		m.TOK_ID = buff.read(2)
		m.Flags = FlagsField(int.from_bytes(buff.read(1), 'big', signed = False))
		m.Filler = buff.read(5)
		m.SND_SEQ = int.from_bytes(buff.read(8), 'big', signed = False)
		m.SGN_CKSUM = buff.read() #should know the size based on the algo!
		return m
		
	def to_bytes(self):
		t  = self.TOK_ID
		t += self.Flags.to_bytes(1, 'big', signed = False)
		t += self.Filler
		t += self.SND_SEQ.to_bytes(8, 'big', signed = False)
		if self.SGN_CKSUM is not None:
			t += self.SGN_CKSUM
		
		return t
		
def get_gssapi(session_key):
	if session_key.enctype == encryption.Enctype.AES256:
		return GSSAPI_AES(session_key, encryption._AES256CTS, encryption._SHA1AES256)
	if session_key.enctype == encryption.Enctype.AES128:
		return GSSAPI_AES(session_key, encryption._AES128CTS, encryption._SHA1AES128)
	elif session_key.enctype == encryption.Enctype.RC4:
		#return GSSAPI_RC4()
		raise Exception('Unsupported etype %s' % enctype.name)
	else:
		raise Exception('Unsupported etype %s' % enctype.name)
		
# 4.2.6.2. Wrap Tokens
class GSSWrapToken:
	def __init__(self):
		self.TOK_ID = b'\x05\x04'
		self.Flags = None
		self.Filler = b'\xFF'
		self.EC = None
		self.RRC = None
		self.SND_SEQ = None
		self.Data = None
		
	@staticmethod
	def from_bytes(data):
		return GSSWrapToken.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		m = GSSWrapToken()
		m.TOK_ID = buff.read(2)
		m.Flags = FlagsField(int.from_bytes(buff.read(1), 'big', signed = False))
		m.Filler = buff.read(1)
		m.EC = int.from_bytes(buff.read(2), 'big', signed = False)
		m.RRC = int.from_bytes(buff.read(2), 'big', signed = False)
		m.SND_SEQ = int.from_bytes(buff.read(8), 'big', signed = False)
		return m
		
	def to_bytes(self):
		t  = self.TOK_ID
		t += self.Flags.to_bytes(1, 'big', signed = False)
		t += self.Filler
		t += self.EC.to_bytes(2, 'big', signed = False)
		t += self.RRC.to_bytes(2, 'big', signed = False)
		t += self.SND_SEQ.to_bytes(8, 'big', signed = False)
		if self.Data is not None:
			t += self.Data
		
		return t
		
class GSSAPI_AES:
	def __init__(self, session_key, cipher_type, checksum_profile):
		self.session_key = session_key
		self.checksum_profile = checksum_profile
		self.cipher_type = cipher_type
		self.cipher = None
		
	def rotate(self, data, numBytes):
		numBytes %= len(data)
		left = len(data) - numBytes
		result = data[left:] + data[:left]
		return result
		
	def unrotate(self, data, numBytes):
		numBytes %= len(data)
		result = data[numBytes:] + data[:numBytes]
		return result
		
	def GSS_GetMIC(self, data, seq_num):
		pad = (4 - (len(data) % 4)) & 0x3
		padStr = bytes([pad]) * pad
		data += padStr
		
		m = GSSMIC()
		m.Flags = FlagsField.AcceptorSubkey
		m.SND_SEQ = seq_num
		checksum_profile = self.checksum_profile()
		m.checksum = checksum_profile.checksum(self.session_key, KG_USAGE.INITIATOR_SIGN.value, data + m.to_bytes()[:16])
		
		return m.to_bytes()
		
	def GSS_Wrap(self, data, seq_num):
		cipher = self.cipher_type()
		pad = (cipher.blocksize - (len(data) % cipher.blocksize)) & 15
		padStr = b'\xFF' * pad
		data += padStr
		print('data_padded:          %s' % data.hex())
		print('data_padded_original: 810e00001a204de2d64fd111a3da0000f875ae0d1c4500003400000034000000008040050000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffff')
		
		t = GSSWrapToken()
		t.Flags = FlagsField.Sealed | FlagsField.AcceptorSubkey
		t.EC = pad
		t.RRC = 0
		t.SND_SEQ = seq_num
		print('token_1:          %s' % t.to_bytes().hex())
		print('token_1_original: 050406ff000c00000000000000000000')
		
		cipher_text = cipher.encrypt(self.session_key, KG_USAGE.INITIATOR_SEAL.value,  data + t.to_bytes(), None)
		print('cipher_text_1:          %s' % cipher_text.hex())
		print('cipher_text_1_original: 0880ed78d6196dde3f3fb23eeea650bc4ae025fa2a9c337c75c024d9d8f0186c75a4a9060e2a40a9ad024317bf5df6a86cb4a764a9ca36843f8fa4f99c03e2bde46f5a29aafc83dacdf9f0a5677446b5d910417142dc7b7ba7ded76cddc4acf9bf7ed44008cb9850e5701f2f9285dad6463ca8d0e365d4f1700f3d054e242ebcde2f3146ddd411a627af7486')
		t.RRC = 28 #[RFC4121] section 4.2.5
		print(t.RRC + t.EC)
		cipher_text = self.rotate(cipher_text, t.RRC + t.EC)
		print('cipher_text_2: %s' % cipher_text.hex())
		print('cipher_text_2_original: 08cb9850e5701f2f9285dad6463ca8d0e365d4f1700f3d054e242ebcde2f3146ddd411a627af74860880ed78d6196dde3f3fb23eeea650bc4ae025fa2a9c337c75c024d9d8f0186c75a4a9060e2a40a9ad024317bf5df6a86cb4a764a9ca36843f8fa4f99c03e2bde46f5a29aafc83dacdf9f0a5677446b5d910417142dc7b7ba7ded76cddc4acf9bf7ed440')
		ret1 = cipher_text[16 + t.RRC + t.EC:]
		ret2 = t.to_bytes() + cipher_text[:16 + t.RRC + t.EC]
		
		return ret1, ret2
		
	def GSS_Unwrap(self, data, seq_num, direction='init', auth_data = None):
		cipher = self.cipher_type()
		print(data.hex())
		input(auth_data.hex())
		t = GSSWrapToken.from_bytes(auth_data[8:])
		rotated = auth_data[16+8:] + data
		
		print(t.RRC)
		print(t.EC)
		
		cipher_text = self.unrotate(rotated, t.RRC + t.EC)
		plain_text = cipher.decrypt(self.session_key, KG_USAGE.ACCEPTOR_SEAL.value, cipher_text)
		
		return plain_text[:-(t.EC + 16)], None
		
		
def test():
	data_padded= bytes.fromhex('810e00001a204de2d64fd111a3da0000f875ae0d1c4500003400000034000000008040050000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffff')
	token_1= bytes.fromhex('050406ff000c00000000000000000000')
	cipherText_1 = bytes.fromhex('0880ed78d6196dde3f3fb23eeea650bc4ae025fa2a9c337c75c024d9d8f0186c75a4a9060e2a40a9ad024317bf5df6a86cb4a764a9ca36843f8fa4f99c03e2bde46f5a29aafc83dacdf9f0a5677446b5d910417142dc7b7ba7ded76cddc4acf9bf7ed44008cb9850e5701f2f9285dad6463ca8d0e365d4f1700f3d054e242ebcde2f3146ddd411a627af7486')
	cipherText_2 = bytes.fromhex('08cb9850e5701f2f9285dad6463ca8d0e365d4f1700f3d054e242ebcde2f3146ddd411a627af74860880ed78d6196dde3f3fb23eeea650bc4ae025fa2a9c337c75c024d9d8f0186c75a4a9060e2a40a9ad024317bf5df6a86cb4a764a9ca36843f8fa4f99c03e2bde46f5a29aafc83dacdf9f0a5677446b5d910417142dc7b7ba7ded76cddc4acf9bf7ed440')



	session_key = encryption.Key( encryption.Enctype.AES256 , bytes.fromhex('3e242e91996aadd513ecb1bc2369e44183e08e08c51550fa4b681e77f75ed8e1'))
	data = bytes.fromhex('810e00001a204de2d64fd111a3da0000f875ae0d1c4500003400000034000000008040050000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffff')
	sequenceNumber = 0
	ret1 = bytes.fromhex('4ae025fa2a9c337c75c024d9d8f0186c75a4a9060e2a40a9ad024317bf5df6a86cb4a764a9ca36843f8fa4f99c03e2bde46f5a29aafc83dacdf9f0a5677446b5d910417142dc7b7ba7ded76cddc4acf9bf7ed440')
	ret2 = bytes.fromhex('050406ff000c001c000000000000000008cb9850e5701f2f9285dad6463ca8d0e365d4f1700f3d054e242ebcde2f3146ddd411a627af74860880ed78d6196dde3f3fb23eeea650bc')
	
	gssapi = get_gssapi(session_key)
	r1, r2 = gssapi.GSS_Wrap(data, sequenceNumber)
	
	gssapi.GSS_Unwrap(r1, 0, auth_data = b'\xff'*8 + r2)
	
	print(r1.hex())
	print(ret1.hex())
	
	assert r1 == ret1
	assert r2 == ret2

if __name__ == '__main__':
	test()