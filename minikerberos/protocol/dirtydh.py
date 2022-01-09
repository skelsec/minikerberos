import os
from asn1crypto import algos

class DirtyDH:
	def __init__(self):
		self.p = None
		self.g = None
		self.shared_key = None
		self.shared_key_int = None
		self.private_key = os.urandom(32)
		self.private_key_int = int(self.private_key.hex(), 16)
		self.dh_nonce = os.urandom(32)

	@staticmethod
	def from_params(p, g):
		dd = DirtyDH()
		dd.p = p
		dd.g = g
		return dd

	@staticmethod
	def from_dict(dhp):
		dd = DirtyDH()
		dd.p = dhp['p']
		dd.g = dhp['g']
		return dd

	@staticmethod
	def from_asn1(asn1_bytes):
		dhp = algos.DHParameters.load(asn1_bytes).native
		return DirtyDH.from_dict(dhp)
		
	
	def get_public_key(self):
		#y = g^x mod p
		return pow(self.g, self.private_key_int, self.p)
	
	def exchange(self, bob_int):
		self.shared_key_int = pow(bob_int, self.private_key_int, self.p)
		x = hex(self.shared_key_int)[2:]
		if len(x) % 2 != 0:
			x = '0' + x
		self.shared_key = bytes.fromhex(x)
		return self.shared_key