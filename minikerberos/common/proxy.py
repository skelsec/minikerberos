
class KerberosProxy:
	def __init__(self, target = None,creds = None, type = None):
		self.target = target
		self.creds = creds
		self.type = type

	def __str__(self):
		t = '===KerberosTarget===\r\n'
		t += 'target: %s\r\n' % str(self.target)
		t += 'creds: %s\r\n' % str(self.creds)
		return t
