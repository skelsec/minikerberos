
from minikerberos.common.constants import KerberosSocketType

class KerberosTarget:
	def __init__(self, ip = None):
		self.ip = ip
		self.port = 88
		self.protocol = KerberosSocketType.TCP
		self.proxy = None
		self.timeout = 10

	def __str__(self):
		t = '===KerberosTarget===\r\n'
		t += 'ip: %s\r\n' % self.ip
		t += 'port: %s\r\n' % self.port
		t += 'protocol: %s\r\n' % self.protocol.name
		t += 'timeout: %s\r\n' % self.timeout
		t += 'proxy: %s\r\n' % str(self.proxy)
		return t
