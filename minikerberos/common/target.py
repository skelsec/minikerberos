
from asysocks.unicomm.common.target import UniTarget, UniProto

class KerberosTarget(UniTarget):
	def __init__(self, ip:str = None, proxies = None, protocol = UniProto.CLIENT_TCP, timeout = 10, port = 88):
		UniTarget.__init__(self, ip, port , protocol, timeout=timeout, proxies = proxies, dc_ip = ip)

	def __str__(self):
		t = '===KerberosTarget===\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for x in self.__dict__[k]:
					t += '    %s: %s\r\n' % (k, x)
			else:
				t += '%s: %s\r\n' % (k, self.__dict__[k])
			
		return t
