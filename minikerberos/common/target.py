
from asysocks.unicomm.common.target import UniTarget, UniProto
import copy

class KerberosTarget(UniTarget):
	def __init__(self, ip:str = None, proxies = None, protocol = UniProto.CLIENT_TCP, timeout = 10, port = 88):
		UniTarget.__init__(self, ip, port , protocol, timeout=timeout, proxies = proxies, dc_ip = ip)

	def get_newtarget(self, ip, port:int=88, hostname:str = None):
		return KerberosTarget(
			ip, 
			port = port, 
			protocol = self.protocol, 
			timeout = self.timeout, 
			proxies=copy.deepcopy(self.proxies)
		)

	def __str__(self):
		t = '===KerberosTarget===\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for x in self.__dict__[k]:
					t += '    %s: %s\r\n' % (k, x)
			else:
				t += '%s: %s\r\n' % (k, self.__dict__[k])
			
		return t
