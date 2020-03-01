

from minikerberos.common.target import KerberosTarget
from minikerberos.common.creds import KerberosCredential
from minikerberos.common.proxy import KerberosProxy
from minikerberos.common.constants import KerberosSocketType, KerberosSecretType
from urllib.parse import urlparse, parse_qs

from asysocks.common.clienturl import SocksClientURL 

kerberos_url_help_epilog = """==== Extra Help ====
   kerberos connection url secret types: 
   - Plaintext: "pw" or "pass" or "password"
   - NT hash: "nt"
   - RC4 key: "rc4"
   - AES128/256 key: "aes"
   - CCACHE file: "ccache"
   - SSPI: "sspi"
   
   Example:
   - Plaintext + SOCKS5 proxy:
      kerberos+password://domain\\user:SecretPassword@127.0.0.1/proxytype=socks5&proxyhost=127.0.0.1&proxyport=1080
   - Plaintext:
      kerberos+password://domain\\user:SecretPassword@127.0.0.1
      kerberos+pw://domain\\user:SecretPassword@127.0.0.1
      kerberos+pass://domain\\user:SecretPassword@127.0.0.1
   - NT hash:
      kerberos+nt://domain\\user:921a7fece11f4d8c72432e41e40d0372@127.0.0.1
   - SSPI:
      TEST/user/sspi:@192.168.1.1
   - RC4 key:
      kerberos+rc4://domain\\user:921a7fece11f4d8c72432e41e40d0372@127.0.0.1
   - AES key:
      kerberos+aes://domain\\user:921a7fece11f4d8c72432e41e40d0372@127.0.0.1
   - CCACHE file:
      kerberos+ccache://domain\\user:creds.ccache@127.0.0.1
   - KEYTAB file:
      kerberos+keytab://domain\\user:creds.keytab@127.0.0.1
"""


kerberosclienturl_param2var = {
	'timeout': ('timeout', [int]),
}

class KerberosClientURL:
	def __init__(self):
		self.domain = None
		self.username = None
		self.secret_type = None
		self.secret = None


		self.dc_ip = None
		self.protocol = KerberosSocketType.TCP
		self.timeout = 10
		self.port = 88

		self.proxy = None

	def get_target(self):
		res = KerberosTarget()
		res.ip = self.dc_ip
		res.port = self.port
		res.protocol = KerberosSocketType.TCP
		res.proxy = self.proxy
		res.timeout = self.timeout
		return res

	def get_creds(self):
		if self.secret_type == KerberosSecretType.KEYTAB:
			return KerberosCredential.from_keytab(self.secret, self.username, self.domain)

		res = KerberosCredential()
		res.username = self.username
		res.domain = self.domain

		if self.secret_type in [KerberosSecretType.PASSWORD, KerberosSecretType.PW, KerberosSecretType.PASS]:
			res.password = self.secret
		elif self.secret_type in [KerberosSecretType.NT, KerberosSecretType.RC4]:
			if len(self.secret) != 32:
				raise Exception('Incorrect RC4/NT key! %s' % self.secret)
			res.nt_hash = self.secret
			res.kerberos_key_rc4 = self.secret
		elif self.secret_type in [KerberosSecretType.AES128, KerberosSecretType.AES256, KerberosSecretType.AES]:
			if self.secret_type == KerberosSecretType.AES:
				if len(self.secret) == 32:
					res.kerberos_key_aes_128 = self.secret
				elif len(self.secret) == 64:
					res.kerberos_key_aes_256 = self.secret
				else:
					raise Exception('Incorrect AES key! %s' % self.secret)
			elif self.secret_type == KerberosSecretType.AES128:
				if len(self.secret) != 32:
					raise Exception('Incorrect AES128 key! %s' % self.secret)
				res.kerberos_key_aes_128 = self.secret
			else:
				if len(self.secret) != 64:
					raise Exception('Incorrect AES256 key! %s' % self.secret)
				res.kerberos_key_aes_256 = self.secret
		elif self.secret_type == KerberosSecretType.DES:
			if len(self.secret) != 16:
				raise Exception('Incorrect DES key! %s' % self.secret)
			res.kerberos_key_des = self.secret
		elif self.secret_type in [KerberosSecretType.DES3, KerberosSecretType.TDES]:
			if len(self.secret) != 24:
				raise Exception('Incorrect DES3 key! %s' % self.secret)
			res.kerberos_key_des3 = self.secret
		elif self.secret_type == KerberosSecretType.CCACHE:
			res.ccache = self.secret
		else:
			raise Exception('Missing/unknown secret_type!')

		return res

	@staticmethod
	def from_url(url_str):
		res = KerberosClientURL()
		url = urlparse(url_str)

		res.dc_ip = url.hostname
		schemes = url.scheme.upper().split('+')
		if schemes[0] not in ['KERBEROS', 'KERBEROS-TCP, KERBEROS-UDP']:
			raise Exception('Unknown protocol! %s' % schemes[0])

		if schemes[0].endswith('UDP') is True:
			res.protocol = KerberosSocketType.UDP
		
		try:
			res.secret_type = KerberosSecretType(schemes[1])
		except:
			raise Exception('Unknown secret type! %s' % schemes[0])
		
		if url.username is not None:
			if url.username.find('\\') != -1:
				res.domain , res.username = url.username.split('\\')
			else:
				raise Exception('Domain missing from username!')
		else:
			raise Exception('Missing username!')

		res.secret = url.password
		if url.port is not None:
			res.port = int(url.port)
		
		query = parse_qs(url.query)
		proxy_present = False
		for k in query:
			if k.startswith('proxy') is True:
				proxy_present = True
			
			if k in kerberosclienturl_param2var:
				data = query[k][0]
				for c in kerberosclienturl_param2var[k][1]:
					data = c(data)

					setattr(
							res, 
							kerberosclienturl_param2var[k][0], 
							data
						)
		
		if proxy_present is True:
			cu = SocksClientURL.from_params(url_str)
			cu.endpoint_ip = res.dc_ip
			cu.endpoint_port = res.port

			res.proxy = KerberosProxy(cu.get_target(), cu.get_creds())

		
		if res.username is None:
			raise Exception('Missing username!')
		if res.secret is None:
			raise Exception('Missing secret/password!')
		if res.secret_type is None:
			raise Exception('Missing secret_type!')
		if res.dc_ip is None:
			raise Exception('Missing target hostname!')
		
		return res

if __name__ == '__main__':
	urls = [
		'kerberos+password://domain\\user:pass@word34tnk;adfs@127.0.0.1',
		'kerberos+aes://domain\\user:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@dc_ip',
		'kerberos+aes256://domain\\user:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@dc_ip',
		'kerberos+aes128://domain\\user:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@dc_ip',
		'kerberos+aes128://domain\\user:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@dc_ip',
		'kerberos+rc4://domain\\user:password@dc_ip',
		'kerberos+rc4://domain\\user:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@dc_ip',
		'kerberos+nt://domain\\user:password@dc_ip',
		'kerberos+nt://domain\\user:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@dc_ip',
		'kerberos+des://domain\\user:password@dc_ip',
		'kerberos+des://domain\\user:AAAAAAAAAAAAAAAA@dc_ip',
		'kerberos+password://domain\\user:password34tnk;adfs%40#@dc_ip',
		'kerberos+ccache://domain\\user:password@dc_ip',
		'kerberos+keytab://domain\\user:password@dc_ip',
		'kerberos+aes://domain\\user:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@dc_ip/?timeout=99',
		'kerberos+aes://domain\\user:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@dc_ip/?timeout=77&proxyhost=127.0.0.1&proxytype=socks5',
	]
	for url in urls:
		try:
			print(url)
			cu = KerberosClientURL.from_url(url)
			target = cu.get_target()
			creds = cu.get_creds()
			print(target)
			print(creds)
			input()
		except Exception as e:
			print(e)
			input()
	