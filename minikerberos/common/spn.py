

class KerberosSPN:
	def __init__(self):
		self.username = None
		self.service  = None #the service we are trying to get a ticket for (eg. cifs/mssql...)
		self.domain   = None #the kerberos realm
		self.port     = None #the port the service is running on
		
	# https://docs.microsoft.com/en-us/windows/desktop/ad/name-formats-for-unique-spns
	#def from_spn(self):

	@staticmethod
	def from_user_email(s):
		#please dont use this anymore
		return KerberosSPN.from_upn(s)

	@staticmethod
	def from_upn(s):
		"""Converts UserPrincipalName to SPN"""
		kt = KerberosSPN()
		if s.find('@') == -1:
			raise Exception('Incorrect format, @ sign is missing!')
		kt.username, kt.domain = s.split('@')
		return kt

	@staticmethod
	def from_spn(s, override_realm:str = None):
		"""
		Converts ServicePrincipalName to SPN
		service/host@domain
		or
		host@domain
		"""
		kt = KerberosSPN()
		
		if s.find('/') != -1:
			t, kt.domain = s.rsplit('@',1)
			kt.service, kt.username = t.split('/')
		else:
			if s.find('@') != -1:
				kt.username, kt.domain = s.rsplit('@', 1)
			else:
				kt.username = s
				if override_realm is None or override_realm == '':
					raise Exception('The following SPN is incorrect without additionally setting the realm: %s' % s)
		if override_realm is not None:
			kt.domain = override_realm
		if kt.domain.find(':') != -1:
			kt.domain, kt.port = kt.domain.split(':', 1)
		return kt

	def get_principalname(self):
		if self.service:
			if self.port:
				return [self.service, '%s:%s' % (self.username, self.port)]
			return [self.service, self.username]
		return [self.username]

	def get_formatted_pname(self):
		if self.service:
			if self.port:
				return '%s/%s:%s@%s' % (self.service, self.username, self.port, self.domain)
			else:
				return '%s/%s@%s' % (self.service, self.username, self.domain)
		return '%s@%s' % (self.username, self.domain)
	
	def __str__(self):
		return self.get_formatted_pname()
	
	@staticmethod
	def from_file(fpath:str, override_realm:str = None):
		res = []
		with open(fpath, 'r') as f:
			for line in f:
				line = line.strip()
				if line == '':
					continue
				spn = KerberosSPN.from_spn(line, override_realm)
				res.append(spn)
		return res