import secrets

class UserCredential:
	def __init__(self):
		self.username = None
		self.domain = None
		self.password = None
		self.NT = None
		self.LM = None
		self.kerberos_key_aes_256 = None
		self.kerberos_key_aes_128 = None
		self.kerberos_key_des = None
		self.kerberos_key_rc4 = None
		
class TargetServer:
	def __init__(self):
		self.ip = None
		self.hostname = None
		self.service = None #the service we are trying to get a ticket for (eg. cifs/mssql...)
		self.domain = None #the kerberos realm
		self.kerberos_ip = None #IP address of the kerberos server (active directory)

