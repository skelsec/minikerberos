import enum

class KerberosSocketType(enum.Enum):
	UDP = enum.auto()
	TCP = enum.auto()	

class KerberosSecretType(enum.Enum):
	PASSWORD = 'PASSWORD'
	PW = 'PW'
	PASS = 'PASS'
	NT = 'NT'
	AES = 'AES' #keeping this here for user's secret-type specification and compatibility reasons
	AES128 = 'AES128'
	AES256 = 'AES256'
	RC4 = 'RC4'
	DES = 'DES'
	DES3 = 'DES3'
	TDES = 'TDES'
	CCACHE = 'CCACHE'
	KEYTAB = 'KEYTAB'