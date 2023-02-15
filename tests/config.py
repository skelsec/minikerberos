
import pathlib

# TEST DATA
##
KERBEROS_SERVER = '10.10.10.2'
KERBEROS_DOMAIN = 'TEST.CORP'
KERBEROS_USER = 'victim'
KERBEROS_PASSWORD = 'Passw0rd!1'

## Generic user account with valid credentials
KERBEROS_CONN_URL_PW = 'kerberos+password://TEST\\victim:Passw0rd!1@10.10.10.2'
KERBEROS_CONN_URL_RC4 = 'kerberos+rc4://TEST\\victim:f8963568a1ec62a3161d9d6449baba93@10.10.10.2'
KERBEROS_CONN_URL_RC4MD4 = 'kerberos+password://TEST\\victim:Passw0rd!1@10.10.10.2/?etype=-128'
KERBEROS_CONN_URL_AES128 = 'kerberos+password://TEST\\victim:Passw0rd!1@10.10.10.2/?etype=17'
KERBEROS_CONN_URL_AES256 = 'kerberos+password://TEST\\victim:Passw0rd!1@10.10.10.2/?etype=18'
KERBEROS_CONN_URL_PKINIT_PFX = 'kerberos+pfx://TEST\\victim:admin@10.10.10.2/?certdata=a.pfx'
KERBEROS_CONN_URL_PKINIT_PEM = 'kerberos+pem://TEST\\victim@10.10.10.2/?certdata=a.pem&keydata=a.key'
KERBEROS_CONN_URL_ASREP_MD4ARC4 = 'kerberos+none://TEST\\asreptest@10.10.10.2'
KERBEROS_CONN_URL_PKINIT_PFX = 'kerberos+pfx://TEST\\victim:admin@10.10.10.2/?certdata=a.pfx'

# SPN string for a valid TGS request
KERBEROS_TGS_SPN = 'cifs/win2019ad.test.corp@test.corp'

# Machine account for delegation tests
KERBEROS_CONN_URL_MACHINE = 'kerberos+password://TEST\\delegationtest$:TESTPassw0rd!1TESTPassw0rd!1@10.10.10.2'
KERBEROS_CONN_URL_MACHINE_CCACHE = 'kerberos+ccache://TEST\\delegationtest$:test.ccache@10.10.10.2'


# SPN string for a valid TGS request
KERBEROS_DELEGATION_USER_SELF = 'Administrator@test.corp'
KERBEROS_DELEGATION_SPN_SELF = 'cifs/delegationtest.test.corp@test.corp'

KERBEROS_DELEGATION_USER_PROXY = 'victim@test.corp'
KERBEROS_DELEGATION_SPN_PROXY = 'cifs/win2019ad.test.corp@test.corp'

KERBEROS_KERBEROAST_USER = 'srv_mssql'
KERBEROS_USERNAMES_VALID = [
	'Administrator',
	'victim',
	'asreptest', # this one is a bit special, it's a service account that can be used to request TGT without password
]
KERBEROS_USERNAMES_NONEXISTENT = [
	'nonexistent123',
	'nonexistent456',
	'nonexistent789'
]

KERBEROS_USERNAMES_KERBEROAST = [
	'krbtgt',
	'srv_mssql',
]
KERBEROS_USERNAMES_ASREP = [
	'asreptest', # this one is a bit special, it's a service account that can be used to request TGT without password
]



CURRENT_FILE_PATH = pathlib.Path(__file__).parent.absolute()
CCACHE_DIR = CURRENT_FILE_PATH.joinpath('testdata', 'ccache')
ADMIN_CCACHE = CCACHE_DIR.joinpath('administrator.ccache')
KIRBI_DIR = CURRENT_FILE_PATH.joinpath('testdata', 'kirbi')

def get_testfiles_kirbi():
	current_file_path = pathlib.Path(__file__).parent.absolute()
	kirbi_file_path = current_file_path.joinpath('testdata', 'kirbi')
	for kirbifile in kirbi_file_path.glob('*.kirbi'):
		yield kirbifile

def get_testfiles_keytab():
    current_file_path = pathlib.Path(__file__).parent.absolute()
    kirbi_file_path = current_file_path.joinpath('testdata', 'keytab')
    for kirbifile in kirbi_file_path.glob('*.keytab'):
        yield kirbifile

def get_testfiles_ccache():
	current_file_path = pathlib.Path(__file__).parent.absolute()
	ccache_file_path = current_file_path.joinpath('testdata', 'ccache')
	for ccachefile in ccache_file_path.glob('*.ccache'):
		yield ccachefile
	

def listcompare(list1, list2):
	if len(list1) != len(list2):
		raise Exception('Lists are not the same length')
	for item in list1:
		if item not in list2:
			raise Exception('Item not found in list2: %s' % item)
	return True