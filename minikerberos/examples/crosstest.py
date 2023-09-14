import os
import logging
import asyncio
import copy
from minikerberos.common.factory import KerberosClientFactory, kerberos_url_help_epilog
from minikerberos.common.target import KerberosTarget
from asysocks.unicomm.common.target import UniProto
from minikerberos.common.spn import KerberosSPN
from minikerberos.aioclient import AIOKerberosClient
from minikerberos.common.kirbi import Kirbi
from minikerberos.common.creds import KerberosCredential
from minikerberos import logger

async def getTGS(kerberos_url, kirbifile = None):
	if isinstance(spn, str):
		spn = KerberosSPN.from_spn(spn)

	cu = KerberosClientFactory.from_url(kerberos_url)
	client = cu.get_client()
	logging.debug('Getting TGT')
	await client.get_TGT()
	logging.debug('Getting TGS for otherdomain krbtgt')
	ref_tgs, ref_encpart, ref_key, new_factory = await client.get_referral_ticket(spn.domain)
	kirbi = Kirbi.from_ticketdata(ref_tgs, ref_encpart)
	print(str(kirbi))
	if kirbifile is not None:
		kirbi.to_file(kirbifile)
	
	logging.info('Done!')

def main():
	import argparse
	
	parser = argparse.ArgumentParser(description='Polls the kerberos service for a TGS for the sepcified user and specified service', formatter_class=argparse.RawDescriptionHelpFormatter, epilog = kerberos_url_help_epilog)
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('--kirbi', help='kirbi file to store the TGT ticket in, otherwise kirbi will be printed to stdout')
	parser.add_argument('kerberos_url', help='the kerberos target string. ')

	logger.setLevel(logging.DEBUG)
	args = parser.parse_args()
	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	elif args.verbose == 1:
		logging.basicConfig(level=logging.DEBUG)
	else:
		logging.basicConfig(level=1)
	
	asyncio.run(getTGS(args.kerberos_url, args.kirbi))
	
if __name__ == '__main__':
	main()