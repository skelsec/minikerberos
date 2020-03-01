#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import os
import logging
import asyncio

from minikerberos import logger
from minikerberos.common.url import KerberosClientURL, kerberos_url_help_epilog
from minikerberos.aioclient import AIOKerberosClient
from minikerberos.common.spn import KerberosSPN

import pprint

async def amain(args):
	cu = KerberosClientURL.from_url(args.kerberos_connection_url)
	ccred = cu.get_creds()
	target = cu.get_target()

	service_spn = KerberosSPN.from_target_string(args.spn)
	target_user = KerberosSPN.from_user_email(args.targetuser)
	
	if not ccred.ccache:
		logger.debug('Getting TGT')
		client = AIOKerberosClient(ccred, target)
		await client.get_TGT()
		logger.debug('Getting ST')
		tgs, encTGSRepPart, key = await client.getST(target_user, service_spn)
	else:
		logger.debug('Getting TGS via TGT from CCACHE')
		for tgt, key in ccred.ccache.get_all_tgt():
			try:
				logger.info('Trying to get SPN with %s' % '!'.join(tgt['cname']['name-string']))
				client = AIOKerberosClient.from_tgt(target, tgt, key)

				tgs, encTGSRepPart, key = await client.getST(target_user, service_spn)
				logger.info('Sucsess!')
			except Exception as e:
				logger.debug('This ticket is not usable it seems Reason: %s' % e)
				continue
			else:
				break

	client.ccache.to_file(args.ccache)	
	logger.info('Done!')


def main():
	import argparse
	
	parser = argparse.ArgumentParser(description='Gets an S4U2proxy ticket impersonating given user', formatter_class=argparse.RawDescriptionHelpFormatter, epilog = kerberos_url_help_epilog)
	parser.add_argument('kerberos_connection_url', help='the kerberos target string in the following format <domain>/<username>/<secret_type>:<secret>@<domaincontroller-ip>')
	parser.add_argument('spn', help='the service principal in format <service>/<server-hostname>@<domain> Example: cifs/fileserver.test.corp@TEST.corp for a TGS ticket to be used for file access on server "fileserver". IMPORTANT: SERVER\'S HOSTNAME MUST BE USED, NOT IP!!!')
	parser.add_argument('targetuser', help='')
	parser.add_argument('ccache', help='ccache file to store the TGT ticket in')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	
	args = parser.parse_args()
	if args.verbose == 0:
		logger.setLevel(logging.WARNING)
	elif args.verbose == 1:
		logger.setLevel(logging.INFO)
	else:
		logger.setLevel(1)

	asyncio.run(amain(args))
	
	
if __name__ == '__main__':
	main()