#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import os
import logging
import asyncio
from minikerberos.common.url import KerberosClientURL, kerberos_url_help_epilog
from minikerberos.common.spn import KerberosSPN
from minikerberos.aioclient import AIOKerberosClient

async def amain(args):

	if args.spn.find('@') == -1:
		raise Exception('SPN must contain @')
	t, domain = args.spn.split('@')
	if t.find('/') != -1:
		service, hostname = args.spn.split('/')
	else:
		hostname = t
		service = None

	spn = KerberosSPN()
	spn.username = hostname
	spn.service = service
	spn.domain = domain

	cu = KerberosClientURL.from_url(args.kerberos_connection_url)
	ccred = cu.get_creds()
	target = cu.get_target()
	
	logging.debug('Getting TGT')
	
	if not ccred.ccache:
		client = AIOKerberosClient(ccred, target)
		logging.debug('Getting TGT')
		await client.get_TGT()
		logging.debug('Getting TGS')
		await client.get_TGS(spn)
	else:
		logging.debug('Getting TGS via TGT from CCACHE')
		for tgt, key in ccred.ccache.get_all_tgt():
			try:
				logging.info('Trying to get SPN with %s' % '!'.join(tgt['cname']['name-string']))
				client = AIOKerberosClient.from_tgt(target, tgt, key)
				await client.get_TGS(spn)
				logging.info('Sucsess!')
			except Exception as e:
				logging.debug('This ticket is not usable it seems Reason: %s' % e)
				continue
			else:
				break
				
	client.ccache.to_file(args.ccache)
	logging.info('Done!')

def main():
	import argparse
	
	parser = argparse.ArgumentParser(description='Polls the kerberos service for a TGS for the sepcified user and specified service', formatter_class=argparse.RawDescriptionHelpFormatter, epilog = kerberos_url_help_epilog)
	parser.add_argument('kerberos_connection_string', help='the kerberos target string in the following format <domain>/<username>/<secret_type>:<secret>@<domaincontroller-ip>')
	parser.add_argument('spn', help='the service principal in format <service>/<server-hostname>@<domain> Example: cifs/fileserver.test.corp@TEST.corp for a TGS ticket to be used for file access on server "fileserver". IMPORTANT: SERVER\'S HOSTNAME MUST BE USED, NOT IP!!!')
	parser.add_argument('ccache', help='ccache file to store the TGT ticket in')
	parser.add_argument('-u', action='store_true', help='Use UDP instead of TCP (not tested)')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	
	args = parser.parse_args()
	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	elif args.verbose == 1:
		logging.basicConfig(level=logging.DEBUG)
	else:
		logging.basicConfig(level=1)
	
	asyncio.run(amain(args))
	
if __name__ == '__main__':
	main()