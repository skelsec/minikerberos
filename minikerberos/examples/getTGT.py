#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import os
import logging
import asyncio
from minikerberos.common.url import KerberosClientURL, kerberos_url_help_epilog
from minikerberos.aioclient import AIOKerberosClient

async def amain(args):
	cu = KerberosClientURL.from_url(args.kerberos_connection_url)
	ccred = cu.get_creds()
	target = cu.get_target()

	logging.debug('Getting TGT')
	
	client = AIOKerberosClient(ccred, target)
	await client.get_TGT()
	client.ccache.to_file(args.ccache)	
	logging.info('Done!')


def main():
	import argparse
	
	parser = argparse.ArgumentParser(description='Polls the kerberos service for a TGT for the sepcified user', formatter_class=argparse.RawDescriptionHelpFormatter, epilog = kerberos_url_help_epilog)
	parser.add_argument('kerberos_connection_url', help='the kerberos target string. ')
	parser.add_argument('ccache', help='ccache file to store the TGT ticket in')
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