#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import os
import logging
import asyncio
from minikerberos.common.url import KerberosClientURL, kerberos_url_help_epilog
from minikerberos.client import KerbrosClient

def getNT(args):
	cu = KerberosClientURL.from_url(args.kerberos_connection_url)
	ccred = cu.get_creds()
	target = cu.get_target()

	logging.debug('Getting TGT')
	
	client = KerbrosClient(ccred, target)
	tgs, enctgs, key, decticket = client.U2U()
	results = client.get_NT_from_PAC(decticket)
	for result in results:
		print('%s : %s' % (result[0], result[1]))
	logging.info('Done!')


def main():
	import argparse
	
	parser = argparse.ArgumentParser(description='Polls the kerberos service for a TGT for the sepcified user', formatter_class=argparse.RawDescriptionHelpFormatter, epilog = kerberos_url_help_epilog)
	parser.add_argument('kerberos_connection_url', help='the kerberos target string. ')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	
	args = parser.parse_args()
	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	elif args.verbose == 1:
		logging.basicConfig(level=logging.DEBUG)
	else:
		logging.basicConfig(level=1)
	
	getNT(args)
	
	
if __name__ == '__main__':
	main()