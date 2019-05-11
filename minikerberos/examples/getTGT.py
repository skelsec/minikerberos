#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import os
import logging
from minikerberos.common import *
from minikerberos.communication import *

def main():
	import argparse
	
	parser = argparse.ArgumentParser(description='Polls the kerberos service for a TGT for the sepcified user', formatter_class=argparse.RawDescriptionHelpFormatter, epilog = KerberosCredential.help_epilog)
	parser.add_argument('kerberos_connection_string', help='the kerberos target string in the following format <domain>/<username>/<secret_type>:<secret>@<domaincontroller-ip>')
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
	
	ccred = KerberosCredential.from_connection_string(args.kerberos_connection_string)
	
	soc_type = KerberosSocketType.UDP if args.u else KerberosSocketType.TCP
	ksoc = KerberosSocket.from_connection_string(args.kerberos_connection_string, soc_type)
	
	logging.debug('Getting TGT')
	
	kc = KerbrosComm(ccred, ksoc)
	kc.get_TGT()
	kc.ccache.to_file(args.ccache)	
	logging.info('Done!')
	
	
if __name__ == '__main__':
	main()