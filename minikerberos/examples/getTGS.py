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
	
	parser = argparse.ArgumentParser(description='Polls the kerberos service for a TGS for the sepcified user and specified service', formatter_class=argparse.RawDescriptionHelpFormatter, epilog = KerberosCredential.help_epilog)
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
	
	
	ccred = KerberosCredential.from_connection_string(args.kerberos_connection_string)
	soc_type = KerberosSocketType.UDP if args.u else KerberosSocketType.TCP
	ksoc = KerberosSocket.from_connection_string(args.kerberos_connection_string, soc_type)
	
	service, t = args.spn.split('/')
	hostname, domain = t.split('@')
	
	target = KerberosTarget()
	target.username = hostname
	target.service = service
	target.domain = domain
	
	
	if not ccred.ccache:
		logging.debug('Getting TGT')
		kc = KerbrosComm(ccred, ksoc)
		tgt = kc.get_TGT()
		logging.debug('Getting TGS')
		tgs, encpart, key = kc.get_TGS(target)
	else:
		logging.debug('Getting TGS via TGT from CCACHE')
		for tgt, key in ccred.ccache.get_all_tgt():
			try:
				logging.info('Trying to get SPN with %s' % '!'.join(tgt['cname']['name-string']))
				kc = KerbrosComm.from_tgt(ksoc, tgt, key)
				tgs, encpart, key = kc.get_TGS(target)
				logging.info('Sucsess!')
			except Exception as e:
				logging.debug('This ticket is not usable it seems Reason: %s' % e)
				continue
			else:
				break
				
	
	kc.ccache.to_file(args.ccache)	
	logging.info('Done!')
	
if __name__ == '__main__':
	main()