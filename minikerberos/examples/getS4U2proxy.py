#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import os
import logging
from minikerberos import logger
from minikerberos.common import *
from minikerberos.communication import *
import pprint

def main():
	import argparse
	
	parser = argparse.ArgumentParser(description='Gets an S4U2proxy ticket impersonating given user', formatter_class=argparse.RawDescriptionHelpFormatter, epilog = KerberosCredential.help_epilog)
	parser.add_argument('kerberos_connection_string', help='the kerberos target string in the following format <domain>/<username>/<secret_type>:<secret>@<domaincontroller-ip>')
	parser.add_argument('spn', help='the service principal in format <service>/<server-hostname>@<domain> Example: cifs/fileserver.test.corp@TEST.corp for a TGS ticket to be used for file access on server "fileserver". IMPORTANT: SERVER\'S HOSTNAME MUST BE USED, NOT IP!!!')
	parser.add_argument('targetuser', help='')
	parser.add_argument('ccache', help='ccache file to store the TGT ticket in')
	parser.add_argument('-u', action='store_true', help='Use UDP instead of TCP (not tested)')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	
	args = parser.parse_args()
	if args.verbose == 0:
		logger.setLevel(logging.WARNING)
	elif args.verbose == 1:
		logger.setLevel(logging.INFO)
	else:
		logger.setLevel(1)
	
	
	ccred = KerberosCredential.from_connection_string(args.kerberos_connection_string)
	soc_type = KerberosSocketType.UDP if args.u else KerberosSocketType.TCP
	ksoc = KerberosSocket.from_connection_string(args.kerberos_connection_string, soc_type)	
	service_spn = KerberosTarget.from_target_string(args.spn)
	target_user = KerberosTarget.from_user_email(args.targetuser)
	
	if not ccred.ccache:
		logger.debug('Getting TGT')
		kc = KerbrosComm(ccred, ksoc)
		kc.get_TGT()
		logger.debug('Getting TGS')
		tgs, encTGSRepPart, key = kc.getST(target_user, service_spn)
	else:
		logger.debug('Getting TGS via TGT from CCACHE')
		for tgt, key in ccred.ccache.get_all_tgt():
			try:
				logger.info('Trying to get SPN with %s' % '!'.join(tgt['cname']['name-string']))
				kc = KerbrosComm.from_tgt(ksoc, tgt, key)
				tgs, encTGSRepPart, key = kc.getST(target_user, service_spn)
				logger.info('Sucsess!')
			except Exception as e:
				logger.debug('This ticket is not usable it seems Reason: %s' % e)
				continue
			else:
				break

	kc.ccache.to_file(args.ccache)	
	logger.info('Done!')
	
if __name__ == '__main__':
	main()