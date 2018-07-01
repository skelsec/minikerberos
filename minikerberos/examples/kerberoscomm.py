#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import os
import logging
from minikerberos.common import *
from minikerberos.communication import *
from minikerberos.ccache import CCACHE

def main():
	import argparse
	import getpass
	
	parser = argparse.ArgumentParser(description='Polls the kerberos service for a TGS for the sepcified user and specified service')
	parser.add_argument('ticket-type', default='TGT', const='TGT', nargs='?', choices=['TGT', 'TGS'], help='Kerberos ticket type to be requested (default: %(default)s)')
	parser.add_argument('user', help='the user in impacket format <domain>/<username>:<password>@<domaincontroller-ip> password can be omitted wither by supplying AES key OR NT hash OR you\'ll be prompted for it in a secure manner')
	parser.add_argument('ccache', help='ccache file to store the TGT ticket in')
	parser.add_argument('-s','--service', help='the service principal in format <service>/<server-hostname>@<domain> Example: cifs/fileserver.test.corp@TEST.corp for a TGS ticket to be used for file access on server "fileserver". IMPORTANT: SERVER\'S HOSTNAME MUST BE USED, NOT IP!!!')
	parser.add_argument('-k', help='AES key')
	parser.add_argument('-n', help='NT hash of the password. For... reasons')
	parser.add_argument('-u', action='store_true', help='Use UDP instead of TCP (not tested)')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	
	args = parser.parse_args()
	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	elif args.verbose == 1:
		logging.basicConfig(level=logging.DEBUG)
	else:
		logging.basicConfig(level=1)
		
	if args.ticket_type == 'TGS' and not args.service:
		raise Exception('TGS ticket type requires a service definition (--service)!')
	
	password = None
	
	t, dc_ip = args.user.split('@')
	marker = t.find('/')
	domain = t[:marker]
	t = t[marker+1:]
	marker = t.find(':')
	if marker != -1:
		username = t[:marker]
		password = t[marker + 1 :]
	
	else:
		username = t
		
	kerberos_key_aes_128 = None
	kerberos_key_aes_256 = None
	if args.k:
		try:
			bytearray.fromhex(args.k)
		except Exception as e:
			raise Exception('AES key must be in hex format! %s' % e)
		
		if len(args.k) == 32:
			kerberos_key_aes_128 = args.k
		elif len(args.k) == 64:
			bytearray.fromhex(args.k)
			kerberos_key_aes_256 = args.k
		else:
			raise Exception('Wrong AES key size!')
	
	nt = None
	if args.n:
		try:
			bytearray.fromhex(args.n)
		except Exception as e:
			raise Exception('NT hash must be in hex format! %s' % e)
		
		if len(args.n) != 32:
			raise Exception('NT hash size incorrect')
		
		nt = args.n
		
	if not args.n and not args.k and not password:
		password = getpass.getpass('Enter password:')
			
	ccred = User()
	ccred.username = username
	ccred.domain = domain
	ccred.password = password
	ccred.NT = nt
	ccred.kerberos_key_aes_256 = kerberos_key_aes_256
	ccred.kerberos_key_aes_128 = kerberos_key_aes_128
	
	logging.debug('Getting TGT with %s/%s@%s' % (ccred.domain,ccred.username,dc_ip))
	
	ksoc = KerberosSocket(dc_ip, soc_type = KerberosSocketType.UDP if args.u == True else KerberosSocketType.TCP)
	
	service, t = args.service.split('/')
	hostname, domain = t.split('@')
	
	target = TargetServer()
	target.hostname = hostname
	target.service = service
	target.domain = domain
	
	if args.ticket_type == 'TGS':
		logging.debug('Getting TGS for %s/%s@%s' % (target.service,target.hostname,target.domain))
		
		kc = KerbrosComm(ccred, ksoc)
		tgt = kc.get_TGT()
		tgs = kc.get_TGS(target)
		kc.ccache.to_file(args.ccache)	
	
	logging.info('Done!')

if __name__ == '__main__':
	main()