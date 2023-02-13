import os
import logging
import asyncio
from minikerberos.common.factory import KerberosClientFactory, kerberos_url_help_epilog
from minikerberos.common.spn import KerberosSPN
from minikerberos.aioclient import AIOKerberosClient
from minikerberos.common.kirbi import Kirbi

async def getTGS(kerberos_url, spn, kirbifile = None, ccachefile = None):
	if isinstance(spn, str):
		spn = KerberosSPN.from_spn(spn)

	cu = KerberosClientFactory.from_url(kerberos_url)
	client = cu.get_client()
	logging.debug('Getting TGT')
	await client.get_TGT()
	logging.debug('Getting TGS')
	tgs, encpart, key = await client.get_TGS(spn)
	if ccachefile is not None:
		client.ccache.to_file(ccachefile)
		print('TGT stored in ccache file %s' % ccachefile)
	
	kirbi = Kirbi.from_ticketdata(tgs, encpart)
	print(str(kirbi))
	if kirbifile is not None:
		kirbi.to_file(kirbifile)
		
	logging.info('Done!')

async def amain(args):

	if args.spn.find('@') == -1:
		raise Exception('SPN must contain @')
	t, domain = args.spn.split('@')
	if t.find('/') != -1:
		service, hostname = t.split('/')
	else:
		hostname = t
		service = None

	spn = KerberosSPN()
	spn.username = hostname
	spn.service = service
	spn.domain = domain

	cu = KerberosClientFactory.from_url(args.kerberos_connection_url)
	ccred = cu.get_creds()
	target = cu.get_target()
	
	logging.debug('Getting TGT')

	client = AIOKerberosClient(ccred, target)
	logging.debug('Getting TGT')
	await client.get_TGT()
	logging.debug('Getting TGS')
	await client.get_TGS(spn)
				
	client.ccache.to_file(args.ccache)
	logging.info('Done!')

def main():
	import argparse
	
	parser = argparse.ArgumentParser(description='Polls the kerberos service for a TGS for the sepcified user and specified service', formatter_class=argparse.RawDescriptionHelpFormatter, epilog = kerberos_url_help_epilog)
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('--ccache', help='CCACHE file to store the TGT ticket in, otherwise kirbi will be printed to stdout')
	parser.add_argument('--kirbi', help='kirbi file to store the TGT ticket in, otherwise kirbi will be printed to stdout')
	parser.add_argument('kerberos_url', help='the kerberos target string. ')
	parser.add_argument('spn', help='the SPN to request the TGS for. Must be in the format of service/host@domain')
	
	
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