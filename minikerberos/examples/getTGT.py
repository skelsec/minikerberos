import logging
import asyncio
from minikerberos.common.factory import KerberosClientFactory, kerberos_url_help_epilog
from minikerberos.common.kirbi import Kirbi

async def getTGT(kerberos_url:str, kirbifile:str = None, ccachefile:str = None, nopac:bool = False):
	cu = KerberosClientFactory.from_url(kerberos_url)
	client = cu.get_client()
	logging.debug('Getting TGT')
	
	await client.get_TGT(with_pac=nopac)
	if ccachefile is not None:
		client.ccache.to_file(ccachefile)
		print('TGT stored in ccache file %s' % ccachefile)
	
	kirbi = Kirbi.from_ticketdata(client.kerberos_TGT, client.kerberos_TGT_encpart)
	print(str(kirbi))
	if kirbifile is not None:
		kirbi.to_file(kirbifile)
		
	logging.info('Done!')

def main():
	import argparse
	
	parser = argparse.ArgumentParser(description='Polls the kerberos service for a TGT for the sepcified user', formatter_class=argparse.RawDescriptionHelpFormatter, epilog = kerberos_url_help_epilog)
	parser.add_argument('--nopac', action='store_false', help="Don't request a PAC in the TGT")
	parser.add_argument('--ccache', help='CCACHE file to store the TGT ticket in, otherwise kirbi will be printed to stdout')
	parser.add_argument('--kirbi', help='kirbi file to store the TGT ticket in, otherwise kirbi will be printed to stdout')
	parser.add_argument('kerberos_url', help='the kerberos target string. ')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	
	args = parser.parse_args()
	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	elif args.verbose == 1:
		logging.basicConfig(level=logging.DEBUG)
	else:
		logging.basicConfig(level=1)
	
	asyncio.run(getTGT(args.kerberos_url, args.kirbi, args.ccache, args.nopac))
	
	
if __name__ == '__main__':
	main()