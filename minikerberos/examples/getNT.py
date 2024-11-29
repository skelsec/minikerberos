import logging
import asyncio
from minikerberos.common.factory import KerberosClientFactory, kerberos_url_help_epilog
from minikerberos.protocol.external.ticketutil import get_NT_from_PAC

async def get_NT(kerberos_url):
	cu = KerberosClientFactory.from_url(kerberos_url)
	client = cu.get_client()
	tgs, enctgs, key, decticket = await client.U2U()
	results = get_NT_from_PAC(client.pkinit_tkey, decticket)
	for result in results:
		print('%s : %s' % (result[0], result[1]))
	print('Done!')
	return results

def main():
	import argparse
	
	parser = argparse.ArgumentParser(description='Fetches the NT hash for the user. PKI auth required.', formatter_class=argparse.RawDescriptionHelpFormatter, epilog = kerberos_url_help_epilog)
	parser.add_argument('kerberos_url', help=r'The kerberos target URL. Example: "kerberos+pfx://TEST.corp\Administrator:admin@10.10.10.2/?certdata=test.pfx"')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	
	args = parser.parse_args()
	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	elif args.verbose == 1:
		logging.basicConfig(level=logging.DEBUG)
	else:
		logging.basicConfig(level=1)
	
	asyncio.run(get_NT(args.kerberos_url))
	
	
if __name__ == '__main__':
	main()
