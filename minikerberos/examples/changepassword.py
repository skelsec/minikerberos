
import logging
import asyncio
from minikerberos.common.factory import KerberosClientFactory, kerberos_url_help_epilog
from minikerberos.common.kirbi import Kirbi
from typing import List
import traceback

async def change_password(connection_url:str, newpass:str = None, targetuser:str=None, etypes:List[int] = [23,17,18]):
	try:
		etypes_final = []
		if isinstance(etypes, list) is False:
			etypes = [etypes]
		for etype in etypes:
			if isinstance(etype, str):
				etypes_final.extend([int(x) for x in etype.split(',')])
			
			if isinstance(etypes, int):
				etypes_final.append(etype)
		
		etypes = etypes_final

		cu = KerberosClientFactory.from_url(connection_url)
		client = cu.get_client()
		await client.get_TGT(override_etype=etypes)
		response = await client.change_password(newpass, targetuser=targetuser)
		if response.result_code == 0:
			print('Password changed successfully!')
			return
		
		print('Error changing password!')
		print(response)
		return

	except Exception as e:
		traceback.print_exc()
		print(str(e))

async def amain():
	import argparse
	
	parser = argparse.ArgumentParser(description='Kerberoast', formatter_class=argparse.RawDescriptionHelpFormatter, epilog = kerberos_url_help_epilog)
	parser.add_argument('kerberos_connection_url', help='the kerberos target string in the following format kerberos+<stype>://<domain>\\<username>@<domaincontroller-ip>')
	parser.add_argument('newpassword', help='New password')
	parser.add_argument('-u', '--targetuser', help='Target user to change password for. If not specified, the current user will be used.')
	parser.add_argument('-e', '--etypes', default='23,17,18', help='Encryption types to use. Default: 23,17,18')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	
	args = parser.parse_args()
	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	elif args.verbose == 1:
		logging.basicConfig(level=logging.DEBUG)
	else:
		logging.basicConfig(level=1)
	
	await change_password(args.kerberos_connection_url, args.newpassword, args.targetuser, args.etypes)

def main():
	asyncio.run(amain())
	
if __name__ == '__main__':
	main()