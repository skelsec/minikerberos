#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import os
import logging
import ntpath

from minikerberos.common.ccache import CCACHE, Credential
from minikerberos.common.utils import print_table

def main():
	import argparse

	parser = argparse.ArgumentParser(description='Tool to manipulate CCACHE files')
	subparsers = parser.add_subparsers(help = 'commands')
	subparsers.required = True
	subparsers.dest = 'command'
	
	roast_group = subparsers.add_parser('roast', help='Lists all tickets in hashcat-friendly format')
	roast_group.add_argument('-a', '--allhash', action='store_true', help='Process all tickets, regardless of enctype')
	roast_group.add_argument('-o', '--outfile', help='Output hash file name')
	
	list_group = subparsers.add_parser('list', help='List all tickets in the file')
	
	delete_group = subparsers.add_parser('del', help = 'Delete ticket(s) from file, store the new ccache file in a specified filename, or an automatically generated one')
	delete_group.add_argument('-o', '--outfile', help='Output ccache file name')
	delete_group.add_argument('-i','--id', type=int, action='append', help='Ticket ID to delete', required=True)
	parser.add_argument('ccachefile', help='input CCACHE file')
	args = parser.parse_args()

	
	logging.basicConfig(level=logging.INFO)
	logging.debug('Opening file %s' % args.ccachefile)
	cc = CCACHE.from_file(args.ccachefile)

	if args.command == 'list':
		table = []
		table.append(['id'] + Credential.summary_header())
		i = 0
		for cred in cc.credentials:
			table.append([str(i)] + cred.summary())
			i += 1
		print()	#this line intentionally left blank
		print_table(table)

	elif args.command == 'roast':
		if args.outfile:
			with open(args.outfile, 'wb') as f:
				for h in cc.get_hashes(all_hashes = args.allhash):
					f.write(h.encode() + b'\r\n')
		else:
			for h in cc.get_hashes(all_hashes = args.allhash):
				print(h)
	
	elif args.command == 'del':
		#delete
		output_filename = os.path.join(os.path.dirname(os.path.abspath(args.ccachefile)), '%s.edited.ccache' % ntpath.basename(args.ccachefile)) #sorry for this, im tired now :(
		id = args.id
		temp_cc = CCACHE()
		temp_cc.file_format_version = cc.file_format_version
		temp_cc.headers = cc.headers
		temp_cc.primary_principal = cc.primary_principal
		i = 0
		for cred in cc.credentials:
			if i in id:
				i += 1
				continue
			
			temp_cc.credentials.append(cred)
			i += 1
		logging.info('Writing edited file to %s' % output_filename)
		temp_cc.to_file(output_filename)

if __name__ == '__main__':
	main()