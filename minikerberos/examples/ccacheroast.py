#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

from minikerberos.common.ccache import CCACHE

def main():
	import argparse
	parser = argparse.ArgumentParser(description='Parses CCACHE file and outputs all TGS tickets in a hashcat-crackable format')
	parser.add_argument('ccache', help='CCACHE file to roast')
	
	args = parser.parse_args()
	
	ccache = CCACHE.from_file(args.ccache)
	for hash in ccache.get_hashes(all_hashes = True):
		print(hash)
		
		
if __name__ == '__main__':
	main()