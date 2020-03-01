#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import os
import logging
from minikerberos.common.ccache import CCACHE

def main():
	import argparse
	
	parser = argparse.ArgumentParser(description='Convert ccache file to kirbi file(s)')
	parser.add_argument('ccache', help='path to the ccache file')
	parser.add_argument('kirbidir', help='output directory fir the extracted kirbi file(s)')	
	parser.add_argument('-v', '--verbose', action='count', default=0)
	
	args = parser.parse_args()
	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	elif args.verbose == 1:
		logging.basicConfig(level=logging.DEBUG)
	else:
		logging.basicConfig(level=1)
	
	logging.info('Parsing CCACHE file')
	cc = CCACHE.from_file(args.ccache)
	logging.info('Extracting kirbi file(s)')
	cc.to_kirbidir(args.kirbidir)
	logging.info('Done!')

if __name__ == '__main__':
	main()