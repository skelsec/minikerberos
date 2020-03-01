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
	
	parser = argparse.ArgumentParser(description='Convert kirbi file(s) to a single ccache file')
	parser.add_argument('kirbi', help='path to the kirbi file or a of kirbi files')
	parser.add_argument('ccache', help='ccache file name to be created')
	
	parser.add_argument('-v', '--verbose', action='count', default=0)
	
	args = parser.parse_args()
	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	elif args.verbose == 1:
		logging.basicConfig(level=logging.DEBUG)
	else:
		logging.basicConfig(level=1)
	
	abs_path = os.path.abspath(args.kirbi)
	if os.path.isdir(abs_path):	
		logging.info('Parsing kirbi files in directory %s' % abs_path)
		cc = CCACHE.from_kirbidir(abs_path)
		cc.to_file(args.ccache)
		
	else:
		logging.info('Parsing kirbi file %s' % abs_path)
		cc = CCACHE.from_kirbifile(abs_path)
		cc.to_file(args.ccache)
		
	logging.info('Done!')

if __name__ == '__main__':
	main()