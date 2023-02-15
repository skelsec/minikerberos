
from minikerberos.common.ccache import CCACHE

def ccacheroast(ccachefilepath):
	ccache = CCACHE.from_file(ccachefilepath)
	for hash in ccache.get_hashes():
		print(hash)

def main():
	import argparse
	parser = argparse.ArgumentParser(description='Parses CCACHE file and outputs all TGS tickets in a hashcat-crackable format')
	parser.add_argument('ccache', help='CCACHE file to roast')
	
	args = parser.parse_args()
	ccacheroast(args.ccache)
	
		
		
if __name__ == '__main__':
	main()