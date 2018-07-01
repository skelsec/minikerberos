from minikerberos.ccache import CCACHE

if __name__ == '__main__':
	ccache = CCACHE.from_file('../../ktest/victim_lsass_latest.dmp_229c8765.ccache')
	print(ccache.get_hashes(all_hashes = True))