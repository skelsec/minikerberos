from unicrypto.symmetric import RC4 as ARC4
from unicrypto import hmac as HMAC
from unicrypto.hashlib import md5 as MD5
from tqdm import tqdm

def crack_asrep(hashlist, tickets, total = 0):
	for asrep in tickets:
		result = None
		test = asrep.split('$')
		etype = test[2]
		user,checksum  = test[3].split(':')
		edata = test[4]

		#print('Etype : %s' % etype)
		#print('User  : %s' % user)
		#print('Chksum: %s' % checksum)
		#print('EData : %s...' % edata[:16])

		checksum = bytes.fromhex(checksum)
		edata = bytes.fromhex(edata)

		keyusage = 8
		keyusage = keyusage.to_bytes(4, byteorder='little', signed=False)

		for pwhash in tqdm(hashlist, total=total):
			pwhash = pwhash.strip()
			pwhash = bytes.fromhex(pwhash)

			ki = HMAC.new(pwhash, keyusage, MD5).digest()
			ke = HMAC.new(ki, checksum, MD5).digest()
			# at this point you can add some optimizations to make it faster,
			# but honestly I don't think it's needed, it's Python so it will be slow anyhow
			basic_plaintext = ARC4(ke).decrypt(edata)
			exp_cksum = HMAC.new(ki, basic_plaintext, MD5).digest()
			if checksum == exp_cksum:
				result = pwhash
				break
		else:
			continue
		print('%s: %s' % (asrep, result.hex()))



def crack_tgs(hashlist, tickets, total = 0):
	for tgs in tickets:
		result = None
		test = tgs.split('$')
		etype = test[2]
		user = test[3]
		realm = test[4]
		checksum = test[6]
		edata = test[7]

		#print('Etype : %s' % etype)
		#print('User  : %s' % user)
		#print('Realm : %s' % realm)
		#print('Chksum: %s' % checksum)
		#print('EData : %s...' % edata[:16])

		checksum = bytes.fromhex(checksum)
		edata = bytes.fromhex(edata)

		keyusage = 2
		keyusage = keyusage.to_bytes(4, byteorder='little', signed=False)

		for pwhash in tqdm(hashlist, total=total):
			pwhash = pwhash.strip()
			pwhash = bytes.fromhex(pwhash)

			ki = HMAC.new(pwhash, keyusage, MD5).digest()
			ke = HMAC.new(ki, checksum, MD5).digest()
			# at this point you can add some optimizations to make it faster,
			# but honestly I don't think it's needed
			basic_plaintext = ARC4(ke).decrypt(edata)
			exp_cksum = HMAC.new(ki, basic_plaintext, MD5).digest()
			if checksum == exp_cksum:
				result = pwhash
				break
		else:
			continue
		print('%s: %s' % (tgs, result.hex()))

def crack(hashlist, tickets):
	spntickets = []
	asreptickets = []
	if tickets.lower().find('$krb5tgs$23$') == -1 and tickets.lower().find('$krb5asrep$23$') == -1:
		with open(tickets, 'r') as f:
			for line in f:
				line = line.strip()
				if line == '':
					continue
				
				if line.lower().find('$krb5tgs$23$') != -1:
					spntickets.append(line)
				if line.lower().find('$krb5asrep$23$') != -1:
					asreptickets.append(line)
	else:
		if tickets.lower().find('$krb5tgs$23$') != -1:
			spntickets.append(tickets)
		if tickets.lower().find('$krb5asrep$23$') != -1:
			asreptickets.append(tickets)
	
	tt = len(spntickets) + len(asreptickets)
	if tt == 0:
		print('No tickets loaded! Exiting!')
		return
	
	print('Loaded %s tickets' % tt)
	total = 0
	with open(hashlist, 'r') as f:
		for line in f:
			line = line.strip()
			if line == '':
				continue
			total += 1
	
	with open(hashlist, 'r') as f:
		if len(spntickets) > 0:
			crack_tgs(f, spntickets, total=total)
		if len(asreptickets) > 0:
			crack_asrep(f, asreptickets, total=total)


def main():
	import argparse
	
	parser = argparse.ArgumentParser(description='Tries to decrypt RC4 TGS or ASREP ($krb5tgs$23$ / $krb5asrep$23$) using a list of NT hashes')
	parser.add_argument('hashlist', help='File containing NT hashes')
	parser.add_argument('tickets', help='Kerberoasted ticket in hashcat format. $krb5tgs$23$... or $krb5asrep$23$...')
	 
	args = parser.parse_args()
	
	crack(args.hashlist, args.tickets)


if __name__ == '__main__':
	main()