#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import os
import logging
from minikerberos.common import *
from minikerberos.communication import *
from minikerberos.ccache import CCACHE
from minikerberos.encryption import _enctype_table, Key
import pprint

if __name__ == '__main__':
	import argparse
	import getpass
	
	parser = argparse.ArgumentParser(description='Polls the kerberos service for a TGT for the sepcified user')
	parser.add_argument('connection', help='the user in impacket format <domain>/<username>/<secret_type>:<secret>@<domaincontroller-ip> password can be omitted wither by supplying AES key OR NT hash OR you\'ll be prompted for it in a secure manner')
	#parser.add_argument('ccache', help='ccache file to store the TGT ticket in')
	parser.add_argument('-u', action='store_true', help='Use UDP instead of TCP (not tested)')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	
	args = parser.parse_args()
	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	elif args.verbose == 1:
		logging.basicConfig(level=logging.DEBUG)
	else:
		logging.basicConfig(level=1)
	
	ccred = KerberosCredential.from_connection_string(args.connection)
	print(str(ccred))
	
	ccred_krbtgt = KerberosCredential.from_connection_string('TEST/ktbtgt/aes:832da89673a5dc815d400fe3954b9db3fc2a437c1d462727f3956306c71aad92@10.10.10.2')
	
	soc_type = KerberosSocketType.UDP if args.u else KerberosSocketType.TCP
	ksoc = KerberosSocket.from_connection_string(args.connection, soc_type)
	print(str(ksoc))
	
	logging.debug('Getting TGT')
	
	kc = KerbrosComm(ccred, ksoc)
	kc.get_TGT()
	#kc.ccache.to_file(args.ccache)	
	logging.info('Done!')
	
	if args.verbose > 1:
		pprint.pprint(kc.kerberos_TGT)
		pprint.pprint(kc.kerberos_TGT_encpart)
	
	
	
	krbtgt_data = kc.kerberos_TGT['ticket']['enc-part']['cipher']
	et = EncryptionType(kc.kerberos_TGT['ticket']['enc-part']['etype'])
	krbtgt_key = Key(kc.kerberos_TGT['ticket']['enc-part']['etype'], ccred_krbtgt.get_key_for_enctype(et))
	
	krbtgt_cipher = _enctype_table[kc.kerberos_TGT['ticket']['enc-part']['etype']]
	
	temp = krbtgt_cipher.decrypt(krbtgt_key, kc.kerberos_TGT['ticket']['enc-part']['kvno'], krbtgt_data)
	print(temp.hex())
	krbtgt_enc = EncTicketPart.load(temp).native
	pprint.pprint(krbtgt_enc)
	
	#print(krbtgt_enc['authorization-data'][0]['ad-data'])
	ad_data = AD_IF_RELEVANT.load(krbtgt_enc['authorization-data'][0]['ad-data'])
	
	with open('addata.bin','wb') as f:
		f.write(ad_data.native[0]['ad-data'])
	
	
	