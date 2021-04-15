
import datetime
from minikerberos.protocol.asn1_structs import KRB_CRED, KrbCredInfo, EncKrbCredPart, EncryptedData

def print_table(lines, separate_head=True):
	"""Prints a formatted table given a 2 dimensional array"""
	#Count the column width
	widths = []
	for line in lines:
			for i,size in enumerate([len(x) for x in line]):
					while i >= len(widths):
							widths.append(0)
					if size > widths[i]:
							widths[i] = size
	   
	#Generate the format string to pad the columns
	print_string = ""
	for i,width in enumerate(widths):
			print_string += "{" + str(i) + ":" + str(width) + "} | "
	if (len(print_string) == 0):
			return
	print_string = print_string[:-3]
	   
	#Print the actual data
	for i,line in enumerate(lines):
			print(print_string.format(*line))
			if (i == 0 and separate_head):
					print("-"*(sum(widths)+3*(len(widths)-1)))



# this is from impacket, a bit modified
windows_epoch = datetime.datetime(1970,1,1, tzinfo=datetime.timezone.utc)
def dt_to_kerbtime(dt):
	td = dt - windows_epoch
	return int((td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / 1e6)

def TGSTicket2hashcat(res):		
	tgs_encryption_type    = int(res['ticket']['enc-part']['etype'])
	tgs_name_string        = '@'.join(res['ticket']['sname']['name-string']) #[0]
	tgs_realm              = res['ticket']['realm']

	if tgs_encryption_type == 23:
		tgs_checksum           = res['ticket']['enc-part']['cipher'][:16]
		tgs_encrypted_data2    = res['ticket']['enc-part']['cipher'][16:]
		return '$krb5tgs$%s$*%s$%s$spn*$%s$%s' % (tgs_encryption_type,tgs_name_string,tgs_realm, tgs_checksum.hex(), tgs_encrypted_data2.hex() )
	
	elif tgs_encryption_type in [17,18]:
		# $krb5tgs$17$user$realm$ae8434177efd09be5bc2eff8$90b4ce5b266821adc26c64f71958a475cf9348fce65096190be04f8430c4e0d554c86dd7ad29c275f9e8f15d2dab4565a3d6e21e449dc2f88e52ea0402c7170ba74f4af037c5d7f8db6d53018a564ab590fc23aa1134788bcc4a55f69ec13c0a083291a96b41bffb978f5a160b7edc828382d11aacd89b5a1bfa710b0e591b190bff9062eace4d26187777db358e70efd26df9c9312dbeef20b1ee0d823d4e71b8f1d00d91ea017459c27c32dc20e451ea6278be63cdd512ce656357c942b95438228e
		# $krb5tgs$18$user$realm$8efd91bb01cc69dd07e46009$7352410d6aafd72c64972a66058b02aa1c28ac580ba41137d5a170467f06f17faf5dfb3f95ecf4fad74821fdc7e63a3195573f45f962f86942cb24255e544ad8d05178d560f683a3f59ce94e82c8e724a3af0160be549b472dd83e6b80733ad349973885e9082617294c6cbbea92349671883eaf068d7f5dcfc0405d97fda27435082b82b24f3be27f06c19354bf32066933312c770424eb6143674756243c1bde78ee3294792dcc49008a1b54f32ec5d5695f899946d42a67ce2fb1c227cb1d2004c0 

		tgs_checksum           = res['ticket']['enc-part']['cipher'][-12:]
		tgs_encrypted_data2    = res['ticket']['enc-part']['cipher'][:-12]
		return '$krb5tgs$%s$%s$%s$%s$%s' % (tgs_encryption_type,tgs_name_string,tgs_realm, tgs_checksum.hex(), tgs_encrypted_data2.hex() )
	
	else:
		return 'unknown$enctype$%s' % tgs_encryption_type
		
	
def TGTTicket2hashcat(res):
	tgt_encryption_type    = int(res['enc-part']['etype'])
	tgt_name_string        = res['cname']['name-string'][0]
	tgt_realm              = res['crealm']
	tgt_checksum           = res['enc-part']['cipher'][:16]
	tgt_encrypted_data2    = res['enc-part']['cipher'][16:]
	
	return '$krb5asrep$%s$%s@%s:%s$%s' % (tgt_encryption_type,tgt_name_string, tgt_realm, tgt_checksum.hex(), tgt_encrypted_data2.hex())

def tgt_to_kirbi(tgs, encTGSRepPart):
	#encTGSRepPart is already decrypted at this point
	ci = {}
	ci['key'] = encTGSRepPart['key']
	ci['prealm'] = tgs['crealm']
	ci['pname'] = tgs['cname']
	ci['flags'] = encTGSRepPart['flags']
	ci['authtime'] = encTGSRepPart['authtime']
	ci['starttime'] = encTGSRepPart['starttime']
	ci['endtime'] = encTGSRepPart['endtime']
	ci['renew-till'] = encTGSRepPart['renew-till']
	ci['srealm'] = encTGSRepPart['srealm']
	ci['sname'] = encTGSRepPart['sname']

	ti = {}
	ti['ticket-info'] = [KrbCredInfo(ci)]

	te = {}
	te['etype']  = 0
	te['cipher'] = EncKrbCredPart(ti).dump()

	t = {}
	t['pvno'] = 5
	t['msg-type'] = 22
	t['enc-part'] = EncryptedData(te)
	t['tickets'] = [tgs['ticket']]

	return KRB_CRED(t)