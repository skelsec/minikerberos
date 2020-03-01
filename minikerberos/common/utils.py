
import datetime

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
	tgs_name_string        = res['ticket']['sname']['name-string'][0]
	tgs_realm              = res['ticket']['realm']
	tgs_checksum           = res['ticket']['enc-part']['cipher'][:16]
	tgs_encrypted_data2    = res['ticket']['enc-part']['cipher'][16:]
		
	return '$krb5tgs$%s$*%s$%s$spn*$%s$%s' % (tgs_encryption_type,tgs_name_string,tgs_realm, tgs_checksum.hex(), tgs_encrypted_data2.hex() )
	
def TGTTicket2hashcat(res):
	tgt_encryption_type    = int(res['enc-part']['etype'])
	tgt_name_string        = res['cname']['name-string'][0]
	tgt_realm              = res['crealm']
	tgt_checksum           = res['enc-part']['cipher'][:16]
	tgt_encrypted_data2    = res['enc-part']['cipher'][16:]
	
	return '$krb5asrep$%s$%s@%s:%s$%s' % (tgt_encryption_type,tgt_name_string, tgt_realm, tgt_checksum.hex(), tgt_encrypted_data2.hex())
	
