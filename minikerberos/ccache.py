#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import os
import datetime
import glob
from asn1_structs import *
from asn1crypto import core

# this is from impacket, a bit modified
windows_epoch = datetime.datetime(1970,1,1, tzinfo=datetime.timezone.utc)
def dt_to_kerbtime(dt):
	td = dt - windows_epoch
	return int((td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / 1e6)

# http://repo.or.cz/w/krb5dissect.git/blob_plain/HEAD:/ccache.txt
class Header:
	def __init__(self):
		self.tag = None
		self.taglen = None
		self.tagdata = None
		
	def parse(reader):
		h = Header()
		h.tag = int.from_bytes(reader.read(2), byteorder='big', signed=False)
		h.taglen = int.from_bytes(reader.read(2), byteorder='big', signed=False)
		h.tagdata = reader.read(h.taglen)
		return h
		
	def to_bytes(self):
		t =  self.tag.to_bytes(2, byteorder='big', signed=False)
		t += self.taglen.to_bytes(2, byteorder='big', signed=False)
		t += self.tagdata
		return t

class DateTime:
	def __init__(self):
		self.time_offset = None
		self.usec_offset = None
		
	def parse(reader):
		d = DateTime()
		d.time_offset = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		d.usec_offset = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		return d
		
	def to_bytes(self):
		t =  self.time_offset.to_bytes(4, byteorder='big', signed=False)
		t += self.usec_offset.to_bytes(4, byteorder='big', signed=False)
		return t
		

		
class Credential:
	def __init__(self):
		self.client = None
		self.server = None
		self.key = None
		self.time = None
		self.is_skey = None
		self.tktflags = None
		self.num_address = None
		self.addrs = []
		self.num_authdata = None
		self.authdata = []
		self.ticket = None
		self.second_ticket = None
		
	
		
	def to_tgt(self):
		enc_part = EncryptedData({'etype': 1, 'cipher': b''})
		
		tgt_rep = {}
		tgt_rep['pvno'] = krb5_pvno
		tgt_rep['msg-type'] = int(MESSAGE_TYPE('krb-as-rep'))
		tgt_rep['crealm'] = self.server.realm
		tgt_rep['cname'] = self.client.to_asn1()
		tgt_rep['ticket'] = self.ticket.to_asn1()
		tgt_rep['enc-part'] = enc_part
		
		return tgt_rep
		
		
		
	def from_asn1(ticket, data):
		###
		# data  = KrbCredInfo 
		###
		c = Credential()
		c.client = Principal.from_asn1(data['pname'], data['prealm'])
		c.server = Principal.from_asn1(data['sname'], data['srealm'])
		c.key = Keyblock.from_asn1(data['key'])
		c.is_skey = 0 #not sure!
		
		c.tktflags = TicketFlags(data['flags']).cast(core.IntegerBitString).native
		c.num_address = 0
		c.num_authdata = 0
		c.ticket = CCACHEOctetString.from_asn1(ticket['enc-part']['cipher'])
		c.second_ticket = CCACHEOctetString.empty()
		return c
		
	def parse(reader):
		c = Credential()
		c.client = Principal.parse(reader)
		c.server = Principal.parse(reader)
		c.key = Keyblock.parse(reader)
		c.is_skey = int.from_bytes(reader.read(1), byteorder='big', signed=False)
		c.tktflags = int.from_bytes(reader.read(4), byteorder='little', signed=False)
		c.num_address = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		for i in range(c.num_address):
			c.addrs.append(Address.parse(reader))
		c.num_authdata = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		for i in range(c.num_authdata):
			c.authdata.append(Authdata.parse(reader))
		c.ticket = CCACHEOctetString.parse(reader)
		c.second_ticket = CCACHEOctetString.parse(reader)
		return c
		
	def to_bytes(self):
		t =  self.client.to_bytes()
		t += self.server.to_bytes()
		t += self.key.to_bytes()
		t += self.time.to_bytes()
		t += self.is_skey.to_bytes(1, byteorder='big', signed=False)
		t += self.tktflags.to_bytes(4, byteorder='little', signed=False)
		t += self.num_address.to_bytes(4, byteorder='big', signed=False)
		for addr in self.addrs:
			t += addr.to_bytes()
		t += self.num_authdata.to_bytes(4, byteorder='big', signed=False)
		for ad in self.authdata:
			t += ad.to_bytes()
		t += self.ticket.to_bytes()
		t += self.second_ticket.to_bytes()
		return t
		
class Keyblock:
	def __init__(self):
		self.keytype = None
		self.etype = None
		self.keylen = None
		self.keyvalue = None
		
	def from_asn1(data):
		k = Keyblock()
		k.keytype = data['keytype']
		k.etype = 0 # not sure
		k.keylen = len(data['keyvalue'])
		k.keyvalue = data['keyvalue']
		print(k.keylen)
		print(k.keyvalue.hex())
		
		return k
		
	def parse(reader):
		k = Keyblock()
		k.keytype = int.from_bytes(reader.read(2), byteorder='big', signed=False)
		k.etype = int.from_bytes(reader.read(2), byteorder='big', signed=False)
		k.keylen = int.from_bytes(reader.read(2), byteorder='big', signed=False)
		k.keyvalue = reader.read(k.keylen)
		return k
		
	def to_bytes(self):
		t = self.keytype.to_bytes(2, byteorder='big', signed=False)
		t += self.etype.to_bytes(2, byteorder='big', signed=False)
		t += self.keylen.to_bytes(2, byteorder='big', signed=False)
		t += self.keyvalue
		return t
		
		
class Times:
	def __init__(self):
		self.authtime = None
		self.starttime = None
		self.endtime = None
		self.renew_till = None
		
	def from_asn1(enc_as_rep_part):
		t = Times()
		if 'authtime' in enc_as_rep_part and enc_as_rep_part['authtime']:
			t.authtime = dt_to_kerbtime(enc_as_rep_part['authtime'])
		else:
			t.authtime = 0
		t.starttime = dt_to_kerbtime(enc_as_rep_part['starttime'])
		t.endtime = dt_to_kerbtime(enc_as_rep_part['endtime'])
		t.renew_till = dt_to_kerbtime(enc_as_rep_part['renew-till'])
		
		return t
		
	def dummy_time(start= datetime.datetime.now(datetime.timezone.utc)):
		t = Times()
		t.authtime = dt_to_kerbtime(start)
		t.starttime = dt_to_kerbtime(start )
		t.endtime = dt_to_kerbtime(start + datetime.timedelta(days=1))
		t.renew_till = dt_to_kerbtime(start + datetime.timedelta(days=2))
		return t
		
	def parse(reader):
		t = Times()
		t.authtime = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		t.starttime = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		t.endtime = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		t.renew_till = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		return t
		
	def to_bytes(self):
		t = self.authtime.to_bytes(4, byteorder='big', signed=False)
		t += self.starttime.to_bytes(4, byteorder='big', signed=False)
		t += self.endtime.to_bytes(4, byteorder='big', signed=False)
		t += self.renew_till.to_bytes(4, byteorder='big', signed=False)
		return t
		
class Address:
	def __init__(self):
		self.addrtype = None
		self.addrdata = None
		
	def parse(reader):
		a = Address()
		a.addrtype = int.from_bytes(reader.read(2), byteorder='big', signed=False)
		a.addrdata = CCACHEOctetString.parse(reader)
		return a
		
	def to_bytes(self):
		t = self.addrtype.to_bytes(2, byteorder='big', signed=False)
		t += self.addrdata.to_bytes()
		return t
		
class Authdata:
	def __init__(self):
		self.authtype = None
		self.authdata = None
	
	def parse(reader):
		a = Authdata()
		a.authtype = int.from_bytes(reader.read(2), byteorder='big', signed=False)
		a.authdata = CCACHEOctetString.parse(reader)
		return a
		
	def to_bytes(self):
		t = self.authtype.to_bytes(2, byteorder='big', signed=False)
		t += self.authdata.to_bytes()
		return t
		
class Principal:
	def __init__(self):
		self.name_type = None
		self.num_components = None
		self.realm = None
		self.components = []
		
	def from_asn1(principal, realm):
		p = Principal()
		p.name_type = principal['name-type']
		p.num_components = len(principal['name-string'])
		p.realm = CCACHEOctetString.from_string(realm)
		for comp in principal['name-string']:
			p.components.append(CCACHEOctetString.from_asn1(comp))
			
		return p
		
	def to_asn1(self):
		t = {}
		t['name_type'] = self.name_type
		t['name-string'] = [ cos.data for cos in self.components ]		
		return t, self.realm
		
	def parse(reader):
		p = Principal()
		p.name_type = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		p.num_components = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		p.realm = CCACHEOctetString.parse(reader)
		for i in range(p.num_components):
			p.components.append(CCACHEOctetString.parse(reader))
		return p
		
	def to_bytes(self):
		t = self.name_type.to_bytes(4, byteorder='big', signed=False)
		t += self.num_components.to_bytes(4, byteorder='big', signed=False)
		t += self.realm.to_bytes()
		for com in self.components:
			t += com.to_bytes()
		return t
		
class CCACHEOctetString:
	def __init__(self):
		self.length = None
		self.data = None
		
	def empty():
		o = CCACHEOctetString()
		o.length = 0
		o.data = b''
		return o
		
	def to_asn1(self):
		return self.data
		
	def from_string(data):
		o = CCACHEOctetString()
		o.length = len(data)
		o.data = data.encode()
		return o
		
	def from_asn1(data):
		o = CCACHEOctetString()
		o.length = len(data)
		if isinstance(data,str):
			o.data = data.encode()
		else:
			o.data = data
		return o
	
	def parse(reader):
		o = CCACHEOctetString()
		o.length = int.from_bytes(reader.read(4), byteorder='big', signed=False)
		o.data = reader.read(o.length)
		return o
		
	def to_bytes(self):
		t = self.length.to_bytes(4, byteorder='big', signed=False)
		t += self.data
		return t	
	
class CCACHEFile:
	def __init__(self, filename):
		self.filename = filename
		self.ccache = None
		
		
class CCACHE:
	def __init__(self):
		self.file_format_version = None #0x0504
		self.headerlen = None
		self.headers = []
		self.primary_principal = None
		self.credentials = []
		
		self.setup()
		
	def setup(self):
		self.file_format_version = 0x0504
		self.headerlen = 1
		header = Header()
		header.tag = 1
		header.taglen = 8
		header.tagdata = b'\xff\xff\xff\xff\x00\x00\x00\x00'
		self.headers.append(header)
		
	def add_tgt(self, as_rep, enc_as_rep_part, override_pp = True): #from AS_REP
		"""
		Creates credential object from the TGT and adds to the ccache file
		The TGT is basically the native representation of the asn1 encoded AS_REP data that the AD sends upon a succsessful TGT request.
		
		This function doesn't do decryption of the encrypted part of the as_rep object, it is expected that the decrypted XXX is supplied in enc_as_rep_part
		
		override_pp: bool to determine if client principal should be used as the primary principal for the ccache file
		"""
		c = Credential()
		c.client = Principal.from_asn1(as_rep['cname'], as_rep['crealm'])
		if override_pp == True:
			self.primary_principal = c.client
		c.server = Principal.from_asn1(enc_as_rep_part['sname'], enc_as_rep_part['srealm'])
		c.time = Times.from_asn1(enc_as_rep_part)
		c.key = Keyblock.from_asn1(enc_as_rep_part['key'])
		c.is_skey = 0 #not sure!
		
		c.tktflags = TicketFlags(enc_as_rep_part['flags']).cast(core.IntegerBitString).native
		c.num_address = 0
		c.num_authdata = 0
		c.ticket = CCACHEOctetString.from_asn1(Ticket(as_rep['ticket']).dump())
		c.second_ticket = CCACHEOctetString.empty()
		
		self.credentials.append(c)
		
	def add_tgs(self, tgs_rep, enc_tgs_rep_part, override_pp = False): #from AS_REP
		"""
		Creates credential object from the TGS and adds to the ccache file
		The TGS is the native representation of the asn1 encoded TGS_REP data when the user requests a tgs to a specific service principal with a valid TGT
		
		This function doesn't do decryption of the encrypted part of the tgs_rep object, it is expected that the decrypted XXX is supplied in enc_as_rep_part
		
		override_pp: bool to determine if client principal should be used as the primary principal for the ccache file
		"""
		c = Credential()
		c.client = Principal.from_asn1(tgs_rep['cname'], tgs_rep['crealm'])
		if override_pp == True:
			self.primary_principal = c.client
		c.server = Principal.from_asn1(enc_tgs_rep_part['sname'], enc_tgs_rep_part['srealm'])
		c.time = Times.from_asn1(enc_tgs_rep_part)
		c.key = Keyblock.from_asn1(enc_tgs_rep_part['key'])
		c.is_skey = 0 #not sure!
		
		c.tktflags = TicketFlags(enc_tgs_rep_part['flags']).cast(core.IntegerBitString).native
		c.num_address = 0
		c.num_authdata = 0
		c.ticket = CCACHEOctetString.from_asn1(Ticket(tgs_rep['ticket']).dump())
		c.second_ticket = CCACHEOctetString.empty()
		
		self.credentials.append(c)
	
	"""
	class KrbCredInfo(core.Sequence):
	_fields = [
		('key', EncryptionKey, {'tag_type': TAG, 'tag': 0}),
		('prealm', Realm, {'tag_type': TAG, 'tag': 1, 'optional': True}),
		('pname', PrincipalName, {'tag_type': TAG, 'tag': 2, 'optional': True}),
		('flags', TicketFlags , {'tag_type': TAG, 'tag': 3, 'optional': True}),
		('authtime', KerberosTime , {'tag_type': TAG, 'tag': 4, 'optional': True}),
		('starttime', KerberosTime , {'tag_type': TAG, 'tag': 5, 'optional': True}),
		('endtime', KerberosTime , {'tag_type': TAG, 'tag': 6, 'optional': True}),
		('renew-till', KerberosTime , {'tag_type': TAG, 'tag': 7, 'optional': True}),
		('srealm', Realm , {'tag_type': TAG, 'tag': 8, 'optional': True}),
		('sname', PrincipalName , {'tag_type': TAG, 'tag': 9, 'optional': True}),
		('caddr', HostAddresses , {'tag_type': TAG, 'tag': 10, 'optional': True}),
	]
	
	class EncKrbCredPart(core.Sequence):
	explicit = (APPLICATION, 29)
	_fields = [
		('ticket-info', SequenceOfKrbCredInfo, {'tag_type': TAG, 'tag': 0}),
		('nonce', krb5int32, {'tag_type': TAG, 'tag': 1, 'optional': True}),
		('timestamp', KerberosTime , {'tag_type': TAG, 'tag': 2, 'optional': True}),
		('usec', krb5int32 , {'tag_type': TAG, 'tag': 3, 'optional': True}),
		('s-address', HostAddress , {'tag_type': TAG, 'tag': 4, 'optional': True}),
		('r-address', HostAddress , {'tag_type': TAG, 'tag': 5, 'optional': True}),
	]
	
	
	class KRBCRED(core.Sequence):
	explicit = (APPLICATION, 22)
	
	_fields = [
		('pvno', core.Integer, {'tag_type': TAG, 'tag': 0}),
		('msg-type', core.Integer, {'tag_type': TAG, 'tag': 1}),
		('tickets', SequenceOfTicket, {'tag_type': TAG, 'tag': 2}),
		('enc-part', EncryptedData , {'tag_type': TAG, 'tag': 3}),
	
	]
	"""
		
	def add_kirbi(self, krbcred, override_pp = True):
		c = Credential()
		enc_credinfo = EncKrbCredPart.load(krbcred['enc-part']['cipher']).native
		ticket_info = enc_credinfo['ticket-info'][0]
		
		c.client = Principal.from_asn1(ticket_info['pname'], ticket_info['prealm'])
		if override_pp == True:
			self.primary_principal = c.client
		c.server = Principal.from_asn1(ticket_info['sname'], ticket_info['srealm'])
		c.time = Times.from_asn1(ticket_info)
		c.key = Keyblock.from_asn1(ticket_info['key'])
		c.is_skey = 0 #not sure!
		
		c.tktflags = TicketFlags(ticket_info['flags']).cast(core.IntegerBitString).native
		c.num_address = 0
		c.num_authdata = 0
		c.ticket = CCACHEOctetString.from_asn1(Ticket(krbcred['tickets'][0]).dump()) #kirbi only stores one ticket per file
		c.second_ticket = CCACHEOctetString.empty()
		
		input('server: %s' % c.server)
		self.credentials.append(c)
		
		
	def from_kirbi(kirbidata):
		kirbi = KRBCRED.load(kirbidata).native
		cc = CCACHE()
		cc.add_kirbi(kirbi)		
		return cc
		
	def to_kirbi(self):
		#TODO
		pass
		
		
	def parse(reader):
		c = CCACHEFile()
		c.file_format_version = int.from_bytes(reader.read(2), byteorder='big', signed=False)
		c.headerlen = int.from_bytes(reader.read(2), byteorder='big', signed=False)
		for i in range(c.headerlen):
			c.headers.append(Header.parse(reader))
		c.primary_principal = Principal.parse(reader)
		pos = reader.tell()
		reader.seek(-1,2)
		eof = reader.tell()
		reader.seek(pos,0)
		while reader.tell() != eof:
			self.credentials.append(Credential.parse(reader))
		
		return c
		
	def to_bytes(self):
		t = self.file_format_version.to_bytes(2, byteorder='big', signed=False)
		t += self.headerlen.to_bytes(2, byteorder='big', signed=False)
		for header in self.headers:
			t += header.to_bytes()
		t += self.primary_principal.to_bytes()
		for cred in self.credentials:
			t += cred.to_bytes()
		return t
		
	def from_kirbifile(kirbi_filename):
		kf_abs = os.path.abspath(kirbi_filename)
		kirbidata = None
		with open(kf_abs, 'rb') as f:
			kirbidata = f.read()
			
		return CCACHE.from_kirbi(kirbidata)
		
	def from_kirbidir(directory_path):
		cc = CCACHE()
		dir_path = os.path.join(os.path.abspath(directory_path), '*.kirbi')
		for filename in glob.glob(dir_path):
			with open(filename, 'rb') as f:
				kirbidata = f.read()
				kirbi = KRBCRED.load(kirbidata).native
				cc.add_kirbi(kirbi)
		
		return cc
		
	def to_kirbifile(self, outfilename):
		kf_abs = os.path.abspath(outfilename)
		with open(kf_abs, 'wb') as o:
			o.write(self.to_kirbi())
		
	def from_file(filename):
		with open(filename, 'rb') as f:
			return CCACHEFile.parse(f)
			
	def to_file(self, filename):
		with open(filename, 'wb') as f:
			f.write(self.to_bytes())
		
