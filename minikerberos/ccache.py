import os
from .asn1_structs import KRBCRED, EncKrbCredPart, TicketFlags, KerberosTicketFlags

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
		self.is_skey = None
		self.tktflags = None
		self.num_address = None
		self.addrs = []
		self.num_authdata = None
		self.authdata = []
		self.ticket = None
		self.second_ticket = None
		
	def from_asn1(ticket, data):
		###
		# data  = KrbCredInfo 
		###
		c = Credential()
		c.client = Principal.from_asn1(data['pname'], data['prealm'])
		c.server = Principal.from_asn1(data['sname'], data['srealm'])
		c.key = Keyblock.from_asn1(data['key'])
		c.is_skey = 0 #not sure!
		
		c.tktflags = KerberosTicketFlags.from_ticketflags(data['flags'])
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
		p.realm = realm
		for comp in principal['name-string']:
			p.components.append(CCACHEOctetString.from_asn1(comp))
			
		return p
		
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
		t += self.realm.encode()
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
	def __init__(self):
		self.filename = None
		self.ccache = None
		
	def from_kirbifile(kirbi_filename, outfilename = None):
		kf_abs = os.path.abspath(kirbi_filename)
		
		cc = CCACHEFile()
		if outfilename:
			cc.filename = outfilename
		else:
			cc.filename = '%s%s' % (kf_abs,'.ccache')
		
		kirbidata = None
		with open(kf_abs, 'rb') as f:
			kirbidata = f.read()
			
		cc.ccache = CCACHE.from_kirbi(kirbidata)
		
		with open(cc.filename, 'wb') as o:
			o.write(cc.ccache.to_bytes())
		
		
class CCACHE:
	def __init__(self):
		self.file_format_version = None #0x0504
		self.headerlen = None
		self.headers = []
		self.primary_principal = None
		self.credentials = []
		
	def create_empty():
		cc = CCACHE()
		cc.file_format_version = 0x0504
		cc.headerlen = 1
		header = Header()
		header.tag = 1
		header.taglen = 8
		header.tagdata = b'\xff\xff\xff\xff\x00\x00\x00\x00'
		cc.headers.append(header)
		
		return cc
		
	def from_kirbi(kirbidata):
		kirbi = KRBCRED.load(kirbidata)
		#input(kirbi.native)
		cc = CCACHE.create_empty()
		#input(kirbi.native['pvno'])
		
		ticket = kirbi.native['tickets'][0]
		
		#decryption is not necessary, because kirbi formats are plaintext
		enc_data = kirbi.native['enc-part']['cipher']
		dec_data = enc_data
		
		t = EncKrbCredPart.load(dec_data).native['ticket-info']
		krbcred = t[0] # kirbi only puts one krbcred here
		#input(krbcred)
		cred = Credential.from_asn1(ticket, krbcred)		
		cc.credentials.append(cred)
		
		cc.primary_principal = cred.client
		
		return cc
		
		
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
		
	def from_file(filename):
		with open(filename, 'rb') as f:
			return CCACHEFile.parse(f)
			
	def to_file(self, filename):
		with open(filename, 'wb') as f:
			f.write(self.to_bytes())
		
