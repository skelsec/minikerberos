from unicrypto import hashlib
import datetime
from asn1crypto.core import OrderedDict

from minikerberos.protocol.asn1_structs import EncryptedData, krb5_pvno, \
	PrincipalName, PrincipalName, Realm, Checksum, APOptions, Authenticator,\
	Ticket, AP_REQ

from minikerberos.protocol.encryption import _enctype_table
from minikerberos.protocol.constants import NAME_TYPE, MESSAGE_TYPE
from minikerberos.protocol.structures import AuthenticatorChecksum
from minikerberos.gssapi.channelbindings import ChannelBindingsStruct

def construct_apreq_from_tgs_tgt(tgs, sessionkey, tgt, flags = None, seq_number = 0, ap_opts = [], cb_data = None):
	return construct_apreq_from_tgs(
		tgs,
		sessionkey,
		tgt['crealm'],
		tgt['cname'],
		flags,
		seq_number,
		ap_opts,
		cb_data
	)

def construct_apreq_from_tgs(tgs, sessionkey, crealm, cname, flags = None, seq_number = 0, ap_opts = [], cb_data = None):
	return construct_apreq_from_ticket(
		Ticket(tgs['ticket']).dump(),
		sessionkey,
		crealm,
		cname,
		flags,
		seq_number,
		ap_opts,
		cb_data
	)

def construct_apreq_from_ticket(ticket_data, sessionkey, crealm, cname, flags = None, seq_number = 0, ap_opts = [], cb_data = None):
	now = datetime.datetime.now(datetime.timezone.utc)
	authenticator_data = {}
	authenticator_data['authenticator-vno'] = krb5_pvno
	if isinstance(crealm, Realm):
		authenticator_data['crealm'] = crealm
	else:
		authenticator_data['crealm'] = Realm(crealm)
	
	try:
		authenticator_data['cname'] = PrincipalName(cname)
	except:
		if isinstance(cname, PrincipalName):
			authenticator_data['cname'] = cname
		else:
			authenticator_data['cname'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': [cname]})
	
	authenticator_data['cusec'] = now.microsecond
	authenticator_data['ctime'] = now.replace(microsecond=0)
	if flags is not None:

		ac = AuthenticatorChecksum()
		ac.flags = flags
		ac.channel_binding = b'\x00'*16
		if cb_data is not None:
			cb_struct = ChannelBindingsStruct()
			cb_struct.application_data = cb_data
			ac.channel_binding = hashlib.md5(cb_struct.to_bytes()).digest()

		chksum = {}
		chksum['cksumtype'] = 0x8003
		chksum['checksum'] = ac.to_bytes()

		authenticator_data['cksum'] = Checksum(chksum)
		authenticator_data['seq-number'] = seq_number

	cipher = _enctype_table[sessionkey.enctype]
	authenticator_data_enc = cipher.encrypt(sessionkey, 11, Authenticator(authenticator_data).dump(), None)

	ap_req = {}
	ap_req['pvno'] = krb5_pvno
	ap_req['msg-type'] = MESSAGE_TYPE.KRB_AP_REQ.value
	ap_req['ticket'] = Ticket.load(ticket_data)
	ap_req['ap-options'] = APOptions(set(ap_opts))
	ap_req['authenticator'] = EncryptedData({'etype': sessionkey.enctype, 'cipher': authenticator_data_enc})
	return AP_REQ(ap_req).dump()