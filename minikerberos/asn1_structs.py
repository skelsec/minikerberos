#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

from asn1crypto import core
import enum
import os

# KerberosV5Spec2 DEFINITIONS EXPLICIT TAGS ::=
TAG = 'explicit'

# class
APPLICATION = 1


class Microseconds(core.Integer):
	"""    ::= INTEGER (0..999999)
	-- microseconds
    """      
class Int32(core.Integer):
    """Int32 ::= INTEGER (-2147483648..2147483647)
    """


class UInt32(core.Integer):
    """UInt32 ::= INTEGER (0..4294967295)
    """

class KerberosString(core.GeneralString):
	"""KerberosString ::= GeneralString (IA5String)
	For compatibility, implementations MAY choose to accept GeneralString
	values that contain characters other than those permitted by
	IA5String...
	"""
	
class HostAddress(core.Sequence):
    """HostAddress for HostAddresses
    HostAddress ::= SEQUENCE {
        addr-type        [0] Int32,
        address  [1] OCTET STRING
    }
    """
    _fields = [
        ('addr-type', Int32, {'tag_type': TAG, 'tag': 0}),
        ('address', core.OctetString, {'tag_type': TAG, 'tag': 1}),
]

class SequenceOfHostAddress(core.SequenceOf):
	"""SEQUENCE OF HostAddress
	"""
	_child_spec = HostAddress
	
class SequenceOfKerberosString(core.SequenceOf):
	"""SEQUENCE OF KerberosString
	"""
	_child_spec = KerberosString

# https://github.com/tiran/kkdcpasn1/blob/asn1crypto/pykkdcpasn1.py
class Realm(KerberosString):
	"""Realm ::= KerberosString
	"""

# https://github.com/tiran/kkdcpasn1/blob/asn1crypto/pykkdcpasn1.py
class PrincipalName(core.Sequence):
	"""PrincipalName for KDC-REQ-BODY and Ticket
	PrincipalName ::= SEQUENCE {
		name-type	[0] Int32,
		name-string  [1] SEQUENCE OF KerberosString
	}
	"""
	_fields = [
		('name-type', Int32, {'tag_type': TAG, 'tag': 0}),
		('name-string', SequenceOfKerberosString, {'tag_type': TAG, 'tag': 1}),
]

# https://github.com/tiran/kkdcpasn1/blob/asn1crypto/pykkdcpasn1.py
class EncryptedData(core.Sequence):
	"""EncryptedData
	* KDC-REQ-BODY
	* Ticket
	* AP-REQ
	* KRB-PRIV
	EncryptedData ::= SEQUENCE {
		etype		[0] Int32,
		kvno		 [1] UInt32 OPTIONAL,
		cipher	   [2] OCTET STRING
	}
	"""
	_fields = [
		('etype', Int32, {'tag_type': TAG, 'tag': 0}),
		('kvno', UInt32, {'tag_type': TAG, 'tag': 1, 'optional': True}),
		('cipher', core.OctetString, {'tag_type': TAG, 'tag': 2}),
]

class EncryptionKey(core.Sequence):
	"""
	EncryptionKey ::= SEQUENCE {
	keytype[0]		krb5int32,
	keyvalue[1]		OCTET STRING
	}
	"""
	_fields = [
		('keytype', Int32, {'tag_type': TAG, 'tag': 0}),
		('keyvalue', core.OctetString, {'tag_type': TAG, 'tag': 1}),
]

# https://github.com/tiran/kkdcpasn1/blob/asn1crypto/pykkdcpasn1.py
class Ticket(core.Sequence):
	"""Ticket for AP-REQ and SEQUENCE OF Ticket

	Ticket ::= [APPLICATION 1] SEQUENCE {
		tkt-vno	  [0] INTEGER,
		realm		[1] Realm,
		sname		[2] PrincipalName,
		enc-part	 [3] EncryptedData
	}
	"""
	#explicit_class = APPLICATION
	#explicit_tag = 1
	#tag_type = TAG
	#explicit = (1, 1)
	explicit = (1,1)
	
	_fields = [
		('tkt-vno', core.Integer, {'tag_type': TAG, 'tag': 0}),
		('realm', Realm, {'tag_type': TAG, 'tag': 1}),
		('sname', PrincipalName, {'tag_type': TAG, 'tag': 2}),
		('enc-part', EncryptedData, {'tag_type': TAG, 'tag': 3}),
	]
	

class TicketFlags(core.BitString):
	"""
	TicketFlags ::= BIT STRING {
	reserved(0),
	forwardable(1),
	forwarded(2),
	proxiable(3),
	proxy(4),
	may-postdate(5),
	postdated(6),
	invalid(7),
	renewable(8),
	initial(9),
	pre-authent(10),
	hw-authent(11),
	transited-policy-checked(12),
	ok-as-delegate(13),
	anonymous(14),
	enc-pa-rep(15)
	}
	"""
	_map = {
		0: 'reserved',
		1: 'forwardable',
		2: 'forwarded',
		3: 'proxiable',
		4: 'proxy',
		5: 'may-postdate',
		6: 'postdated',
		7: 'invalid',
		8: 'renewable',
		9: 'initial',
		10: 'pre_authent',
		11: 'hw_authent',
		12: 'transited_policy_checked',
		13: 'ok_as_delegate',
		14: 'anonymous',
		15: 'enc_pa_rep',
	}
	

class KerberosTicketFlags(enum.IntFlag):
	reserved = 1
	forwardable = 2
	forwarded = 4
	proxiable = 8
	proxy = 16
	may_postdate = 32
	postdated = 64
	invalid = 128
	renewable = 256
	initial = 512
	pre_authent = 1024
	hw_authent = 2048
	transited_policy_checked = 4096
	ok_as_delegate = 8192
	anonymous = 16384
	enc_pa_rep = 32768
	
	def from_ticketflags(tf):
		#I know this is ugly as hell, but I could get the int value out of TicketFlags
		o = 0
		for i in tf:
			o |= KerberosTicketFlags[i.replace('-','_')]
		return o

class KerberosTime(core.GeneralizedTime):
    """KerberosTime ::= GeneralizedTime
    """


class SequenceOfTicket(core.SequenceOf):
	"""SEQUENCE OF Ticket for KDC-REQ-BODY
	"""
	_child_spec = Ticket


class SequenceOfInt32(core.SequenceOf):
	"""SEQUENCE OF Int32 for KDC-REQ-BODY
	"""
	_child_spec = Int32

# http://web.mit.edu/freebsd/head/crypto/heimdal/lib/asn1/krb5.asn1
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
		('caddr', SequenceOfHostAddress , {'tag_type': TAG, 'tag': 10, 'optional': True}),
	]
	
class SequenceOfKrbCredInfo(core.SequenceOf):
	_child_spec = KrbCredInfo
	
	
class EncKrbCredPart(core.Sequence):
	explicit = (1, 29)
	
	_fields = [
		('ticket-info', SequenceOfKrbCredInfo, {'tag_type': TAG, 'tag': 0}),
		('nonce', Int32, {'tag_type': TAG, 'tag': 1, 'optional': True}),
		('timestamp', KerberosTime , {'tag_type': TAG, 'tag': 2, 'optional': True}),
		('usec', Microseconds , {'tag_type': TAG, 'tag': 3, 'optional': True}),
		('s-address', HostAddress , {'tag_type': TAG, 'tag': 4, 'optional': True}),
		('r-address', HostAddress , {'tag_type': TAG, 'tag': 5, 'optional': True}),
	]
	
class KRBCRED(core.Sequence):
	#explicit_class = APPLICATION
	#explicit_tag = 22
	#tag_type = TAG
	#explicit = (TAG, 22)
	#explicit = (22, 1)
	explicit = (1, 22)
	#class_ = 1
	#tag = 22
	#tag_type = TAG
	
	
	_fields = [
		('pvno', core.Integer, {'tag_type': TAG, 'tag': 0}),
		('msg-type', core.Integer, {'tag_type': TAG, 'tag': 1}),
		('tickets', SequenceOfTicket, {'tag_type': TAG, 'tag': 2}),
		('enc-part', EncryptedData , {'tag_type': TAG, 'tag': 3}),
	
	]
	
class MESSAGE_TYPE(core.Enumerated):
	_map = {
        10: 'krb-as-req',
        11: 'krb-as-rep',
        12: 'krb-tgs-req',
        13: 'krb-tgs-rep',
        14: 'krb-ap-req',
        15: 'krb-ap-rep',
        20: 'krb-safe',
        21: 'krb-priv',
        22: 'krb-cred',
        30: 'krb-error',
	}
"""

MESSAGE-TYPE ::= INTEGER {
	krb-as-req(10), -- Request for initial authentication
	krb-as-rep(11), -- Response to KRB_AS_REQ request
	krb-tgs-req(12), -- Request for authentication based on TGT
	krb-tgs-rep(13), -- Response to KRB_TGS_REQ request
	krb-ap-req(14), -- application request to server
	krb-ap-rep(15), -- Response to KRB_AP_REQ_MUTUAL
	krb-safe(20), -- Safe (checksummed) application message
	krb-priv(21), -- Private (encrypted) application message
	krb-cred(22), -- Private (encrypted) message to forward credentials
	krb-error(30) -- Error response
}
"""
class PA_DATA(core.Sequence):
	_fields = [
		('padata-type', core.Integer, {'tag_type': TAG, 'tag': 0}),
		('padata-value', core.OctetString, {'tag_type': TAG, 'tag': 1}),
	]
"""
PA-DATA ::= SEQUENCE {
	-- might be encoded AP-REQ
	padata-type[1]		PADATA-TYPE,
	padata-value[2]		OCTET STRING
}
"""

class METHOD_DATA(core.SequenceOf):
	_child_spec = PA_DATA
"""
METHOD-DATA ::= SEQUENCE OF PA-DATA

"""

"""
PADATA-TYPE ::= INTEGER {
	KRB5-PADATA-NONE(0),
	KRB5-PADATA-TGS-REQ(1),
	KRB5-PADATA-AP-REQ(1),
	KRB5-PADATA-ENC-TIMESTAMP(2),
	KRB5-PADATA-PW-SALT(3),
	KRB5-PADATA-ENC-UNIX-TIME(5),
	KRB5-PADATA-SANDIA-SECUREID(6),
	KRB5-PADATA-SESAME(7),
	KRB5-PADATA-OSF-DCE(8),
	KRB5-PADATA-CYBERSAFE-SECUREID(9),
	KRB5-PADATA-AFS3-SALT(10),
	KRB5-PADATA-ETYPE-INFO(11),
	KRB5-PADATA-SAM-CHALLENGE(12), -- (sam/otp)
	KRB5-PADATA-SAM-RESPONSE(13), -- (sam/otp)
	KRB5-PADATA-PK-AS-REQ-19(14), -- (PKINIT-19)
	KRB5-PADATA-PK-AS-REP-19(15), -- (PKINIT-19)
	KRB5-PADATA-PK-AS-REQ-WIN(15), -- (PKINIT - old number)
	KRB5-PADATA-PK-AS-REQ(16), -- (PKINIT-25)
	KRB5-PADATA-PK-AS-REP(17), -- (PKINIT-25)
	KRB5-PADATA-PA-PK-OCSP-RESPONSE(18),
	KRB5-PADATA-ETYPE-INFO2(19),
	KRB5-PADATA-USE-SPECIFIED-KVNO(20),
	KRB5-PADATA-SVR-REFERRAL-INFO(20), --- old ms referral number
	KRB5-PADATA-SAM-REDIRECT(21), -- (sam/otp)
	KRB5-PADATA-GET-FROM-TYPED-DATA(22),
	KRB5-PADATA-SAM-ETYPE-INFO(23),
	KRB5-PADATA-SERVER-REFERRAL(25),
	KRB5-PADATA-ALT-PRINC(24),		-- (crawdad@fnal.gov)
	KRB5-PADATA-SAM-CHALLENGE2(30),		-- (kenh@pobox.com)
	KRB5-PADATA-SAM-RESPONSE2(31),		-- (kenh@pobox.com)
	KRB5-PA-EXTRA-TGT(41),			-- Reserved extra TGT
	KRB5-PADATA-TD-KRB-PRINCIPAL(102),	-- PrincipalName
	KRB5-PADATA-PK-TD-TRUSTED-CERTIFIERS(104), -- PKINIT
	KRB5-PADATA-PK-TD-CERTIFICATE-INDEX(105), -- PKINIT
	KRB5-PADATA-TD-APP-DEFINED-ERROR(106),	-- application specific
	KRB5-PADATA-TD-REQ-NONCE(107),		-- INTEGER
	KRB5-PADATA-TD-REQ-SEQ(108),		-- INTEGER
	KRB5-PADATA-PA-PAC-REQUEST(128),	-- jbrezak@exchange.microsoft.com
	KRB5-PADATA-FOR-USER(129),		-- MS-KILE
	KRB5-PADATA-FOR-X509-USER(130),		-- MS-KILE
	KRB5-PADATA-FOR-CHECK-DUPS(131),	-- MS-KILE
	KRB5-PADATA-AS-CHECKSUM(132),		-- MS-KILE
	KRB5-PADATA-PK-AS-09-BINDING(132),	-- client send this to
						-- tell KDC that is supports
						-- the asCheckSum in the
						--  PK-AS-REP
	KRB5-PADATA-CLIENT-CANONICALIZED(133),	-- referals
	KRB5-PADATA-FX-COOKIE(133),		-- krb-wg-preauth-framework
	KRB5-PADATA-AUTHENTICATION-SET(134),	-- krb-wg-preauth-framework
	KRB5-PADATA-AUTH-SET-SELECTED(135),	-- krb-wg-preauth-framework
	KRB5-PADATA-FX-FAST(136),		-- krb-wg-preauth-framework
	KRB5-PADATA-FX-ERROR(137),		-- krb-wg-preauth-framework
	KRB5-PADATA-ENCRYPTED-CHALLENGE(138),	-- krb-wg-preauth-framework
	KRB5-PADATA-OTP-CHALLENGE(141),		-- (gareth.richards@rsa.com)
	KRB5-PADATA-OTP-REQUEST(142),		-- (gareth.richards@rsa.com)
	KBB5-PADATA-OTP-CONFIRM(143),		-- (gareth.richards@rsa.com)
	KRB5-PADATA-OTP-PIN-CHANGE(144),	-- (gareth.richards@rsa.com)
	KRB5-PADATA-EPAK-AS-REQ(145),
	KRB5-PADATA-EPAK-AS-REP(146),
	KRB5-PADATA-PKINIT-KX(147),		-- krb-wg-anon
	KRB5-PADATA-PKU2U-NAME(148),		-- zhu-pku2u
	KRB5-PADATA-REQ-ENC-PA-REP(149),	--
	KRB5-PADATA-SUPPORTED-ETYPES(165)	-- MS-KILE
}
"""
	
class KDC_REP(core.Sequence):
	_fields = [
		('pvno', core.Integer, {'tag_type': TAG, 'tag': 0}),
		('msg-type', MESSAGE_TYPE, {'tag_type': TAG, 'tag': 1}),
		('padata', METHOD_DATA, {'tag_type': TAG, 'tag': 2, 'optional': True}),
		('crealm', Realm , {'tag_type': TAG, 'tag': 3}),
		('cname', PrincipalName , {'tag_type': TAG, 'tag': 3}),
		('ticket', Ticket , {'tag_type': TAG, 'tag': 3}),
		('enc-part', EncryptedData , {'tag_type': TAG, 'tag': 3}),
	
	]
	
class AS_REP(KDC_REP):
	#::= [APPLICATION 11] KDC-REP
	explicit = (1, 11)
	
class TGS_REP(KDC_REP): # ::= [APPLICATION 13] KDC-REP
	explicit = (1, 13)
	
	
class KerberosEncryptonType(enum.Enum):
	#KERB_ETYPE_
	NULL = 0
	DES_CBC_CRC = 1
	DES_CBC_MD4 = 2
	DES_CBC_MD5 = 3
	
	RC4_MD4 = -128
	RC4_PLAIN2 = -129
	RC4_LM = -130
	RC4_SHA = -131
	DES_PLAIN = -132
	RC4_HMAC_OLD = -133
	RC4_PLAIN_OLD = -134
	RC4_HMAC_OLD_EXP = -135
	RC4_PLAIN_OLD_EXP = -136
	RC4_PLAIN = -140
	RC4_PLAIN_EXP = -141
	
	""" WTF is repeating values???
	DSA_SHA1_CMS = 9
	RSA_MD5_CMS = 10
	RSA_SHA1_CMS = 11
	RC2_CBC_ENV = 12
	RSA_ENV = 13
	RSA_ES_OEAP_ENV = 14
	DES_EDE3_CBC_ENV = 15
	
	DSA_SIGN = 8
	RSA_PRIV = 9
	RSA_PUB =  10
	RSA_PUB_MD5 = 11
	RSA_PUB_SHA1 = 12
	PKCS7_PUB = 13
	"""
	DES3_CBC_MD5 =  5
	DES3_CBC_SHA1 = 7
	DES3_CBC_SHA1_KD = 16
	
	DES_CBC_MD5_NT = 20
	RC4_HMAC_NT = 23
	RC4_HMAC_NT_EXP = 24