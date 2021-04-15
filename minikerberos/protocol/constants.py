#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import enum

class NAME_TYPE(enum.Enum):
	UNKNOWN = 0     #(0),	-- Name type not known
	PRINCIPAL = 1     #(1),	-- Just the name of the principal as in
	SRV_INST = 2     #(2),	-- Service and other unique instance (krbtgt)
	SRV_HST = 3     #(3),	-- Service with host name as instance
	SRV_XHST = 4     # (4),	-- Service with host as remaining components
	UID = 5     # (5),		-- Unique ID
	X500_PRINCIPAL = 6     #(6), -- PKINIT
	SMTP_NAME = 7     #(7),	-- Name in form of SMTP email name
	ENTERPRISE_PRINCIPAL = 10    #(10), -- Windows 2000 UPN
	WELLKNOWN  = 11    #(11),	-- Wellknown
	ENT_PRINCIPAL_AND_ID  = -130  #(-130), -- Windows 2000 UPN and SID
	MS_PRINCIPAL = -128  #(-128), -- NT 4 style name
	MS_PRINCIPAL_AND_ID = -129  #(-129), -- NT style name and SID
	NTLM = -1200 #(-1200) -- NTLM name, realm is domain

class MESSAGE_TYPE(enum.Enum):
	KRB_AS_REQ = 10 
	KRB_AS_REP = 11 
	KRB_TGS_REQ = 12 
	KRB_TGS_REP = 13 
	KRB_AP_REQ = 14 
	KRB_AP_REP = 15 
	KRB_SAFE = 20 
	KRB_PRIV = 21 
	KRB_CRED = 22 
	KRB_ERROR = 30 

class EncryptionType(enum.Enum):
	NULL = 0#
	DES_CBC_CRC = 1#
	DES_CBC_MD4 = 2#
	DES_CBC_MD5 = 3#
	DES3_CBC_MD5 = 5#
	OLD_DES3_CBC_SHA1 = 7#
	SIGN_DSA_GENERATE = 8#
	ENCRYPT_RSA_PRIV = 9#
	ENCRYPT_RSA_PUB = 10#
	DES3_CBC_SHA1 = 16#	-- with key derivation
	AES128_CTS_HMAC_SHA1_96 = 17#
	AES256_CTS_HMAC_SHA1_96 = 18#
	ARCFOUR_HMAC_MD5 = 23#
	ARCFOUR_HMAC_MD5_56 = 24#
	ENCTYPE_PK_CROSS = 48#
	ARCFOUR_MD4 = -128#
	ARCFOUR_HMAC_OLD = -133#
	ARCFOUR_HMAC_OLD_EXP = -135#
	DES_CBC_NONE = -0x1000#
	DES3_CBC_NONE = -0x1001#
	DES_CFB64_NONE = -0x1002#
	DES_PCBC_NONE = -0x1003#
	DIGEST_MD5_NONE = -0x1004#		-- private use, lukeh@padl.com
	CRAM_MD5_NONE = -0x1005#		-- private use, lukeh@padl.com
	
	
class PaDataType(enum.Enum):
	NONE = 0#
	TGS_REQ = 1#
	AP_REQ = 1#
	ENC_TIMESTAMP = 2#
	PW_SALT = 3#
	ENC_UNIX_TIME = 5#
	SANDIA_SECUREID = 6#
	SESAME = 7#
	OSF_DCE = 8#
	CYBERSAFE_SECUREID = 9#
	AFS3_SALT = 10#
	ETYPE_INFO = 11#
	SAM_CHALLENGE = 12# __  = sam/otp)
	SAM_RESPONSE = 13# __  = sam/otp)
	PK_AS_REQ_19 = 14# __  = PKINIT_19)
	PK_AS_REP_19 = 15# __  = PKINIT_19)
	PK_AS_REQ_WIN = 15# __  = PKINIT _ old number)
	PK_AS_REQ = 16# __  = PKINIT_25)
	PK_AS_REP = 17# __  = PKINIT_25)
	PA_PK_OCSP_RESPONSE = 18#
	ETYPE_INFO2 = 19#
	USE_SPECIFIED_KVNO = 20#
	SVR_REFERRAL_INFO = 20# ___ old ms referral number
	SAM_REDIRECT = 21# __  = sam/otp)
	GET_FROM_TYPED_DATA = 22#
	SAM_ETYPE_INFO = 23#
	SERVER_REFERRAL = 25#
	ALT_PRINC = 24#		__  = crawdad@fnal.gov)
	SAM_CHALLENGE2 = 30#		__  = kenh@pobox.com)
	SAM_RESPONSE2 = 31#		__  = kenh@pobox.com)
	PA_EXTRA_TGT = 41#			__ Reserved extra TGT
	TD_KRB_PRINCIPAL = 102#	__ PrincipalName
	PK_TD_TRUSTED_CERTIFIERS = 104# __ PKINIT
	PK_TD_CERTIFICATE_INDEX = 105# __ PKINIT
	TD_APP_DEFINED_ERROR = 106#	__ application specific
	TD_REQ_NONCE = 107#		__ INTEGER
	TD_REQ_SEQ = 108#		__ INTEGER
	PA_PAC_REQUEST = 128#	__ jbrezak@exchange.microsoft.com
	FOR_USER = 129#		__ MS_KILE
	FOR_X509_USER = 130#		__ MS_KILE
	FOR_CHECK_DUPS = 131#	__ MS_KILE
	AS_CHECKSUM = 132#		__ MS_KILE
	PK_AS_09_BINDING = 132#	__ client send this to __ tell KDC that is supports __ the asCheckSum in the __  PK_AS_REP
	CLIENT_CANONICALIZED = 133#	__ referals
	FX_COOKIE = 133#		__ krb_wg_preauth_framework
	AUTHENTICATION_SET = 134#	__ krb_wg_preauth_framework
	AUTH_SET_SELECTED = 135#	__ krb_wg_preauth_framework
	FX_FAST = 136#		__ krb_wg_preauth_framework
	FX_ERROR = 137#		__ krb_wg_preauth_framework
	ENCRYPTED_CHALLENGE = 138#	__ krb_wg_preauth_framework
	OTP_CHALLENGE = 141#		__  = gareth.richards@rsa.com)
	OTP_REQUEST = 142#		__  = gareth.richards@rsa.com)
	OTP_CONFIRM = 143#		__  = gareth.richards@rsa.com)
	OTP_PIN_CHANGE = 144#	__  = gareth.richards@rsa.com)
	EPAK_AS_REQ = 145#
	EPAK_AS_REP = 146#
	PKINIT_KX = 147#		__ krb_wg_anon
	PKU2U_NAME = 148#		__ zhu_pku2u
	REQ_ENC_PA_REP = 149#	__
	SPAKE = 151#	__https://datatracker.ietf.org/doc/draft-ietf-kitten-krb-spake-preauth/?include_text=1
	SUPPORTED_ETYPES = 165 #)	__ MS_KILE


# Full list of key_usage numbers: https://tools.ietf.org/html/rfc4120#section-7.5.1
# 
class KEY_USAGE(enum.Enum):
	AS_REQ_PA_ENC_TS = 1
	KDC_REP_TICKET = 2
	AS_REP_ENCPART = 3
	TGS_REQ_AD_SESSKEY = 4
	TGS_REQ_AD_SUBKEY = 5
	TGS_REQ_AUTH_CKSUM = 6
	TGS_REQ_AUTH = 7
	TGS_REP_ENCPART_SESSKEY = 8
	TGS_REP_ENCPART_SUBKEY = 9
	AP_REQ_AUTH_CKSUM = 10
	AP_REQ_AUTH = 11
	AP_REP_ENCPART = 12
	KRB_PRIV_ENCPART = 13
	KRB_CRED_ENCPART = 14
	KRB_SAFE_CKSUM = 15
	APP_DATA_ENCRYPT = 16
	APP_DATA_CKSUM = 17
	KRB_ERROR_CKSUM = 18
	AD_KDCISSUED_CKSUM = 19
	AD_MTE = 20
	AD_ITE = 21

	GSS_TOK_MIC = 22
	GSS_TOK_WRAP_INTEG = 23
	GSS_TOK_WRAP_PRIV = 24

	PA_SAM_CHALLENGE_CKSUM = 25
	#PA_SAM_CHALLENGE_TRACKID  26 #/** Note conflict with @ref KRB5_KEYUSAGE_PA_S4U_X509_USER_REQUEST */
	#PA_SAM_RESPONSE           27 #/** Note conflict with @ref KRB5_KEYUSAGE_PA_S4U_X509_USER_REPLY */
	
	PA_S4U_X509_USER_REQUEST = 26 #/* Defined in [MS-SFU] *//** Note conflict with @ref KRB5_KEYUSAGE_PA_SAM_CHALLENGE_TRACKID */
	PA_S4U_X509_USER_REPLY = 27 #/** Note conflict with @ref KRB5_KEYUSAGE_PA_SAM_RESPONSE */

	AD_SIGNEDPATH = -21
	IAKERB_FINISHED = 42
	PA_PKINIT_KX = 44
	PA_OTP_REQUEST = 45 

	FAST_REQ_CHKSUM = 50
	FAST_ENC = 51
	FAST_REP = 52
	FAST_FINISHED = 53
	ENC_CHALLENGE_CLIENT = 54
	ENC_CHALLENGE_KDC = 55
	AS_REQ = 56
	CAMMAC = 64
	SPAKE = 65