import secrets

class UserCredential:
	def __init__(self):
		self.username = None
		self.domain = None
		self.password = None
		self.NT = None
		self.LM = None
		self.kerberos_key_aes_256 = None
		self.kerberos_key_aes_128 = None
		self.kerberos_key_des = None
		self.kerberos_key_rc4 = None
		
class TargetServer:
	def __init__(self):
		self.ip = None
		self.hostname = None
		self.domain = None #the kerberos realm
		self.kerberos_ip = None #IP address of the kerberos server (active directory)

#
#class PADATA_TYPE(enum.Enum):
#	KRB5_PADATA_NONE = 0
#	KRB5_PADATA_TGS_REQ = 1
#	KRB5_PADATA_AP_REQ = 1
#	KRB5_PADATA_ENC_TIMESTAMP = 2
#	KRB5_PADATA_PW_SALT = 3
#	KRB5_PADATA_ENC_UNIX_TIME = 5
#	KRB5_PADATA_SANDIA_SECUREID = 6
#	KRB5_PADATA_SESAME = 7
#	KRB5_PADATA_OSF_DCE = 8
#	KRB5_PADATA_CYBERSAFE_SECUREID = 9
#	KRB5_PADATA_AFS3_SALT = 10
#	KRB5_PADATA_ETYPE_INFO = 11
#	KRB5_PADATA_SAM_CHALLENGE = 12 #  = sam/otp)
#	KRB5_PADATA_SAM_RESPONSE = 13 #  = sam/otp)
#	KRB5_PADATA_PK_AS_REQ_19 = 14 #  = PKINIT_19)
#	KRB5_PADATA_PK_AS_REP_19 = 15 #  = PKINIT_19)
#	KRB5_PADATA_PK_AS_REQ_WIN = 15 #  = PKINIT _ old number)
#	KRB5_PADATA_PK_AS_REQ = 16 #  = PKINIT_25)
#	KRB5_PADATA_PK_AS_REP = 17 #  = PKINIT_25)
#	KRB5_PADATA_PA_PK_OCSP_RESPONSE = 18
#	KRB5_PADATA_ETYPE_INFO2 = 19
#	KRB5_PADATA_USE_SPECIFIED_KVNO = 20
#	KRB5_PADATA_SVR_REFERRAL_INFO = 20 #_ old ms referral number
#	KRB5_PADATA_SAM_REDIRECT = 21 #  = sam/otp)
#	KRB5_PADATA_GET_FROM_TYPED_DATA = 22
#	KRB5_PADATA_SAM_ETYPE_INFO = 23
#	KRB5_PADATA_SERVER_REFERRAL = 25
#	KRB5_PADATA_ALT_PRINC = 24		#  = crawdad@fnal.gov)
#	KRB5_PADATA_SAM_CHALLENGE2 = 30		#  = kenh@pobox.com)
#	KRB5_PADATA_SAM_RESPONSE2 = 31		#  = kenh@pobox.com)
#	KRB5_PA_EXTRA_TGT = 41			# Reserved extra TGT
#	KRB5_PADATA_TD_KRB_PRINCIPAL = 102	# PrincipalName
#	KRB5_PADATA_PK_TD_TRUSTED_CERTIFIERS = 104 # PKINIT
#	KRB5_PADATA_PK_TD_CERTIFICATE_INDEX = 105 # PKINIT
#	KRB5_PADATA_TD_APP_DEFINED_ERROR = 106	# application specific
#	KRB5_PADATA_TD_REQ_NONCE = 107		# INTEGER
#	KRB5_PADATA_TD_REQ_SEQ = 108		# INTEGER
#	KRB5_PADATA_PA_PAC_REQUEST = 128	# jbrezak@exchange.microsoft.com
#	KRB5_PADATA_FOR_USER = 129		# MS_KILE
#	KRB5_PADATA_FOR_X509_USER = 130		# MS_KILE
#	KRB5_PADATA_FOR_CHECK_DUPS = 131	# MS_KILE
#	KRB5_PADATA_AS_CHECKSUM = 132		# MS_KILE
#	KRB5_PADATA_PK_AS_09_BINDING = 132	# client send this to
#						# tell KDC that is supports
#						# the asCheckSum in the
#						#  PK_AS_REP
#	KRB5_PADATA_CLIENT_CANONICALIZED = 133	# referals
#	KRB5_PADATA_FX_COOKIE = 133		# krb_wg_preauth_framework
#	KRB5_PADATA_AUTHENTICATION_SET = 134	# krb_wg_preauth_framework
#	KRB5_PADATA_AUTH_SET_SELECTED = 135	# krb_wg_preauth_framework
#	KRB5_PADATA_FX_FAST = 136		# krb_wg_preauth_framework
#	KRB5_PADATA_FX_ERROR = 137		# krb_wg_preauth_framework
#	KRB5_PADATA_ENCRYPTED_CHALLENGE = 138	# krb_wg_preauth_framework
#	KRB5_PADATA_OTP_CHALLENGE = 141		#  = gareth.richards@rsa.com)
#	KRB5_PADATA_OTP_REQUEST = 142		#  = gareth.richards@rsa.com)
#	KBB5_PADATA_OTP_CONFIRM = 143		#  = gareth.richards@rsa.com)
#	KRB5_PADATA_OTP_PIN_CHANGE = 144	#  = gareth.richards@rsa.com)
#	KRB5_PADATA_EPAK_AS_REQ = 145
#	KRB5_PADATA_EPAK_AS_REP = 146
#	KRB5_PADATA_PKINIT_KX = 147		# krb_wg_anon
#	KRB5_PADATA_PKU2U_NAME = 148		# zhu_pku2u
#	KRB5_PADATA_REQ_ENC_PA_REP = 149	#
#	KRB5_PADATA_SUPPORTED_ETYPES = 165	# MS_KILE
#
#class MessageType(enum.Enum):
#	krb_as_req = 10 #Request for initial authentication
#	krb_as_rep = 11 #Response to KRB_AS_REQ request
#	krb_tgs_req = 12 #Request for authentication based on TGT
#	krb_tgs_rep = 13 #Response to KRB_TGS_REQ request
#	krb_ap_req = 14 #application request to server
#	krb_ap_rep = 15 #Response to KRB_AP_REQ_MUTUAL
#	krb_safe = 20 #Safe  = checksummed application message
#	krb_priv = 21 #Private  = encrypted application message
#	krb_cred = 22 #Private  = encrypted message to forward credentials
#	krb_error = 30 #Error response
#	
#class NAME_TYPE(enum.Enum):
#	KRB5_NT_UNKNOWN = 0	# Name type not known
#	KRB5_NT_PRINCIPAL = 1	# Just the name of the principal as in
#	KRB5_NT_SRV_INST = 2	# Service and other unique instance  = krbtgt)
#	KRB5_NT_SRV_HST = 3	# Service with host name as instance
#	KRB5_NT_SRV_XHST = 4	# Service with host as remaining components
#	KRB5_NT_UID = 5		# Unique ID
#	KRB5_NT_X500_PRINCIPAL = 6 # PKINIT
#	KRB5_NT_SMTP_NAME = 7	# Name in form of SMTP email name
#	KRB5_NT_ENTERPRISE_PRINCIPAL = 10 # Windows 2000 UPN
#	KRB5_NT_WELLKNOWN = 11	# Wellknown
#	KRB5_NT_ENT_PRINCIPAL_AND_ID = -130 # Windows 2000 UPN and SID
#	KRB5_NT_MS_PRINCIPAL = -128 # NT 4 style name
#	KRB5_NT_MS_PRINCIPAL_AND_ID = -129 # NT style name and SID
#	KRB5_NT_NTLM = -1200 # NTLM name, realm is domain
#	
#class ENCTYPE(enum.Enum):
#	KRB5_ENCTYPE_NULL = 0
#	KRB5_ENCTYPE_DES_CBC_CRC = 1
#	KRB5_ENCTYPE_DES_CBC_MD4 = 2
#	KRB5_ENCTYPE_DES_CBC_MD5 = 3
#	KRB5_ENCTYPE_DES3_CBC_MD5 = 5
#	KRB5_ENCTYPE_OLD_DES3_CBC_SHA1 = 7
#	KRB5_ENCTYPE_SIGN_DSA_GENERATE = 8
#	KRB5_ENCTYPE_ENCRYPT_RSA_PRIV = 9
#	KRB5_ENCTYPE_ENCRYPT_RSA_PUB = 10
#	KRB5_ENCTYPE_DES3_CBC_SHA1 = 16	# with key derivation
#	KRB5_ENCTYPE_AES128_CTS_HMAC_SHA1_96 = 17
#	KRB5_ENCTYPE_AES256_CTS_HMAC_SHA1_96 = 18
#	KRB5_ENCTYPE_ARCFOUR_HMAC_MD5 = 23
#	KRB5_ENCTYPE_ARCFOUR_HMAC_MD5_56 = 24
#	KRB5_ENCTYPE_ENCTYPE_PK_CROSS = 48
#	# some "old" windows types
#	KRB5_ENCTYPE_ARCFOUR_MD4 = -128
#	KRB5_ENCTYPE_ARCFOUR_HMAC_OLD = -133
#	KRB5_ENCTYPE_ARCFOUR_HMAC_OLD_EXP = -135
#	# these are for Heimdal internal use
#	KRB5_ENCTYPE_DES_CBC_NONE = -0x1000
#	KRB5_ENCTYPE_DES3_CBC_NONE = -0x1001
#	KRB5_ENCTYPE_DES_CFB64_NONE = -0x1002
#	KRB5_ENCTYPE_DES_PCBC_NONE = -0x1003
#	KRB5_ENCTYPE_DIGEST_MD5_NONE = -0x1004		# private use, lukeh@padl.com
#	KRB5_ENCTYPE_CRAM_MD5_NONE = -0x1005		# private use, lukeh@padl.com
#	
#class KerberosTicketFlags(enum.IntFlag):
#	reserved = 1
#	forwardable = 2
#	forwarded = 4
#	proxiable = 8
#	proxy = 16
#	may_postdate = 32
#	postdated = 64
#	invalid = 128
#	renewable = 256
#	initial = 512
#	pre_authent = 1024
#	hw_authent = 2048
#	transited_policy_checked = 4096
#	ok_as_delegate = 8192
#	anonymous = 16384
#	enc_pa_rep = 32768
#	
#	def from_ticketflags(tf):
#		#I know this is ugly as hell, but I could get the int value out of TicketFlags
#		o = 0
#		for i in tf:
#			o |= KerberosTicketFlags[i.replace('-','_')]
#		return o
#	
#class PA_DATA:
#	def __init__(self):
#		self.type = None #PADATA_TYPE
#		self.value = None #byte array
#		
#class PrincipalName:
#	def __init__(self):
#		self.type = None #NAME-TYPE,
#		self.string = None #SEQUENCE OF GeneralString
#		
#class HostAddress
#	def __init__(self):
#		self.type = None
#		self.address = None
#		
#class PA_ENC_TS_ENC:
#	def __init__(self, patimestamp):
#		self.patimestamp = None #KerberosTime, -- client's time
#		self.pausec = None #int32 OPTIONAL
#
#class PA_PAC_REQUEST:
#	def __init__(self, include_pac = True):
#		self.include_pac = include_pac #[0]		BOOLEAN -- Indicates whether the pac should be included or not
#		
#class KDC_REQ_BODY:
#	def __init__(self):
#		self.kdc_options = None #KDCOptions,
#		self.cname = None #PrincipalName OPTIONAL, -- Used only in AS-REQ
#		self.realm = None #Realm,	-- Server's realm -- Also client's in AS-REQ
#		self.sname = None #PrincipalName OPTIONAL,
#		self.from = None #KerberosTime OPTIONAL,
#		self.till = None #KerberosTime OPTIONAL,
#		self.rtime = None #KerberosTime OPTIONAL,
#		self.nonce = None #krb5int32,
#		self.etype = None #SEQUENCE OF ENCTYPE, -- EncryptionType, #-- in preference order
#		self.addresses = None #HostAddresses OPTIONAL,
#		self.enc_authorization_data = None #EncryptedData OPTIONAL, -- Encrypted AuthorizationData encoding
#		self.additional_tickets = None #SEQUENCE OF Ticket OPTIONAL
#		
#	def construct(client, target, etype):
#		krb = KDC_REQ_BODY()
#		krb.kdc_options = KerberosTicketFlags.forwardable | KerberosTicketFlags.proxiable |KerberosTicketFlags.renewable
#		krb.cname = client.to_principal()
#		krb.realm = client.domain
#		krb.sname = target.to_principal()
#		krb.from = datatime.datetime.utcnow()
#		krb.till = datatime.datetime.utcnow()
#		krb.rtime = datatime.datetime.utcnow()
#		krb.nonce = rand.getrandbits(31)
#		krb.etype = etype
#		
#	def to_asn1(self):
#		pass
#	
#class AS_REQ:
#	def __init__(self):
#		self.client = None
#		self.service = None
#		self.ip_list = None
#		
#		self.pvno = None
#		self.msg_type = None
#		self.padata = None
#		self.req_body = None
#		
#
#	def contruct(req_body, enc_timestamp, include_pac = True):
#		asr = AS_REQ()
#		asr.pvno = 5
#		asr.msg_type = MessageType.krb_as_req
#		
#		pac = PA_DATA()
#		pac.type = PADATA_TYPE.KRB5_PADATA_PA_PAC_REQUEST
#		pac.data = PA_PAC_REQUEST(include_pac)
#		
#		enctime = PA_DATA()
#		enctime.type = PADATA_TYPE.KRB5_PADATA_ENC_TIMESTAMP
#		enctime.data = PA_ENC_TS_ENC(enc_timestamp)
#		
#		asr.padata = [pac, enctime]
#		asr.req_body = req_body
#		
#	def to_asn1(self):
#		pass
#		
#