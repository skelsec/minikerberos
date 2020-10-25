#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import enum

class KerberosError(Exception):
	def __init__(self, krb_err_msg, extra_msg = ''):
		self.krb_err_msg = krb_err_msg.native
		self.errorcode = KerberosErrorCode.ERR_NOT_FOUND
		self.errormsg = 'Error code not found! Err code: %s' % self.krb_err_msg['error-code']
		try:
			self.errorcode = KerberosErrorCode(self.krb_err_msg['error-code'])
			self.errormsg = KerberosErrorMessage[self.errorcode.name]
		except:
			pass
		self.extra_msg = extra_msg
		
		super(Exception, self).__init__('%s Error Code: %d Reason: %s ' % (extra_msg, self.errorcode.value, self.errormsg.value))
	
		

# https://technet.microsoft.com/en-us/library/bb463166.aspx
class KerberosErrorCode(enum.Enum):
	ERR_NOT_FOUND = 0xFFFFFF
	KDC_ERR_NONE = 0x0 #No error
	KDC_ERR_NAME_EXP = 0x1 #Client's entry in KDC database has expired
	KDC_ERR_SERVICE_EXP = 0x2 #Server's entry in KDC database has expired
	KDC_ERR_BAD_PVNO = 0x3 #Requested Kerberos version number not supported
	KDC_ERR_C_OLD_MAST_KVNO = 0x4 #Client's key encrypted in old master key
	KDC_ERR_S_OLD_MAST_KVNO = 0x5 #Server's key encrypted in old master key
	KDC_ERR_C_PRINCIPAL_UNKNOWN = 0x6 #Client not found in Kerberos database
	KDC_ERR_S_PRINCIPAL_UNKNOWN = 0x7 #Server not found in Kerberos database
	KDC_ERR_PRINCIPAL_NOT_UNIQUE = 0x8 #Multiple principal entries in KDC database
	KDC_ERR_NULL_KEY = 0x9 #The client or server has a null key (master key)
	KDC_ERR_CANNOT_POSTDATE = 0xA # Ticket (TGT) not eligible for postdating
	KDC_ERR_NEVER_VALID = 0xB # Requested start time is later than end time
	KDC_ERR_POLICY = 0xC #Requested start time is later than end time
	KDC_ERR_BADOPTION = 0xD #KDC cannot accommodate requested option
	KDC_ERR_ETYPE_NOTSUPP = 0xE # KDC has no support for encryption type
	KDC_ERR_SUMTYPE_NOSUPP = 0xF # KDC has no support for checksum type
	KDC_ERR_PADATA_TYPE_NOSUPP = 0x10 #KDC has no support for PADATA type (pre-authentication data)
	KDC_ERR_TRTYPE_NO_SUPP = 0x11 #KDC has no support for transited type
	KDC_ERR_CLIENT_REVOKED = 0x12 # Client’s credentials have been revoked
	KDC_ERR_SERVICE_REVOKED = 0x13 #Credentials for server have been revoked
	KDC_ERR_TGT_REVOKED = 0x14 #TGT has been revoked
	KDC_ERR_CLIENT_NOTYET = 0x15 # Client not yet valid—try again later
	KDC_ERR_SERVICE_NOTYET = 0x16 #Server not yet valid—try again later
	KDC_ERR_KEY_EXPIRED = 0x17 # Password has expired—change password to reset
	KDC_ERR_PREAUTH_FAILED = 0x18 #Pre-authentication information was invalid
	KDC_ERR_PREAUTH_REQUIRED = 0x19 # Additional preauthentication required
	KDC_ERR_SERVER_NOMATCH = 0x1A #KDC does not know about the requested server
	KDC_ERR_SVC_UNAVAILABLE = 0x1B # KDC is unavailable
	KRB_AP_ERR_BAD_INTEGRITY = 0x1F # Integrity check on decrypted field failed
	KRB_AP_ERR_TKT_EXPIRED = 0x20 # The ticket has expired
	KRB_AP_ERR_TKT_NYV = 0x21 #The ticket is not yet valid
	KRB_AP_ERR_REPEAT = 0x22 # The request is a replay
	KRB_AP_ERR_NOT_US = 0x23 #The ticket is not for us
	KRB_AP_ERR_BADMATCH = 0x24 #The ticket and authenticator do not match
	KRB_AP_ERR_SKEW = 0x25 # The clock skew is too great
	KRB_AP_ERR_BADADDR = 0x26 # Network address in network layer header doesn't match address inside ticket
	KRB_AP_ERR_BADVERSION = 0x27 # Protocol version numbers don't match (PVNO)
	KRB_AP_ERR_MSG_TYPE = 0x28 # Message type is unsupported
	KRB_AP_ERR_MODIFIED = 0x29 # Message stream modified and checksum didn't match
	KRB_AP_ERR_BADORDER = 0x2A # Message out of order (possible tampering)
	KRB_AP_ERR_BADKEYVER = 0x2C # Specified version of key is not available
	KRB_AP_ERR_NOKEY = 0x2D # Service key not available
	KRB_AP_ERR_MUT_FAIL = 0x2E # Mutual authentication failed
	KRB_AP_ERR_BADDIRECTION = 0x2F # Incorrect message direction
	KRB_AP_ERR_METHOD = 0x30 # Alternative authentication method required
	KRB_AP_ERR_BADSEQ = 0x31 # Incorrect sequence number in message
	KRB_AP_ERR_INAPP_CKSUM = 0x32 # Inappropriate type of checksum in message (checksum may be unsupported)
	KRB_AP_PATH_NOT_ACCEPTED = 0x33 # Desired path is unreachable
	KRB_ERR_RESPONSE_TOO_BIG = 0x34 # Too much data
	KRB_ERR_GENERIC = 0x3C # Generic error; the description is in the e-data field
	KRB_ERR_FIELD_TOOLONG = 0x3D # Field is too long for this implementation
	KDC_ERR_CLIENT_NOT_TRUSTED = 0x3E # The client trust failed or is not implemented
	KDC_ERR_KDC_NOT_TRUSTED = 0x3F # The KDC server trust failed or could not be verified
	KDC_ERR_INVALID_SIG = 0x40 # The signature is invalid
	KDC_ERR_KEY_TOO_WEAK = 0x41 #A higher encryption level is needed
	KRB_AP_ERR_USER_TO_USER_REQUIRED = 0x42# User-to-user authorization is required
	KRB_AP_ERR_NO_TGT  = 0x43 # No TGT was presented or available
	KDC_ERR_WRONG_REALM = 0x44 #Incorrect domain or principal
	
class KerberosErrorMessage(enum.Enum):
	KDC_ERR_NONE = 'No error'
	KDC_ERR_NAME_EXP = 'Client\'s entry in KDC database has expired'
	KDC_ERR_SERVICE_EXP = 'Server\'s entry in KDC database has expired'
	KDC_ERR_BAD_PVNO = 'Requested Kerberos version number not supported'
	KDC_ERR_C_OLD_MAST_KVNO =  'Client\'s key encrypted in old master key'
	KDC_ERR_S_OLD_MAST_KVNO = 'Server\'s key encrypted in old master key'
	KDC_ERR_C_PRINCIPAL_UNKNOWN =  'Client not found in Kerberos database'
	KDC_ERR_S_PRINCIPAL_UNKNOWN = 'Server not found in Kerberos database'
	KDC_ERR_PRINCIPAL_NOT_UNIQUE = 'Multiple principal entries in KDC database'
	KDC_ERR_NULL_KEY = 'The client or server has a null key (master key)'
	KDC_ERR_CANNOT_POSTDATE =  'Ticket (TGT) not eligible for postdating'
	KDC_ERR_NEVER_VALID = 'Requested start time is later than end time'
	KDC_ERR_POLICY = 'Requested start time is later than end time'
	KDC_ERR_BADOPTION = 'KDC cannot accommodate requested option'
	KDC_ERR_ETYPE_NOTSUPP =  'KDC has no support for encryption type'
	KDC_ERR_SUMTYPE_NOSUPP = 'KDC has no support for checksum type'
	KDC_ERR_PADATA_TYPE_NOSUPP =  'KDC has no support for PADATA type (pre-authentication data)'
	KDC_ERR_TRTYPE_NO_SUPP =  'KDC has no support for transited type'
	KDC_ERR_CLIENT_REVOKED ='Client’s credentials have been revoked'
	KDC_ERR_SERVICE_REVOKED =  'Credentials for server have been revoked'
	KDC_ERR_TGT_REVOKED =  'TGT has been revoked'
	KDC_ERR_CLIENT_NOTYET =  'Client not yet valid—try again later'
	KDC_ERR_SERVICE_NOTYET = 'Server not yet valid—try again later'
	KDC_ERR_KEY_EXPIRED =  'Password has expired—change password to reset'
	KDC_ERR_PREAUTH_FAILED = 'Pre-authentication information was invalid'
	KDC_ERR_PREAUTH_REQUIRED =  'Additional preauthentication required'
	KDC_ERR_SERVER_NOMATCH = 'KDC does not know about the requested server'
	KDC_ERR_SVC_UNAVAILABLE = 'KDC is unavailable'
	KRB_AP_ERR_BAD_INTEGRITY =  'Integrity check on decrypted field failed'
	KRB_AP_ERR_TKT_EXPIRED =  'The ticket has expired'
	KRB_AP_ERR_TKT_NYV = 'The ticket is not yet valid'
	KRB_AP_ERR_REPEAT =  'The request is a replay'
	KRB_AP_ERR_NOT_US =  'The ticket is not for us'
	KRB_AP_ERR_BADMATCH =  'The ticket and authenticator do not match'
	KRB_AP_ERR_SKEW =  'The clock skew is too great'
	KRB_AP_ERR_BADADDR =  'Network address in network layer header doesn\'t match address inside ticket'
	KRB_AP_ERR_BADVERSION = 'Protocol version numbers don\'t match (PVNO)'
	KRB_AP_ERR_MSG_TYPE ='Message type is unsupported'
	KRB_AP_ERR_MODIFIED = 'Message stream modified and checksum didn\'t match'
	KRB_AP_ERR_BADORDER = 'Message out of order (possible tampering)'
	KRB_AP_ERR_BADKEYVER =  'Specified version of key is not available'
	KRB_AP_ERR_NOKEY =  'Service key not available'
	KRB_AP_ERR_MUT_FAIL = 'Mutual authentication failed'
	KRB_AP_ERR_BADDIRECTION = 'Incorrect message direction'
	KRB_AP_ERR_METHOD =  'Alternative authentication method required'
	KRB_AP_ERR_BADSEQ = 'Incorrect sequence number in message'
	KRB_AP_ERR_INAPP_CKSUM = 'Inappropriate type of checksum in message (checksum may be unsupported)'
	KRB_AP_PATH_NOT_ACCEPTED = 'Desired path is unreachable'
	KRB_ERR_RESPONSE_TOO_BIG =  'Too much data'
	KRB_ERR_GENERIC =  'Generic error; the description is in the e-data field'
	KRB_ERR_FIELD_TOOLONG =  'Field is too long for this implementation'
	KDC_ERR_CLIENT_NOT_TRUSTED = 'The client trust failed or is not implemented'
	KDC_ERR_KDC_NOT_TRUSTED =  'The KDC server trust failed or could not be verified'
	KDC_ERR_INVALID_SIG = 'The signature is invalid'
	KDC_ERR_KEY_TOO_WEAK = 'A higher encryption level is needed'
	KRB_AP_ERR_USER_TO_USER_REQUIRED ='User-to-user authorization is required'
	KRB_AP_ERR_NO_TGT  ='No TGT was presented or available'
	KDC_ERR_WRONG_REALM = 'Incorrect domain or principal'