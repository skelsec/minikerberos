
# Kudos:
# Parts of this code was inspired by the following project by @rubin_mor
# https://github.com/morRubin/AzureADJoinedMachinePTC
# 


from ctypes import GetLastError
from minikerberos.common.windows.defines import *

CMSG_DATA = 1
CMSG_SIGNED =  2
CMSG_ENVELOPED =  3
CMSG_SIGNED_AND_ENVELOPED = 4
CMSG_HASHED = 5

CMSG_TYPE_PARAM = 1
CMSG_CONTENT_PARAM = 2
CMSG_BARE_CONTENT_PARAM = 3
CMSG_INNER_CONTENT_TYPE_PARAM = 4
CMSG_SIGNER_COUNT_PARAM = 5
CMSG_SIGNER_INFO_PARAM = 6
CMSG_SIGNER_CERT_INFO_PARAM = 7
CMSG_SIGNER_HASH_ALGORITHM_PARAM = 8
CMSG_SIGNER_AUTH_ATTR_PARAM = 9
CMSG_SIGNER_UNAUTH_ATTR_PARAM = 10
CMSG_CERT_COUNT_PARAM = 11
CMSG_CERT_PARAM = 12
CMSG_CRL_COUNT_PARAM = 13
CMSG_CRL_PARAM = 14
CMSG_ENVELOPE_ALGORITHM_PARAM = 15
CMSG_RECIPIENT_COUNT_PARAM = 17
CMSG_RECIPIENT_INDEX_PARAM = 18
CMSG_RECIPIENT_INFO_PARAM = 19
CMSG_HASH_ALGORITHM_PARAM = 20
CMSG_HASH_DATA_PARAM = 21
CMSG_COMPUTED_HASH_PARAM = 22
CMSG_ENCRYPT_PARAM = 26


X509_ASN_ENCODING = 0x00000001
X509_NDR_ENCODING = 0x00000002
PKCS_7_ASN_ENCODING = 0x00010000
PKCS_7_NDR_ENCODING = 0x00020000

CMSG_CMS_ENCAPSULATED_CONTENT_FLAG = 0x00000040

CRYPT_ACQUIRE_CACHE_FLAG = 0x00000001
CRYPT_ACQUIRE_USE_PROV_INFO_FLAG = 0x00000002
CRYPT_ACQUIRE_COMPARE_KEY_FLAG = 0x00000004
CRYPT_ACQUIRE_NO_HEALING = 0x00000008
CRYPT_ACQUIRE_SILENT_FLAG = 0x00000040
CRYPT_ACQUIRE_NCRYPT_KEY_FLAGS_MASK = 0x00070000
CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG = 0x00010000
CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG = 0x00020000
CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG = 0x00040000

HCRYPTMSG = HANDLE
HCERTSTORE = HANDLE
HCRYPTPROV_OR_NCRYPT_KEY_HANDLE = HANDLE
PHCRYPTPROV_OR_NCRYPT_KEY_HANDLE = POINTER(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE)

class FILETIME(Structure):
	_fields_ = [
		('dwLowDateTime', DWORD),
		('dwHighDateTime', DWORD),
	]


class CRYPTOAPI_BLOB(Structure):
	_fields_ = [
		('cbData', DWORD),
		('pbData', LPBYTE),
	]

	@staticmethod
	def get_empty():
		t = CRYPTOAPI_BLOB()
		t.cbData = 0
		t.pbData = None
		return t

CRYPT_INTEGER_BLOB = CRYPTOAPI_BLOB
CERT_NAME_BLOB = CRYPTOAPI_BLOB
CRL_BLOB = CRYPTOAPI_BLOB
PCRL_BLOB = POINTER(CRL_BLOB)
CERT_BLOB = CRYPTOAPI_BLOB
PCERT_BLOB = POINTER(CERT_BLOB)
CRYPT_BIT_BLOB = CRYPTOAPI_BLOB
CRYPT_OBJID_BLOB = CRYPTOAPI_BLOB
CRYPT_HASH_BLOB = CRYPTOAPI_BLOB
PCRYPT_ATTR_BLOB = POINTER(CRYPTOAPI_BLOB)

class CRYPT_ALGORITHM_IDENTIFIER(Structure):
	_fields_ = [
		('pszObjId', LPSTR),
		('Parameters', CRYPT_OBJID_BLOB),
	]

class CRYPT_ATTRIBUTE(Structure):
	_fields_ = [
		("pszObjId", LPSTR),
		("cValue",   DWORD),
		("rgValue",  PCRYPT_ATTR_BLOB),
	]
PCRYPT_ATTRIBUTE = POINTER(CRYPT_ATTRIBUTE)

class CERT_PUBLIC_KEY_INFO(Structure):
	_fields_ = [
		('Algorithm', CRYPT_ALGORITHM_IDENTIFIER),
		('PublicKey', CRYPT_BIT_BLOB),
	]

class CERT_EXTENSION(Structure):
	_fields_ = [
		('pszObjId', LPSTR),
		('fCritical', BOOL),
		('Value', CRYPT_OBJID_BLOB),
	]

class CERT_ISSUER_SERIAL_NUMBER(Structure):
	_fields_ = [
		("Issuer", CERT_NAME_BLOB),
		("SerialNumber", CRYPT_INTEGER_BLOB),
	]
PCERT_ISSUER_SERIAL_NUMBER = POINTER(CERT_ISSUER_SERIAL_NUMBER)

class TMPUNION_CERT_ID(Union):
	_fields_ = [
		("IssuerSerialNumber", CERT_ISSUER_SERIAL_NUMBER),
		("KeyId", CRYPT_HASH_BLOB),
		("HashId", CRYPT_HASH_BLOB),
	]
PTMPUNION_CERT_ID = POINTER(TMPUNION_CERT_ID)

class CERT_ID(Structure):
	_fields_ = [
		("dwIdChoice",     DWORD),
		("DUMMYUNIONNAME", TMPUNION_CERT_ID),
	]
PCERT_ID = POINTER(CERT_ID)

PCERT_EXTENSION  = POINTER(CERT_EXTENSION)

class CERT_INFO(Structure):
	_fields_ = [
		('dwVersion',          DWORD),
		('SerialNumber',       CRYPT_INTEGER_BLOB),
		('SignatureAlgorithm', CRYPT_ALGORITHM_IDENTIFIER),
		('Issuer',             CERT_NAME_BLOB),
		('NotBefore',          FILETIME),
		('NotAfter',           FILETIME),
		('Subject',            CERT_NAME_BLOB),
		('SubjectPublicKeyInfo',  CERT_PUBLIC_KEY_INFO),
		('IssuerUniqueId',     CRYPT_BIT_BLOB),
		('SubjectUniqueId',    CRYPT_BIT_BLOB),
		('cExtension',         DWORD),
		('rgExtension',        PCERT_EXTENSION),
	]
PCERT_INFO  = POINTER(CERT_INFO)


HCRYPTPROV = HANDLE
NCRYPT_KEY_HANDLE = HANDLE

class CMSG_SIGNER_ENCODE_INFO_UNION(Union):
	_fields_ = [
		("hCryptProv", HCRYPTPROV),
		("hNCryptKey", NCRYPT_KEY_HANDLE)
]
PCMSG_SIGNER_ENCODE_INFO_UNION = POINTER(CMSG_SIGNER_ENCODE_INFO_UNION)

class DUMMYUNIONNAME(ctypes.Union):
	_fields_ = [
		("hCryptProv", HCRYPTPROV),
		("hNCryptKey", NCRYPT_KEY_HANDLE)]

class CMSG_SIGNER_ENCODE_INFO(Structure):
	#_anonymous_ = ("u",)
	_fields_ = [
		('cbSize',        DWORD),
		('pCertInfo',     PCERT_INFO),
		('DUMMYUNIONNAME', LPVOID), # CMSG_SIGNER_ENCODE_INFO_UNION
		('dwKeySpec',     DWORD),
		('HashAlgorithm', CRYPT_ALGORITHM_IDENTIFIER ),
		('pvHashAuxInfo', PVOID),
		('cAuthAttr',     DWORD),
		('rgAuthAttr',    PCRYPT_ATTRIBUTE),
		('cUnauthAttr',   DWORD),
		('rgUnauthAttr',  PCRYPT_ATTRIBUTE),
		('SignerId',      CERT_ID),
		#('HashEncryptionAlgorithm', CRYPT_ALGORITHM_IDENTIFIER),
		#('pvHashEncryptionAuxInfo', PVOID),
	]
PCMSG_SIGNER_ENCODE_INFO  = POINTER(CMSG_SIGNER_ENCODE_INFO)


class CMSG_SIGNED_ENCODE_INFO(Structure):
	_fields_ = [
		("cbSize", DWORD),
		("cSigners", DWORD),
		("rgSigners", PCMSG_SIGNER_ENCODE_INFO),
		("cCertEncoded", DWORD),
		("rgCertEncoded", PCERT_BLOB),
		("cCrlEncoded", DWORD),
		("rgCrlEncoded", PCRL_BLOB),
		("cAttrCertEncoded", DWORD),
		("rgAttrCertEncoded", PCERT_BLOB),
	
	]
PCMSG_SIGNED_ENCODE_INFO = POINTER(CMSG_SIGNED_ENCODE_INFO)
PPCMSG_SIGNED_ENCODE_INFO = POINTER(PCMSG_SIGNED_ENCODE_INFO)

class CERT_CONTEXT(Structure):
	_fields_ = [
		('dwCertEncodingType', DWORD),
		('pbCertEncoded',      LPBYTE),
		('cbCertEncoded',      DWORD),
		('pCertInfo',          PCERT_INFO),
		('hCertStore',         HCERTSTORE),
	]
PCERT_CONTEXT  = POINTER(CERT_CONTEXT)
PCCERT_CONTEXT = PCERT_CONTEXT


class CMSG_STREAM_INFO(Structure):
	_fields_ = [
		("cbContent",       DWORD),
		("pfnStreamOutput", PVOID),
		("pvArg",           PVOID),
	]
PCMSG_STREAM_INFO = POINTER(CMSG_STREAM_INFO)


# https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopensystemstorew
def CertOpenSystemStore(subSystemProtocol = 'MY'):
	_CertOpenSystemStore = windll.crypt32.CertOpenSystemStoreW
	_CertOpenSystemStore.argtypes = [PVOID, LPWSTR]
	_CertOpenSystemStore.restype = HCERTSTORE
	_CertOpenSystemStore.errcheck = RaiseIfZero
	
	handle = _CertOpenSystemStore(None, subSystemProtocol)

	return handle

# https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certclosestore
def CertCloseStore(handle, dwFlags = 0):
	_CertCloseStore = windll.crypt32.CertCloseStore
	_CertCloseStore.argtypes = [HCERTSTORE, DWORD]
	_CertCloseStore.restype = BOOL
	_CertCloseStore.errcheck = RaiseIfZero
	
	handle = _CertCloseStore(handle, dwFlags)

	return handle

def CertFreeCertificateContext(handle):
	_CertFreeCertificateContext = windll.crypt32.CertFreeCertificateContext
	_CertFreeCertificateContext.argtypes = [PCCERT_CONTEXT]
	_CertFreeCertificateContext.restype = BOOL
	
	_CertFreeCertificateContext(handle)

def CertEnumCertificatesInStore(handle, prev_cert_handle = None):
	_CertEnumCertificatesInStore = windll.crypt32.CertEnumCertificatesInStore
	_CertEnumCertificatesInStore.argtypes = [HCERTSTORE, PCCERT_CONTEXT]
	_CertEnumCertificatesInStore.restype = PCCERT_CONTEXT
	#_CertEnumCertificatesInStore.errcheck = RaiseIfZero
	
	handle = _CertEnumCertificatesInStore(handle, prev_cert_handle)

	return handle

def CryptAcquireCertificatePrivateKey(handle, dwFlags = CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG):
	_CryptAcquireCertificatePrivateKey = windll.crypt32.CryptAcquireCertificatePrivateKey
	_CryptAcquireCertificatePrivateKey.argtypes = [PCCERT_CONTEXT, DWORD, PVOID, PHCRYPTPROV_OR_NCRYPT_KEY_HANDLE, LPDWORD, LPBOOL]
	_CryptAcquireCertificatePrivateKey.restype = BOOL
	_CryptAcquireCertificatePrivateKey.errcheck = RaiseIfZero

	dwKeySpec = DWORD(0)
	fCallerFreeProvOrNCryptKey = BOOL(0)
	hprov = HANDLE(0)

	_CryptAcquireCertificatePrivateKey(handle, dwFlags, None, byref(hprov), byref(dwKeySpec),  byref(fCallerFreeProvOrNCryptKey))

	return hprov, dwKeySpec, fCallerFreeProvOrNCryptKey


def CryptMsgOpenToEncode(MsgEncodeInfo, dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, dwFlags = CMSG_CMS_ENCAPSULATED_CONTENT_FLAG, dwMsgType = CMSG_SIGNED, InnerContentObjID = b"1.3.6.1.5.2.3.1", StreamInfo = None):
	_CryptMsgOpenToEncode = windll.crypt32.CryptMsgOpenToEncode
	_CryptMsgOpenToEncode.argtypes = [DWORD, DWORD, DWORD, PCMSG_SIGNED_ENCODE_INFO, LPSTR, PCMSG_STREAM_INFO]
	_CryptMsgOpenToEncode.restype = HCRYPTMSG
	_CryptMsgOpenToEncode.errcheck = RaiseIfZero

	if isinstance(InnerContentObjID, str):
		InnerContentObjID = ctypes.create_string_buffer(InnerContentObjID)
	res = _CryptMsgOpenToEncode(dwMsgEncodingType, dwFlags, dwMsgType, byref(MsgEncodeInfo), InnerContentObjID, StreamInfo)

	return res

def CryptMsgUpdate(hCryptMsg, data, fFinal = True):
	_CryptMsgUpdate = windll.crypt32.CryptMsgUpdate
	_CryptMsgUpdate.argtypes = [HCRYPTMSG, PVOID, DWORD, BOOL]
	_CryptMsgUpdate.restype = BOOL
	_CryptMsgUpdate.errcheck = RaiseIfZero

	dlen = len(data)
	data = ctypes.create_string_buffer(data, len(data))
	res = _CryptMsgUpdate(hCryptMsg, data, dlen, fFinal)

	return res

def CryptMsgGetParam(hCryptMsg, ptype, dwIndex = 0):
	_CryptMsgGetParam = windll.crypt32.CryptMsgGetParam
	_CryptMsgGetParam.argtypes = [HCRYPTMSG, DWORD, DWORD, PVOID, LPDWORD]
	_CryptMsgGetParam.restype = BOOL

	
	dlen = DWORD(0)
	res = _CryptMsgGetParam(hCryptMsg, ptype, dwIndex, None, byref(dlen))
	
	data = ctypes.create_string_buffer(dlen.value)
	res = _CryptMsgGetParam(hCryptMsg, ptype, dwIndex, byref(data), byref(dlen))
	if res != True:
		raise ctypes.WinError(GetLastError())

	return data.raw


def get_cert(pccert, native = False):
	from asn1crypto.x509 import Certificate
	cctx = pccert.contents
	cert_data = ctypes.string_at(cctx.pbCertEncoded, cctx.cbCertEncoded)
	if native is False:
		return Certificate.load(cert_data)
	return Certificate.load(cert_data).native

def list_certstore(certstore_name = 'MY'):
	chandle = CertOpenSystemStore(certstore_name)
	hcert = None
	while True:
		hcert = CertEnumCertificatesInStore(chandle, hcert)
		if bool(hcert) is False:
			#null ptr means no more certs
			break

		certificate = get_cert(hcert, True)
		if 'tbs_certificate' in certificate:
			if 'subject' in certificate['tbs_certificate']:
				subject = certificate['tbs_certificate']['subject']#['common_name']
				if isinstance(subject, str):
					subject = [subject]
				print(subject)

		else:
			input('!')
	if bool(hcert) is True:
		CertFreeCertificateContext(hcert)

def find_cert_by_cn(common_name, certstore_name = 'MY'):
	chandle = CertOpenSystemStore(certstore_name)
	hcert = None
	while True:
		hcert = CertEnumCertificatesInStore(chandle, hcert)
		if bool(hcert) is False:
			raise Exception('Couldnt find certificate for %s in certstore %s' % (common_name, certstore_name))
		certificate = get_cert(hcert)
		subject = certificate.subject.native['common_name']
		if isinstance(subject, list):
			for se in subject:
				if se == common_name:
					return certificate, hcert, chandle
		else:
			if subject == common_name:
				return certificate, hcert, chandle

	

def pkcs7_sign(hcert, data):
	hprov, keyspec, to_free = CryptAcquireCertificatePrivateKey(hcert)

	hashalgo = CRYPT_ALGORITHM_IDENTIFIER()
	hashalgo.pszObjId = b"1.3.14.3.2.26" #szOID_OIWSEC_sha1
	hashalgo.Parameters = CRYPTOAPI_BLOB.get_empty()

	Signers = CMSG_SIGNER_ENCODE_INFO()
	Signers.cbSize = ctypes.sizeof(CMSG_SIGNER_ENCODE_INFO)
	Signers.pCertInfo = hcert.contents.pCertInfo
	Signers.DUMMYUNIONNAME = hprov
	Signers.dwKeySpec = keyspec
	Signers.HashAlgorithm = hashalgo
	Signers.pvHashAuxInfo = None
	Signers.cAuthAttr = 0
	Signers.rgAuthAttr = None
	Signers.cUnauthAttr = 0
	Signers.rgUnauthAttr = None

	Certificate = CERT_BLOB()
	Certificate.cbData = hcert.contents.cbCertEncoded
	Certificate.pbData = hcert.contents.pbCertEncoded

	MsgEncodeInfo = CMSG_SIGNED_ENCODE_INFO()
	MsgEncodeInfo.cbSize = ctypes.sizeof(CMSG_SIGNED_ENCODE_INFO)
	MsgEncodeInfo.cSigners = 1
	MsgEncodeInfo.rgSigners = ctypes.pointer(Signers)
	MsgEncodeInfo.cCertEncoded = 1
	MsgEncodeInfo.rgCertEncoded = ctypes.pointer(Certificate)
	MsgEncodeInfo.cCrlEncoded = 0
	MsgEncodeInfo.rgCrlEncoded = None
	MsgEncodeInfo.cAttrCertEncoded  = 0
	MsgEncodeInfo.rgAttrCertEncoded = None

	hmsg = CryptMsgOpenToEncode(MsgEncodeInfo)

	CryptMsgUpdate(hmsg, data, True)
	res = CryptMsgGetParam(hmsg, CMSG_CONTENT_PARAM)
	
	return res
