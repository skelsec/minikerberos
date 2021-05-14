from asn1crypto import core
from asn1crypto.keys import PublicKeyInfo as SubjectPublicKeyInfo
from asn1crypto.x509 import AlgorithmIdentifier
from minikerberos.protocol.asn1_structs import EncryptionKey, Checksum, KerberosTime, PrincipalName, Realm


#### PKINIT ASN1 strructs
#### RFC4556 # https://tools.ietf.org/html/rfc4556 ####

# KerberosV5Spec2 DEFINITIONS EXPLICIT TAGS ::=
TAG = 'explicit'

# class
UNIVERSAL = 0
APPLICATION = 1
CONTEXT = 2

class DHNonce(core.OctetString):
	pass

class AlgorithmIdentifiers(core.SequenceOf):
	_child_spec = AlgorithmIdentifier

class TD_DH_PARAMETERS(core.SequenceOf):
	_child_spec = AlgorithmIdentifier

class ReplyKeyPack(core.Sequence):
	_fields = [
		('replyKey', EncryptionKey, {'tag_type': TAG, 'tag': 0}), 
		('asChecksum', Checksum, {'tag_type': TAG, 'tag': 1}),
		('dhKeyExpiration', KerberosTime, {'tag_type': TAG, 'tag': 2, 'optional': True}),
	]

class KDCDHKeyInfo(core.Sequence):
	_fields = [
		('subjectPublicKey', core.BitString, {'tag_type': TAG, 'tag': 0}), 
		('nonce', core.Integer, {'tag_type': TAG, 'tag': 1}),
		('dhKeyExpiration', KerberosTime, {'tag_type': TAG, 'tag': 2, 'optional': True}),
	]

class DHRepInfo(core.Sequence):
	_fields = [
		('dhSignedData', core.OctetString, {'tag_type': 'implicit', 'tag': 0}), 
		('serverDHNonce', DHNonce, {'tag_type': TAG, 'tag': 1, 'optional': True}),

	]

class PA_PK_AS_REP(core.Choice):
	_alternatives = [
		('dhInfo', DHRepInfo, {'explicit': (CONTEXT,0) }  ),
		('encKeyPack', core.OctetString, {'implicit': (CONTEXT,1) }  ),
	]

class ExternalPrincipalIdentifier(core.Sequence):
	_fields = [
		('subjectName', core.OctetString, {'tag_type': 'implicit', 'tag': 0, 'optional' : True}), 
		('issuerAndSerialNumber', core.OctetString, {'tag_type': 'implicit', 'tag': 1, 'optional' : True}),
		('subjectKeyIdentifier', core.OctetString, {'tag_type': 'implicit', 'tag': 2, 'optional' : True}), 
	]

class ExternalPrincipalIdentifiers(core.SequenceOf):
	_child_spec = ExternalPrincipalIdentifier

class AD_INITIAL_VERIFIED_CAS(core.SequenceOf):
	_child_spec = ExternalPrincipalIdentifier

class KRB5PrincipalName(core.Sequence):
	_fields = [
		('realm', Realm, {'tag_type': TAG, 'tag': 0}), 
		('principalName', PrincipalName, {'tag_type': TAG, 'tag': 1}),
	]

class TD_INVALID_CERTIFICATES(core.SequenceOf):
	_child_spec = ExternalPrincipalIdentifier

class TD_TRUSTED_CERTIFIERS(core.SequenceOf):
	_child_spec = ExternalPrincipalIdentifier

class PKAuthenticator(core.Sequence):
	_fields = [
		('cusec', core.Integer, {'tag_type': TAG, 'tag': 0}), 
		('ctime', KerberosTime, {'tag_type': TAG, 'tag': 1}),
		('nonce', core.Integer, {'tag_type': TAG, 'tag': 2}),
		('paChecksum', core.OctetString, {'tag_type': TAG, 'tag': 3, 'optional': True}),
	]

class AuthPack(core.Sequence):
	_fields = [
		('pkAuthenticator', PKAuthenticator, {'tag_type': TAG, 'tag': 0}), 
		('clientPublicValue', SubjectPublicKeyInfo, {'tag_type': TAG, 'tag': 1, 'optional' : True}),
		('supportedCMSTypes', AlgorithmIdentifiers, {'tag_type': TAG, 'tag': 2, 'optional' : True}), 
		('clientDHNonce', DHNonce, {'tag_type': TAG, 'tag': 3, 'optional' : True}), 

	]

class PA_PK_AS_REQ(core.Sequence):
	_fields = [
		('signedAuthPack', core.OctetString, {'tag_type': 'implicit', 'tag': 0}), 
		('trustedCertifiers', ExternalPrincipalIdentifiers, {'tag_type': TAG, 'tag': 1, 'optional' : True}),
		('kdcPkId', core.OctetString, {'tag_type': 'implicit', 'tag': 2, 'optional' : True}), 
	]


# TODO: figure out what structs these are...

class NameTypeAndValueBMP(core.Sequence):
	_fields = [
		('type', core.ObjectIdentifier),
		('value', core.BMPString),
	]

class Dunno1(core.SetOf):
	_child_spec = NameTypeAndValueBMP

class Dunno2(core.SequenceOf):
	_child_spec = Dunno1

class Info(core.Sequence):
	_fields = [
		('pku2u', core.GeneralString, {'tag_type': TAG, 'tag': 0}),
		('clientInfo', PrincipalName, {'tag_type': TAG, 'tag': 1}),
	]

class CertIssuer(core.Sequence):
	_fields = [
		('data', core.OctetString, {'tag_type': 'implicit', 'tag': 0}), # there is another ASN1 encoded blob here that contains the issuer. Classes X and Y deal with that. No documentation....
	]

class CertIssuers(core.SequenceOf):
	_child_spec = CertIssuer

class MetaData(core.Sequence):
	_fields = [
		('1', CertIssuers, {'tag_type': TAG, 'tag': 0}), 
		('Info', Info, {'tag_type': TAG, 'tag': 1}),
	]