
from asn1crypto import core
from minikerberos.protocol.asn1_structs import Checksum

# GSS_EXTS_FINISHED             2 #Data type for the IAKERB checksum.
# corresponding checksum type: KEY_USAGE_FINISHED            41
# https://tools.ietf.org/html/draft-ietf-kitten-iakerb-03


TAG = 'explicit'

class KRB_FINISHED(core.Sequence):
    _fields = [
        ('gss-mic', Checksum, {'tag_type': TAG, 'tag': 1}),
    ]

	# Contains the checksum [RFC3961] of the GSS-API tokens
	# exchanged between the initiator and the acceptor,
	# and prior to the containing AP_REQ GSS-API token.
	# The checksum is performed over the GSS-API tokens
	# exactly as they were transmitted and received,
	# in the order that the tokens were sent.


class IAKERB_HEADER(core.Sequence):
    _fields = [
        ('target-realm', core.GeneralString, {'tag_type': TAG, 'tag': 1}),
		('cookie', core.OctetString, {'tag_type': TAG, 'tag': 2, 'optional': True}),
    ]