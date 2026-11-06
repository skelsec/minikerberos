from minikerberos.protocol.encryption import Cksumtype, Enctype, make_checksum


def tgs_checksum(session_key, body):
    """RFC 4120 section 7.5.1: PA-TGS-REQ checksum uses the TGT session key."""
    checksum_types = {
        Enctype.AES128: Cksumtype.SHA1_AES128,
        Enctype.AES256: Cksumtype.SHA1_AES256,
        Enctype.DES3: Cksumtype.SHA1_DES3,
        Enctype.RC4: Cksumtype.HMAC_MD5,
    }
    try:
        checksum_type = checksum_types[session_key.enctype]
    except KeyError:
        raise ValueError(
            'Unsupported TGS session key enctype: %s' % session_key.enctype
        ) from None
    return {
        'cksumtype': checksum_type,
        'checksum': make_checksum(checksum_type, session_key, 6, body),
    }
