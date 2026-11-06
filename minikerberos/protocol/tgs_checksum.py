from minikerberos.protocol.encryption import Cksumtype, Enctype, make_checksum


# Session key enctypes for which we have a keyed, collision-proof checksum
# profile suitable for the PA-TGS-REQ authenticator (RFC 4120 7.5.1).
_TGS_CHECKSUM_TYPES = {
    Enctype.AES128: Cksumtype.SHA1_AES128,
    Enctype.AES256: Cksumtype.SHA1_AES256,
    Enctype.DES3: Cksumtype.SHA1_DES3,
    Enctype.RC4: Cksumtype.HMAC_MD5,
}


def tgs_checksum(session_key, body):
    """RFC 4120 section 7.5.1: PA-TGS-REQ checksum uses the TGT session key.

    Returns a dict suitable for ``Checksum(...)``, or ``None`` when the session
    key enctype has no keyed checksum profile (e.g. RC4-MD4 / DES). In that case
    the caller should omit the authenticator checksum entirely, which preserves
    the pre-patch behaviour that Windows KDCs accept.
    """
    checksum_type = _TGS_CHECKSUM_TYPES.get(session_key.enctype)
    if checksum_type is None:
        return None
    return {
        'cksumtype': checksum_type,
        'checksum': make_checksum(checksum_type, session_key, 6, body),
    }
