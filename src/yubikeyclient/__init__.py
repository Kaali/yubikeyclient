from yubikeyclient.yubico import wsapi


def split_otp(otp):
    """Splits OTP to it's public ID token and AES (modhex) part

    >>> split_otp('vvvvvvvvvvvvfhkjfseiwbwiuhvewivuheihviuhwiuh')
    ('vvvvvvvvvvvv', 'fhkjfseiwbwiuhvewivuheihviuhwiuh')

    """
    return (otp[:-32], otp[-32:])


def verify(otp, api_id, api_key=None):
    """Verify ``otp`` using the default Yubico Web Service API

    API requires ``api_id`` for access.  If ``api_key`` is defined, then the
    verification process is signed and verified with HMAC.

    Returns True if the check was ok otherwise throws ``YubiWsException``

    """
    ws = wsapi.WsApi(wsapi.YUBICO_WS_URL, api_id, api_key)
    return ws.verify(otp)


def query(otp, api_id, api_key=None):
    """Query ``otp`` using the default Yubico Web Service API

    API requires ``api_id`` for access.  If ``api_key`` is defined, then the
    verification process is signed and verified with HMAC.

    Returns the raw status response and doesn't raise ``YubiWsException``'s

    """
    ws = wsapi.WsApi(wsapi.YUBICO_WS_URL, api_id, api_key)
    return ws.query(otp)


