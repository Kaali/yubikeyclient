import base64
try:
    from hashlib import sha1
except ImportError:
    # Python 2.4 compatibility
    from sha1 import sha as sha1
import hmac
import urllib


YUBICO_WS_URL = 'http://api.yubico.com/wsapi/verify'


def sorted_urlencode(params):
    return urllib.urlencode(sorted(params))


def sign(key, data):
    """base64 encoded SHA1 HMAC signature with ``key`` for ``data``

    Note: data is utf-8 encoded as per Yubico Web Service API.

    """
    h = hmac.new(key, data.encode('utf8'), sha1)
    return base64.b64encode(h.digest())


def parse_response(conn):
    """Parse web service response"""
    response = {}
    for line in conn.readlines():
        try:
            key, value = line.split('=', 1)
            response[key] = value.strip()
        except ValueError:
            # Skip empty lines and lines that aren't valid results
            pass
    return response


def verify_response(api_key, response):
    """Verify web service response"""
    # Remove signature from the response
    r = dict(response)
    del r['h']

    # Convert to HTML query as that is used by Yubico to sign the response
    query = sorted_urlencode(list(r.iteritems()))

    # We unquote it because it's not the HTTP quoted version
    query = urllib.unquote_plus(query)

    return sign(api_key, query) == response['h']


def exception_message(exception):
    errors = {
        'OK': 'The OTP is valid.',
        'BAD_OTP': 'The OTP is invalid format.',
        'REPLAYED_OTP': 'The OTP has already been seen by the service.',
        'BAD_SIGNATURE': 'The HMAC signature verification failed.',
        'MISSING_PARAMETER': 'The request lacks parameter given by key info.',
        'NO_SUCH_CLIENT': 'The request id does not exist.',
        'OPERATION_NOT_ALLOWED': ('The request id is not allowed to verify '
                                  'OTPs.'),
        'BACKEND_ERROR': ('Unexpected error in our server. '
                          'Please contact us if you see this error.')
        }
    try:
        return errors[str(exception)]
    except KeyError, e:
        return ''


class YubiWsException(Exception):
    pass


class WsApi(object):
    """Yubico Web Service API client

    ``url`` -- Web Service URL to call
    ``api_id`` -- API ID for using the service
    ``api_key`` -- Signature key (base64 encoded)

    """

    def __init__(self, url, api_id, api_key=None):
        self.url = url
        self.api_id = api_id
        self.api_key = api_key
        if self.api_key:
            self.api_key_decoded = base64.b64decode(api_key)

    def _verify(self, otp):
        query = sorted_urlencode((('id', self.api_id), ('otp', otp)))

        # If key is provided, then sign the call
        if self.api_key:
            signature = sign(self.api_key_decoded, query)
            query += '&h=%s' % urllib.quote(signature)

        # Send the message and parse results
        try:
            conn = urllib.urlopen(self.url + '?' + query)
            response = parse_response(conn)
        finally:
            conn.close()

        if self.api_key and not verify_response(self.api_key_decoded, response):
            raise YubiWsException('Invalid signature')

        return response

    def verify(self, otp):
        """Verify OTP"""
        status = self._verify(otp)['status']
        if status == 'OK':
            return True
        else:
            raise YubiWsException(status)

    def query(self, otp):
        """Exceptionless version of ``verify``

        Returns the raw status string from the response

        """
        try:
            return self._verify(otp)['status']
        except YubiWsException, e:
            # Only YubiWsException raised by verify
            return 'InvalidSignature'
