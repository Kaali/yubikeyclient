import base64
import datetime
import urllib
import StringIO

from nose.tools import eq_, raises

from yubikeyclient.yubico import wsapi


def working_connect(self, query):
    """Fake working WsApi._connect"""
    # Generate response with UTC ISO timestamp
    now = datetime.datetime.utcnow()
    response = {'t': now.isoformat(), 'status': 'OK'}
    response_query = wsapi.sorted_urlencode(list(response.iteritems()))
    response_query = urllib.unquote_plus(response_query)

    # Generate signature
    if self.api_key:
        api_key = self.api_key_decoded
    else:
        api_key = 'empty'
    signature = wsapi.sign(api_key, response_query)
    response = r'''
h=%s
t=%s
status=%s''' % (signature, response['t'], response['status'])

    return StringIO.StringIO(response)


def failure_connect(self, query):
    """Failing WsApi._connect"""
    now = datetime.datetime.utcnow()
    response = r'''
h=nosignature
t=%s
status=BAD_OTP
''' % now.isoformat()

    return StringIO.StringIO(response.strip())


def test_parse_response():
    response = r'''
invalid line

h=1093u42\$#!%
info=Information goes here
status=OK
'''.strip()
    test = {'h': '1093u42\$#!%',
            'info': 'Information goes here',
            'status': 'OK'}

    parsed = wsapi.parse_response(response)
    eq_(parsed, test)


def test_parse_empty_response():
    response = ''
    parsed = wsapi.parse_response(response)
    eq_(parsed, {})


def test_verify_response_dict():
    # NOTE: This test mostly just duplicates what verify_response_dict does,
    #       maybe should be removed.
    response = {'info': 'foo bar', 'status': 'OK'}

    key = 'foo'
    query = wsapi.sorted_urlencode(list(response.iteritems()))
    query = urllib.unquote_plus(query)
    signature = wsapi.sign(key, query)
    response['h'] = signature

    assert wsapi.verify_response_dict(key, response)


# TODO: The following two methods are a bit lazy, as they test two different
#       WsApi calls.
def test_working_wsapi():
    api_key = base64.b64encode('foo')
    old_connect = wsapi.WsApi._connect
    wsapi.WsApi._connect = working_connect

    try:
        ws = wsapi.WsApi('fake', '1234', api_key)
        eq_(ws.verify('otp'), True)
        eq_(ws.query('otp'), 'OK')
    finally:
        wsapi.WsApi._connect = old_connect


@raises(wsapi.YubiWsException)
def test_failure_wsapi():
    old_connect = wsapi.WsApi._connect
    wsapi.WsApi._connect = failure_connect

    try:
        ws = wsapi.WsApi('fake', '1234')
        eq_(ws.query('otp'), 'BAD_OTP')
        ws.verify('otp')
    finally:
        wsapi.WsApi._connect = old_connect
