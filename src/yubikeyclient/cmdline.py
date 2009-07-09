import logging
from optparse import OptionParser
import sys

from yubikeyclient import query


def query_yubico_wsapi():
    usage = "usage: %prog [options] api_id otp"
    parser = OptionParser(usage=usage)
    parser.add_option("-v", "--verboe", action='store_true', dest="verbose",
                      help="Verbose output")
    parser.add_option("-k", "--api-key", dest="api_key", default=None,
                      help="Use API key signature checking (base64 key)")

    (options, args) = parser.parse_args()

    if len(args) != 2:
        parser.print_help()
        sys.exit(-1)

    if options.verbose:
        logging.basicConfig(level=logging.DEBUG)

    api_id, otp = args[:2]
    print query(otp, api_id, api_key=options.api_key)
