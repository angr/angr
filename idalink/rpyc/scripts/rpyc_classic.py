#!/usr/bin/env python
"""
classic rpyc server (threaded, forking or std) running a SlaveService
usage:
    rpyc_classic.py                         # default settings
    rpyc_classic.py -m forking -p 12345     # custom settings

    # ssl-authenticated server (keyfile and certfile are required)
    rpyc_classic.py --ssl-keyfile keyfile.pem --ssl-certfile certfile.pem --ssl-cafile cafile.pem
"""
import sys
import os
import rpyc
from optparse import OptionParser
from rpyc.utils.server import ThreadedServer, ForkingServer
from rpyc.utils.classic import DEFAULT_SERVER_PORT, DEFAULT_SERVER_SSL_PORT
from rpyc.utils.registry import REGISTRY_PORT
from rpyc.utils.registry import UDPRegistryClient, TCPRegistryClient
from rpyc.utils.authenticators import SSLAuthenticator
from rpyc.lib import setup_logger
from rpyc.core import SlaveService


parser = OptionParser()
parser.add_option("-m", "--mode", action="store", dest="mode", metavar="MODE",
    default="threaded", type="string", help="mode can be 'threaded', 'forking', "
    "or 'stdio' to operate over the standard IO pipes (for inetd, etc.). "
    "Default is 'threaded'")
#
# TCP options
#
parser.add_option("-p", "--port", action="store", dest="port", type="int",
    metavar="PORT", default=None,
    help="specify a different TCP listener port (default = %s, default for SSL = %s)" %
        (DEFAULT_SERVER_PORT, DEFAULT_SERVER_SSL_PORT))
parser.add_option("--host", action="store", dest="host", type="str",
    metavar="HOST", default="", help="specify a different "
    "host to bind to. Default is INADDR_ANY")
parser.add_option("--ipv6", action="store_true", dest="ipv6",
    metavar="HOST", default=False, help="whether to enable ipv6 or not. " 
    "Default is false")
#
# logging
#
parser.add_option("--logfile", action="store", dest="logfile", type="str",
    metavar="FILE", default=None, help="specify the log file to use; the "
    "default is stderr")
parser.add_option("-q", "--quiet", action="store_true", dest="quiet",
    default=False,
    help="quiet mode (no logging). in stdio mode, writes to /dev/null")
#
# SSL
#
parser.add_option("--ssl-keyfile", action="store", dest="ssl_keyfile", metavar="FILENAME",
    default=None, help="the keyfile to use for SSL. required for SSL"
)
parser.add_option("--ssl-certfile", action="store", dest="ssl_certfile", metavar="FILENAME",
    default=None, help="the certificate file to use for SSL. required for SSL"
)
parser.add_option("--ssl-cafile", action="store", dest="ssl_cafile", metavar="FILENAME",
    default=None, help="the certificate authority chain file to use for SSL. "
    "optional, allows client-side authentication"
)
#
# registry
#
parser.add_option("--register", action="store_true", dest="auto_register",
    default=False, help="asks the server to attempt registering with a registry server"
    "By default, the server will not attempt to register")
parser.add_option("--registry-type", action="store", dest="regtype", type="str",
    default="udp", help="can be 'udp' or 'tcp', default is 'udp'")
parser.add_option("--registry-port", action="store", dest="regport", type="int",
    default=REGISTRY_PORT, help="the UDP/TCP port. default is %s" % (REGISTRY_PORT,))
parser.add_option("--registry-host", action="store", dest="reghost", type="str",
    default=None, help="the registry host machine. for UDP, the default is "
    "255.255.255.255; for TCP, a value is required")


def get_options():
    options, args = parser.parse_args()
    if args:
        parser.error("does not take positional arguments: %r" % (args,))

    options.mode = options.mode.lower()

    if options.regtype.lower() == "udp":
        if options.reghost is None:
            options.reghost = "255.255.255.255"
        options.registrar = UDPRegistryClient(ip = options.reghost, port = options.regport)
    elif options.regtype.lower() == "tcp":
        if options.reghost is None:
            parser.error("must specific --registry-host")
        options.registrar = TCPRegistryClient(ip = options.reghost, port = options.regport)
    else:
        parser.error("invalid registry type %r" % (options.regtype,))

    if options.ssl_keyfile or options.ssl_certfile or options.ssl_cafile:
        if not options.ssl_keyfile:
            parser.error("SSL: keyfile required")
        if not options.ssl_certfile:
            parser.error("SSL: certfile required")
        options.authenticator = SSLAuthenticator(options.ssl_keyfile,
            options.ssl_certfile, options.ssl_cafile)
        if not options.port:
            options.port = DEFAULT_SERVER_SSL_PORT
    else:
        options.authenticator = None
        if not options.port:
            options.port = DEFAULT_SERVER_PORT

    options.handler = "serve_%s" % (options.mode,)
    if options.handler not in globals():
        parser.error("invalid mode %r" % (options.mode,))

    return options

def serve_threaded(options):
    setup_logger(options)
    t = ThreadedServer(SlaveService, hostname = options.host,
        port = options.port, reuse_addr = True, ipv6 = options.ipv6,
        authenticator = options.authenticator, registrar = options.registrar,
        auto_register = options.auto_register)
    t.logger.quiet = options.quiet
    if options.logfile:
        t.logger.console = open(options.logfile, "w")
    t.start()

def serve_forking(options):
    setup_logger(options)
    t = ForkingServer(SlaveService, hostname = options.host,
        port = options.port, reuse_addr = True, ipv6 = options.ipv6,
        authenticator = options.authenticator, registrar = options.registrar,
        auto_register = options.auto_register)
    t.logger.quiet = options.quiet
    if options.logfile:
        t.logger.console = open(options.logfile, "w")
    t.start()

def serve_stdio(options):
    origstdin = sys.stdin
    origstdout = sys.stdout
    if options.quiet:
        dev = os.devnull
    elif sys.platform == "win32":
        dev = "con:"
    else:
        dev = "/dev/tty"
    try:
        sys.stdin = open(dev, "r")
        sys.stdout = open(dev, "w")
    except (IOError, OSError):
        sys.stdin = open(os.devnull, "r")
        sys.stdout = open(os.devnull, "w")
    conn = rpyc.classic.connect_pipes(origstdin, origstdout)
    try:
        try:
            conn.serve_all()
        except KeyboardInterrupt:
            print( "User interrupt!" )
    finally:
        conn.close()


def main():
    options = get_options()
    handler = globals()[options.handler]
    handler(options)


if __name__ == "__main__":
    main()

