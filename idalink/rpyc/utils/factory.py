"""
RPyC connection factories: ease the creation of a connection for the common 
cases)
"""
import socket

import threading
try:
    from thread import interrupt_main
except ImportError:
    try:
        from _thread import interrupt_main
    except ImportError:
        # assume jython (#83)
        from java.lang import System
        interrupt_main = System.exit

from rpyc import Connection, Channel, SocketStream, TunneledSocketStream, PipeStream, VoidService
from rpyc.utils.registry import UDPRegistryClient
from rpyc.lib import safe_import
ssl = safe_import("ssl")


class DiscoveryError(Exception):
    pass


#------------------------------------------------------------------------------
# API
#------------------------------------------------------------------------------
def connect_channel(channel, service = VoidService, config = {}):
    """creates a connection over a given channel
    
    :param channel: the channel to use
    :param service: the local service to expose (defaults to Void)
    :param config: configuration dict

    :returns: an RPyC connection
    """
    return Connection(service, channel, config = config)

def connect_stream(stream, service = VoidService, config = {}):
    """creates a connection over a given stream

    :param stream: the stream to use
    :param service: the local service to expose (defaults to Void)
    :param config: configuration dict
    
    :returns: an RPyC connection
    """
    return connect_channel(Channel(stream), service = service, config = config)

def connect_pipes(input, output, service = VoidService, config = {}):
    """
    creates a connection over the given input/output pipes
    
    :param input: the input pipe
    :param output: the output pipe
    :param service: the local service to expose (defaults to Void)
    :param config: configuration dict
    
    :returns: an RPyC connection
    """
    return connect_stream(PipeStream(input, output), service = service, config = config)

def connect_stdpipes(service = VoidService, config = {}):
    """
    creates a connection over the standard input/output pipes
    
    :param service: the local service to expose (defaults to Void)
    :param config: configuration dict
    
    :returns: an RPyC connection
    """
    return connect_stream(PipeStream.from_std(), service = service, config = config)

def connect(host, port, service = VoidService, config = {}, ipv6 = False):
    """
    creates a socket-connection to the given host and port
    
    :param host: the hostname to connect to
    :param port: the TCP port to use
    :param service: the local service to expose (defaults to Void)
    :param config: configuration dict
    :param ipv6: whether to use IPv6 or not

    :returns: an RPyC connection
    """
    s = SocketStream.connect(host, port, ipv6 = ipv6)
    return connect_stream(s, service, config)
    
def unix_connect(path, service = VoidService, config = {}):
    """
    creates a socket-connection to the given host and port

    :param path: the path to the unix domain socket
    :param service: the local service to expose (defaults to Void)
    :param config: configuration dict

    :returns: an RPyC connection
    """
    s = SocketStream.unix_connect(path)
    return connect_stream(s, service, config)
    
def ssl_connect(host, port, keyfile = None, certfile = None, ca_certs = None,
        cert_reqs = None, ssl_version = None, ciphers = None,
        service = VoidService, config = {}, ipv6 = False):
    """
    creates an SSL-wrapped connection to the given host (encrypted and
    authenticated).
    
    :param host: the hostname to connect to
    :param port: the TCP port to use
    :param service: the local service to expose (defaults to Void)
    :param config: configuration dict
    :param ipv6: whether to create an IPv6 socket or an IPv4 one
    
    The following arguments are passed directly to 
    `ssl.wrap_socket <http://docs.python.org/dev/library/ssl.html#ssl.wrap_socket>`_:
    
    :param keyfile: see ``ssl.wrap_socket``. May be ``None``
    :param certfile: see ``ssl.wrap_socket``. May be ``None``
    :param ca_certs: see ``ssl.wrap_socket``. May be ``None``
    :param cert_reqs: see ``ssl.wrap_socket``. By default, if ``ca_cert`` is specified,
                      the requirement is set to ``CERT_REQUIRED``; otherwise it is 
                      set to ``CERT_NONE``
    :param ssl_version: see ``ssl.wrap_socket``. The default is ``PROTOCOL_TLSv1``
    :param ciphers: see ``ssl.wrap_socket``. May be ``None``. New in Python 2.7/3.2

    :returns: an RPyC connection
    """
    ssl_kwargs = {"server_side" : False}
    if keyfile is not None:
        ssl_kwargs["keyfile"] = keyfile
    if certfile is not None:
        ssl_kwargs["certfile"] = certfile
    if ca_certs is not None:
        ssl_kwargs["ca_certs"] = ca_certs
        ssl_kwargs["cert_reqs"] = ssl.CERT_REQUIRED
    if cert_reqs is not None:
        ssl_kwargs["cert_reqs"] = cert_reqs
    if ssl_version is None:
        ssl_kwargs["ssl_version"] = ssl.PROTOCOL_TLSv1
    else:
        ssl_kwargs["ssl_version"] = ssl_version
    if ciphers is not None:
        ssl_kwargs["ciphers"] = ciphers
    s = SocketStream.ssl_connect(host, port, ssl_kwargs, ipv6 = ipv6)
    return connect_stream(s, service, config)

def _get_free_port():
    """attempts to find a free port"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("localhost", 0))
    _, port = s.getsockname()
    s.close()
    return port

def ssh_connect(sshctx, remote_port, service = VoidService, config = {}):
    """
    Connects to an RPyC server over an SSH tunnel
    
    :param sshctx: an :class:`rpyc.utils.ssh.SshContext` instance
    :param remote_port: the port of the remote server
    :param service: the local service to expose (defaults to Void)
    :param config: configuration dict

    :returns: an RPyC connection
    """
    loc_port = _get_free_port()
    tun = sshctx.tunnel(loc_port, remote_port)
    stream = TunneledSocketStream.connect("localhost", loc_port)
    stream.tun = tun
    return Connection(service, Channel(stream), config = config)

def discover(service_name, host = None, registrar = None, timeout = 2):
    """
    discovers hosts running the given service
    
    :param service_name: the service to look for
    :param host: limit the discovery to the given host only (None means any host)
    :param registrar: use this registry client to discover services. if None,
                      use the default UDPRegistryClient with the default settings.
    :param timeout: the number of seconds to wait for a reply from the registry
                    if no hosts are found, raises DiscoveryError
    
    :raises: ``DiscoveryError`` if no server is found
    :returns: a list of (ip, port) pairs
    """
    if registrar is None:
        registrar = UDPRegistryClient(timeout = timeout)
    addrs = registrar.discover(service_name)
    if not addrs:
        raise DiscoveryError("no servers exposing %r were found" % (service_name,))
    if host:
        ips = socket.gethostbyname_ex(host)[2]
        addrs = [(h, p) for h, p in addrs if h in ips]
    if not addrs:
        raise DiscoveryError("no servers exposing %r were found on %r" % (service_name, host))
    return addrs

def connect_by_service(service_name, host = None, service = VoidService, config = {}):
    """create a connection to an arbitrary server that exposes the requested service
    
    :param service_name: the service to discover
    :param host: limit discovery to the given host only (None means any host)
    :param service: the local service to expose (defaults to Void)
    :param config: configuration dict

    :raises: ``DiscoveryError`` if no server is found
    :returns: an RPyC connection
    """
    host, port = discover(service_name, host = host)[0]
    return connect(host, port, service, config = config)

def connect_subproc(args, service = VoidService, config = {}):
    """runs an rpyc server on a child process that and connects to it over
    the stdio pipes. uses the subprocess module.
    
    :param args: the args to Popen, e.g., ["python", "-u", "myfile.py"]
    :param service: the local service to expose (defaults to Void)
    :param config: configuration dict
    """
    from subprocess import Popen, PIPE
    proc = Popen(args, stdin = PIPE, stdout = PIPE)
    conn = connect_pipes(proc.stdout, proc.stdin, service = service, config = config)
    conn.proc = proc # just so you can have control over the processs
    return conn

def connect_thread(service = VoidService, config = {}, remote_service = VoidService, remote_config = {}):
    """starts an rpyc server on a new thread, bound to an arbitrary port, 
    and connects to it over a socket.
    
    :param service: the local service to expose (defaults to Void)
    :param config: configuration dict
    :param server_service: the remote service to expose (of the server; defaults to Void)
    :param server_config: remote configuration dict (of the server)
    """
    listener = socket.socket()
    listener.bind(("localhost", 0))
    listener.listen(1)

    def server(listener = listener):
        client = listener.accept()[0]
        listener.close()
        conn = connect_stream(SocketStream(client), service = remote_service,
            config = remote_config)
        try:
            conn.serve_all()
        except KeyboardInterrupt:
            interrupt_main()

    t = threading.Thread(target = server)
    t.setDaemon(True)
    t.start()
    host, port = listener.getsockname()
    return connect(host, port, service = service, config = config)

def connect_multiprocess(service = VoidService, config = {}, remote_service = VoidService, remote_config = {}, args={}):
    """starts an rpyc server on a new process, bound to an arbitrary port, 
    and connects to it over a socket. Basically a copy of connect_thread().
    However if args is used and if these are shared memory then changes
    will be bi-directional. That is we now have access to shared memmory.
    
    :param service: the local service to expose (defaults to Void)
    :param config: configuration dict
    :param server_service: the remote service to expose (of the server; defaults to Void)
    :param server_config: remote configuration dict (of the server)
    :param args: dict of local vars to pass to new connection, form {'name':var}
    
    Contributed by *@tvanzyl*
    """
    from multiprocessing import Process
    
    listener = socket.socket()
    listener.bind(("localhost", 0))
    listener.listen(1)
    
    def server(listener=listener, args=args):
        client = listener.accept()[0]
        listener.close()
        conn = connect_stream(SocketStream(client), service = remote_service, config = remote_config)        
        try:
            for k in args:
                conn._local_root.exposed_namespace[k] = args[k]
            conn.serve_all()
        except KeyboardInterrupt:
            interrupt_main()
    
    t = Process(target = server)
    t.start()
    host, port = listener.getsockname()
    return connect(host, port, service = service, config = config)


