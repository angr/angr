import sys
import os
import inspect
from rpyc.lib.compat import pickle
from rpyc import SlaveService
from rpyc.utils import factory


DEFAULT_SERVER_PORT = 18812
DEFAULT_SERVER_SSL_PORT = 18821


#===============================================================================
# connecting
#===============================================================================
def connect_channel(channel):
    """
    Creates an RPyC connection over the given ``channel``
    
    :param channel: the :class:`rpyc.core.channel.Channel` instance
    
    :returns: an RPyC connection exposing ``SlaveService``
    """
    return factory.connect_channel(channel, SlaveService)

def connect_stream(stream):
    """
    Creates an RPyC connection over the given stream

    :param channel: the :class:`rpyc.core.stream.Stream` instance
    
    :returns: an RPyC connection exposing ``SlaveService``
    """
    return factory.connect_stream(stream, SlaveService)

def connect_stdpipes():
    """
    Creates an RPyC connection over the standard pipes (``stdin`` and ``stdout``)
    
    :returns: an RPyC connection exposing ``SlaveService``
    """
    return factory.connect_stdpipes(SlaveService)

def connect_pipes(input, output):
    """
    Creates an RPyC connection over two pipes
    
    :param input: the input pipe
    :param output: the output pipe
    
    :returns: an RPyC connection exposing ``SlaveService``
    """
    return factory.connect_pipes(input, output, SlaveService)

def connect(host, port = DEFAULT_SERVER_PORT, ipv6 = False):
    """
    Creates a socket connection to the given host and port.
    
    :param host: the host to connect to
    :param port: the TCP port
    :param ipv6: whether to create an IPv6 socket or IPv4
    
    :returns: an RPyC connection exposing ``SlaveService``
    """
    return factory.connect(host, port, SlaveService, ipv6 = ipv6)

def unix_connect(path):
    """
    Creates a socket connection to the given host and port.

    :param path: the path to the unix domain socket
    
    :returns: an RPyC connection exposing ``SlaveService``
    """
    return factory.unix_connect(path, SlaveService)
    
def ssl_connect(host, port = DEFAULT_SERVER_SSL_PORT, keyfile = None,
        certfile = None, ca_certs = None, cert_reqs = None, ssl_version = None, 
        ciphers = None, ipv6 = False):
    """Creates a secure (``SSL``) socket connection to the given host and port,
    authenticating with the given certfile and CA file.
    
    :param host: the host to connect to
    :param port: the TCP port to use
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

    :returns: an RPyC connection exposing ``SlaveService``

    .. _wrap_socket: 
    """
    return factory.ssl_connect(host, port, keyfile = keyfile, certfile = certfile,
        ssl_version = ssl_version, ca_certs = ca_certs, service = SlaveService,
        ipv6 = ipv6)

def ssh_connect(sshctx, remote_port):
    """Connects to the remote server over an SSH tunnel. See 
    :func:`rpyc.utils.factory.ssh_connect`.
    
    :param sshctx: the :class:`rpyc.utils.ssh.SshContext` instance
    :param remote_port: the remote TCP port
    
    :returns: an RPyC connection exposing ``SlaveService``
    """
    return factory.ssh_connect(sshctx, remote_port, SlaveService)

def connect_subproc(server_file = None):
    """Runs an RPyC classic server as a subprocess and returns an RPyC
    connection to it over stdio
    
    :param server_file: The full path to the server script (``rpyc_classic.py``). 
                        If not given, ``which rpyc_classic.py`` will be attempted.
    
    :returns: an RPyC connection exposing ``SlaveService``
    """
    if server_file is None:
        server_file = os.popen("which rpyc_classic.py").read().strip()
        if not server_file:
            raise ValueError("server_file not given and could not be inferred")
    return factory.connect_subproc([sys.executable, "-u", server_file, "-q", "-m", "stdio"],
        SlaveService)

def connect_thread():
    """
    Starts a SlaveService on a thread and connects to it. Useful for testing 
    purposes. See :func:`rpyc.utils.factory.connect_thread`
    
    :returns: an RPyC connection exposing ``SlaveService``
    """
    return factory.connect_thread(SlaveService, remote_service = SlaveService)

def connect_multiprocess(args = {}):
    """
    Starts a SlaveService on a multiprocess process and connects to it.
    Useful for testing purposes and running multicore code thats uses shared
    memory. See :func:`rpyc.utils.factory.connect_multiprocess`
    
    :returns: an RPyC connection exposing ``SlaveService``
    """
    return factory.connect_multiprocess(SlaveService, remote_service = SlaveService, args=args)


#===============================================================================
# remoting utilities
#===============================================================================

def upload(conn, localpath, remotepath, filter = None, ignore_invalid = False, chunk_size = 16000):
    """uploads a file or a directory to the given remote path
    
    :param localpath: the local file or directory
    :param remotepath: the remote path
    :param filter: a predicate that accepts the filename and determines whether
                   it should be uploaded; None means any file
    :param chunk_size: the IO chunk size
    """
    if os.path.isdir(localpath):
        upload_dir(conn, localpath, remotepath, filter, chunk_size)
    elif os.path.isfile(localpath):
        upload_file(conn, localpath, remotepath, chunk_size)
    else:
        if not ignore_invalid:
            raise ValueError("cannot upload %r" % (localpath,))

def upload_file(conn, localpath, remotepath, chunk_size = 16000):
    lf = open(localpath, "rb")
    rf = conn.builtin.open(remotepath, "wb")
    while True:
        buf = lf.read(chunk_size)
        if not buf:
            break
        rf.write(buf)
    lf.close()
    rf.close()

def upload_dir(conn, localpath, remotepath, filter = None, chunk_size = 16000):
    if not conn.modules.os.path.isdir(remotepath):
        conn.modules.os.makedirs(remotepath)
    for fn in os.listdir(localpath):
        if not filter or filter(fn):
            lfn = os.path.join(localpath, fn)
            rfn = conn.modules.os.path.join(remotepath, fn)
            upload(conn, lfn, rfn, filter = filter, ignore_invalid = True, chunk_size = chunk_size)

def download(conn, remotepath, localpath, filter = None, ignore_invalid = False, chunk_size = 16000):
    """
    download a file or a directory to the given remote path
    
    :param localpath: the local file or directory
    :param remotepath: the remote path
    :param filter: a predicate that accepts the filename and determines whether
                   it should be downloaded; None means any file
    :param chunk_size: the IO chunk size
    """
    if conn.modules.os.path.isdir(remotepath):
        download_dir(conn, remotepath, localpath, filter)
    elif conn.modules.os.path.isfile(remotepath):
        download_file(conn, remotepath, localpath, chunk_size)
    else:
        if not ignore_invalid:
            raise ValueError("cannot download %r" % (remotepath,))

def download_file(conn, remotepath, localpath, chunk_size = 16000):
    rf = conn.builtin.open(remotepath, "rb")
    lf = open(localpath, "wb")
    while True:
        buf = rf.read(chunk_size)
        if not buf:
            break
        lf.write(buf)
    lf.close()
    rf.close()

def download_dir(conn, remotepath, localpath, filter = None, chunk_size = 16000):
    if not os.path.isdir(localpath):
        os.makedirs(localpath)
    for fn in conn.modules.os.listdir(remotepath):
        if not filter or filter(fn):
            rfn = conn.modules.os.path.join(remotepath, fn)
            lfn = os.path.join(localpath, fn)
            download(conn, rfn, lfn, filter = filter, ignore_invalid = True)

def upload_package(conn, module, remotepath = None, chunk_size = 16000):
    """
    uploads a module or a package to the remote party
    
    :param conn: the RPyC connection to use
    :param module: the local module/package object to upload
    :param remotepath: the remote path (if ``None``, will default to the 
                       remote system's python library (as reported by 
                       ``distutils``)
    :param chunk_size: the IO chunk size
    
    .. note:: ``upload_module`` is just an alias to ``upload_package``
    
    example::
    
       import foo.bar
       ...
       rpyc.classic.upload_package(conn, foo.bar)
    
    """
    if remotepath is None:
        site = conn.modules["distutils.sysconfig"].get_python_lib()
        remotepath = conn.modules.os.path.join(site, module.__name__)
    localpath = os.path.dirname(inspect.getsourcefile(module))
    upload(conn, localpath, remotepath, chunk_size = chunk_size)

upload_module = upload_package

def obtain(proxy):
    """obtains (copies) a remote object from a proxy object. the object is 
    ``pickled`` on the remote side and ``unpickled`` locally, thus moved 
    **by value**. changes made to the local object will not reflect remotely.
        
    :param proxy: an RPyC proxy object
    
    .. note:: the remote object to must be ``pickle``-able

    :returns: a copy of the remote object
    """
    return pickle.loads(pickle.dumps(proxy))

def deliver(conn, localobj):
    """delivers (recreates) a local object on the other party. the object is
    ``pickled`` locally and ``unpickled`` on the remote side, thus moved
    **by value**. changes made to the remote object will not reflect locally.
    
    :param conn: the RPyC connection
    :param localobj: the local object to deliver
    
    .. note:: the object must be ``picklable``
    
    :returns: a proxy to the remote object
    """
    return conn.modules["rpyc.lib.compat"].pickle.loads(pickle.dumps(localobj))

class redirected_stdio(object):
    """
    Redirects the other party's ``stdin``, ``stdout`` and ``stderr`` to 
    those of the local party, so remote IO will occur locally. It was 
    originally written as a ``contextmanager``, but was turned into a class
    for compatibility with python 2.4
    
    Here's the context-manager::
    
        @contextmanager
        def redirected_stdio(conn):
            orig_stdin = conn.modules.sys.stdin
            orig_stdout = conn.modules.sys.stdout
            orig_stderr = conn.modules.sys.stderr
            try:
                conn.modules.sys.stdin = sys.stdin
                conn.modules.sys.stdout = sys.stdout
                conn.modules.sys.stderr = sys.stderr
                yield
            finally:
                conn.modules.sys.stdin = orig_stdin
                conn.modules.sys.stdout = orig_stdout
                conn.modules.sys.stderr = orig_stderr
    
    Example usage::
    
        with redirected_stdio(conn):
            # remote IO will occur locally
        
    or ::
        
        redir = redirected_stdio(conn)
        try:
            # remote IO will occur locally
        finally:
            redir.restore()
    """
    def __init__(self, conn):
        """
        :param conn: the RPyC connection whose stdio will be redirected
        """
        self._restored = True
        self.conn = conn
        self.orig_stdin = self.conn.modules.sys.stdin
        self.orig_stdout = self.conn.modules.sys.stdout
        self.orig_stderr = self.conn.modules.sys.stderr
        self.conn.modules.sys.stdin = sys.stdin
        self.conn.modules.sys.stdout = sys.stdout
        self.conn.modules.sys.stderr = sys.stderr
        self._restored = False
    def __del__(self):
        self.restore()
    def restore(self):
        """Restores the redirection"""
        if self._restored:
            return
        self._restored = True
        self.conn.modules.sys.stdin = self.orig_stdin
        self.conn.modules.sys.stdout = self.orig_stdout
        self.conn.modules.sys.stderr = self.orig_stderr
    def __enter__(self):
        return self
    def __exit__(self, t, v, tb):
        self.restore()


def pm(conn):
    """same as ``pdb.pm()`` but on a remote exception
    
    :param conn: the RPyC connection
    """
    #pdb.post_mortem(conn.root.getconn()._last_traceback)
    redir = redirected_stdio(conn)
    try:
        conn.modules.pdb.post_mortem(conn.root.getconn()._last_traceback)
    finally:
        redir.restore()

def interact(conn, namespace = None):
    """remote interactive interpreter
    
    :param conn: the RPyC connection
    :param namespace: the namespace to use (a ``dict``)
    """
    if namespace is None:
        namespace = {}
    namespace["conn"] = conn
    redir = redirected_stdio(conn)
    try:
        conn.execute("""def _rinteract(ns):
            import code
            code.interact(local = dict(ns))""")
        conn.namespace["_rinteract"](namespace)
    finally:
        redir.restore()

