"""
RPyC **registry server** implementation. The registry is much like 
`Avahi <http://en.wikipedia.org/wiki/Avahi_(software)>`_ or 
`Bonjour <http://en.wikipedia.org/wiki/Bonjour_(software)>`_, but tailored to
the needs of RPyC. Also, neither of them supports (or supported) Windows,
and Bonjour has a restrictive license. Moreover, they are too "powerful" for 
what RPyC needed and required too complex a setup.

If anyone wants to implement the RPyC registry using Avahi, Bonjour, or any 
other zeroconf implementation -- I'll be happy to include them. 

Refer to :file:`rpyc/scripts/rpyc_registry.py` for more info.
"""
import sys
import socket
import time
import logging
from rpyc.core import brine


DEFAULT_PRUNING_TIMEOUT = 4 * 60
MAX_DGRAM_SIZE          = 1500
REGISTRY_PORT           = 18811


#------------------------------------------------------------------------------
# servers
#------------------------------------------------------------------------------

class RegistryServer(object):
    """Base registry server"""
    
    def __init__(self, listenersock, pruning_timeout = None, logger = None):
        self.sock = listenersock
        self.port = self.sock.getsockname()[1]
        self.active = False
        self.services = {}
        if pruning_timeout is None:
            pruning_timeout = DEFAULT_PRUNING_TIMEOUT
        self.pruning_timeout = pruning_timeout
        if logger is None:
            logger = self._get_logger()
        self.logger = logger

    def _get_logger(self):
        raise NotImplementedError()

    def on_service_added(self, name, addrinfo):
        """called when a new service joins the registry (but not on keepalives).
        override this to add custom logic"""

    def on_service_removed(self, name, addrinfo):
        """called when a service unregisters or is pruned.
        override this to add custom logic"""

    def _add_service(self, name, addrinfo):
        """updates the service's keep-alive time stamp"""
        if name not in self.services:
            self.services[name] = {}
        is_new = addrinfo not in self.services
        self.services[name][addrinfo] = time.time()
        if is_new:
            try:
                self.on_service_added(name, addrinfo)
            except Exception:
                self.logger.exception('error executing service add callback')

    def _remove_service(self, name, addrinfo):
        """removes a single server of the given service"""
        self.services[name].pop(addrinfo, None)
        if not self.services[name]:
            del self.services[name]
        try:
            self.on_service_removed(name, addrinfo)
        except Exception:
            self.logger.exception('error executing service remove callback')

    def cmd_query(self, host, name):
        """implementation of the ``query`` command"""
        name = name.upper()
        self.logger.debug("querying for %r", name)
        if name not in self.services:
            self.logger.debug("no such service")
            return ()

        oldest = time.time() - self.pruning_timeout
        all_servers = sorted(self.services[name].items(), key = lambda x: x[1])
        servers = []
        for addrinfo, t in all_servers:
            if t < oldest:
                self.logger.debug("discarding stale %s:%s", *addrinfo)
                self._remove_service(name, addrinfo)
            else:
                servers.append(addrinfo)

        self.logger.debug("replying with %r", servers)
        return tuple(servers)

    def cmd_register(self, host, names, port):
        """implementation of the ``register`` command"""
        self.logger.debug("registering %s:%s as %s", host, port, ", ".join(names))
        for name in names:
            self._add_service(name.upper(), (host, port))
        return "OK"

    def cmd_unregister(self, host, port):
        """implementation of the ``unregister`` command"""
        self.logger.debug("unregistering %s:%s", host, port)
        for name in self.services.keys():
            self._remove_service(name, (host, port))
        return "OK"

    def _recv(self):
        raise NotImplementedError()

    def _send(self, data, addrinfo):
        raise NotImplementedError()

    def _work(self):
        while self.active:
            try:
                data, addrinfo = self._recv()
            except (socket.error, socket.timeout):
                continue
            try:
                magic, cmd, args = brine.load(data)
            except Exception:
                continue
            if magic != "RPYC":
                self.logger.warn("invalid magic: %r", magic)
                continue
            cmdfunc = getattr(self, "cmd_%s" % (cmd.lower(),), None)
            if not cmdfunc:
                self.logger.warn("unknown command: %r", cmd)
                continue

            try:
                reply = cmdfunc(addrinfo[0], *args)
            except Exception:
                self.logger.exception('error executing function')
            else:
                self._send(brine.dump(reply), addrinfo)

    def start(self):
        """Starts the registry server (blocks)"""
        if self.active:
            raise ValueError("server is already running")
        if self.sock is None:
            raise ValueError("object disposed")
        self.logger.debug("server started on %s:%s", *self.sock.getsockname())
        try:
            try:
                self.active = True
                self._work()
            except KeyboardInterrupt:
                self.logger.warn("User interrupt!")
        finally:
            self.active = False
            self.logger.debug("server closed")
            self.sock.close()
            self.sock = None

    def close(self):
        """Closes (terminates) the registry server"""
        if not self.active:
            raise ValueError("server is not running")
        self.logger.debug("stopping server...")
        self.active = False

class UDPRegistryServer(RegistryServer):
    """UDP-based registry server. The server listens to UDP broadcasts and
    answers them. Useful in local networks, were broadcasts are allowed"""
    
    def __init__(self, host = "0.0.0.0", port = REGISTRY_PORT,
            pruning_timeout = None, logger = None):

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((host, port))
        sock.settimeout(0.5)
        RegistryServer.__init__(self, sock, pruning_timeout = pruning_timeout,
            logger = logger)

    def _get_logger(self):
        return logging.getLogger("REGSRV/UDP/%d" % (self.port,))

    def _recv(self):
        return self.sock.recvfrom(MAX_DGRAM_SIZE)

    def _send(self, data, addrinfo):
        try:
            self.sock.sendto(data, addrinfo)
        except (socket.error, socket.timeout):
            pass

class TCPRegistryServer(RegistryServer):
    """TCP-based registry server. The server listens to a certain TCP port and
    answers requests. Useful when you need to cross routers in the network, since
    they block UDP broadcasts"""
    
    def __init__(self, host = "0.0.0.0", port = REGISTRY_PORT,
            pruning_timeout = None, logger = None, reuse_addr = True):

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if reuse_addr and sys.platform != "win32":
            # warning: reuseaddr is not what you expect on windows!
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(10)
        sock.settimeout(0.5)
        RegistryServer.__init__(self, sock, pruning_timeout = pruning_timeout,
            logger = logger)
        self._connected_sockets = {}

    def _get_logger(self):
        return logging.getLogger("REGSRV/TCP/%d" % (self.port,))

    def _recv(self):
        sock2, _ = self.sock.accept()
        addrinfo = sock2.getpeername()
        data = sock2.recv(MAX_DGRAM_SIZE)
        self._connected_sockets[addrinfo] = sock2
        return data, addrinfo

    def _send(self, data, addrinfo):
        sock2 = self._connected_sockets.pop(addrinfo)
        try:
            try:
                sock2.send(data)
            except (socket.error, socket.timeout):
                pass
        finally:
            sock2.close()

#------------------------------------------------------------------------------
# clients (registrars)
#------------------------------------------------------------------------------
class RegistryClient(object):
    """Base registry client. Also known as **registrar**"""
    
    REREGISTER_INTERVAL = 60

    def __init__(self, ip, port, timeout, logger = None):
        self.ip = ip
        self.port = port
        self.timeout = timeout
        if logger is None:
            logger = self._get_logger()
        self.logger = logger

    def _get_logger(self):
        raise NotImplementedError()

    def discover(self, name):
        """Sends a query for the specified service name.
        
        :param name: the service name (or one of its aliases)
        
        :returns: a list of ``(host, port)`` tuples
        """
        raise NotImplementedError()

    def register(self, aliases, port):
        """Registers the given service aliases with the given TCP port. This 
        API is intended to be called only by an RPyC server.
        
        :param aliases: the :class:`service's <rpyc.core.service.Service>` aliases
        :param port: the listening TCP port of the server
        """
        raise NotImplementedError()

    def unregister(self, port):
        """Unregisters the given RPyC server. This API is intended to be called
        only by an RPyC server.
        
        :param port: the listening TCP port of the RPyC server to unregister
        """
        raise NotImplementedError()

class UDPRegistryClient(RegistryClient):
    """UDP-based registry clients. By default, it sends UDP broadcasts (requires 
    special user privileges on certain OS's) and collects the replies. You can 
    also specify the IP address to send to.
    
    Example::
    
        registrar = UDPRegistryClient()
        list_of_servers = registrar.discover("foo")

    .. note::
       Consider using :func:`rpyc.utils.factory.discover` instead
    """
    
    def __init__(self, ip = "255.255.255.255", port = REGISTRY_PORT, timeout = 2,
    bcast = None, logger = None):
        RegistryClient.__init__(self, ip = ip, port = port, timeout = timeout,
            logger = logger)
        if bcast is None:
            bcast = "255" in ip.split(".")
        self.bcast = bcast

    def _get_logger(self):
        return logging.getLogger('REGCLNT/UDP')

    def discover(self, name):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            if self.bcast:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)
            data = brine.dump(("RPYC", "QUERY", (name,)))
            sock.sendto(data, (self.ip, self.port))
            sock.settimeout(self.timeout)

            try:
                data, _ = sock.recvfrom(MAX_DGRAM_SIZE)
            except (socket.error, socket.timeout):
                servers = ()
            else:
                servers = brine.load(data)
        finally:
            sock.close()
        return servers

    def register(self, aliases, port):
        self.logger.info("registering on %s:%s", self.ip, self.port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            if self.bcast:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)
            data = brine.dump(("RPYC", "REGISTER", (aliases, port)))
            sock.sendto(data, (self.ip, self.port))
    
            tmax = time.time() + self.timeout
            while time.time() < tmax:
                sock.settimeout(tmax - time.time())
                try:
                    data, (rip, rport) = sock.recvfrom(MAX_DGRAM_SIZE)
                except socket.timeout:
                    self.logger.warn("no registry acknowledged")
                    break
                if rport != self.port:
                    continue
                try:
                    reply = brine.load(data)
                except Exception:
                    continue
                if reply == "OK":
                    self.logger.info("registry %s:%s acknowledged", rip, rport)
                    break
            else:
                self.logger.warn("no registry acknowledged")
        finally:
            sock.close()

    def unregister(self, port):
        self.logger.info("unregistering from %s:%s", self.ip, self.port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            if self.bcast:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)
            data = brine.dump(("RPYC", "UNREGISTER", (port,)))
            sock.sendto(data, (self.ip, self.port))
        finally:
            sock.close()


class TCPRegistryClient(RegistryClient):
    """TCP-based registry client. You must specify the host (registry server)
    to connect to.  
    
    Example::
    
        registrar = TCPRegistryClient("localhost")
        list_of_servers = registrar.discover("foo")
    
    .. note::
       Consider using :func:`rpyc.utils.factory.discover` instead
    """
    
    def __init__(self, ip, port = REGISTRY_PORT, timeout = 2, logger = None):
        RegistryClient.__init__(self, ip = ip, port = port, timeout = timeout,
            logger = logger)

    def _get_logger(self):
        return logging.getLogger('REGCLNT/TCP')

    def discover(self, name):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            data = brine.dump(("RPYC", "QUERY", (name,)))
            sock.connect((self.ip, self.port))
            sock.send(data)
            
            try:
                data = sock.recv(MAX_DGRAM_SIZE)
            except (socket.error, socket.timeout):
                servers = ()
            else:
                servers = brine.load(data)
        finally:
            sock.close()
        return servers

    def register(self, aliases, port):
        self.logger.info("registering on %s:%s", self.ip, self.port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        data = brine.dump(("RPYC", "REGISTER", (aliases, port)))

        try:
            try:
                sock.connect((self.ip, self.port))
                sock.send(data)
            except (socket.error, socket.timeout):
                self.logger.warn("could not connect to registry")
                return
            try:
                data = sock.recv(MAX_DGRAM_SIZE)
            except socket.timeout:
                self.logger.warn("registry did not acknowledge")
                return
            try:
                reply = brine.load(data)
            except Exception:
                self.logger.warn("received corrupted data from registry")
                return
            if reply == "OK":
                self.logger.info("registry %s:%s acknowledged", self.ip, self.port)
        finally:
            sock.close()

    def unregister(self, port):
        self.logger.info("unregistering from %s:%s", self.ip, self.port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            data = brine.dump(("RPYC", "UNREGISTER", (port,)))
            try:
                sock.connect((self.ip, self.port))
                sock.send(data)
            except (socket.error, socket.timeout):
                self.logger.warn("could not connect to registry")
        finally:
            sock.close()

