"""
An abstraction layer over OS-dependent file-like objects, that provides a 
consistent view of a *duplex byte stream*.
"""
import sys
import os
import socket
import time
import errno
from rpyc.lib import safe_import
from rpyc.lib.compat import select, select_error, BYTES_LITERAL, get_exc_errno, maxint
win32file = safe_import("win32file")
win32pipe = safe_import("win32pipe")
msvcrt = safe_import("msvcrt")
ssl = safe_import("ssl")


retry_errnos = (errno.EAGAIN, errno.EWOULDBLOCK)


class Stream(object):
    """Base Stream"""
    
    __slots__ = ()
    def close(self):
        """closes the stream, releasing any system resources associated with it"""
        raise NotImplementedError()
    @property
    def closed(self):
        """tests whether the stream is closed or not"""
        raise NotImplementedError()
    def fileno(self):
        """returns the stream's file descriptor"""
        raise NotImplementedError()
    def poll(self, timeout):
        """indicates whether the stream has data to read (within *timeout* 
        seconds)"""
        try:
            rl, _, _ = select([self], [], [], timeout)
        except ValueError:
            # i get this some times: "ValueError: file descriptor cannot be a negative integer (-1)"
            # let's translate it to select.error
            ex = sys.exc_info()[1]
            raise select_error(str(ex))
        return bool(rl)
    def read(self, count):
        """reads **exactly** *count* bytes, or raise EOFError
        
        :param count: the number of bytes to read
        
        :returns: read data
        """
        raise NotImplementedError()
    def write(self, data):
        """writes the entire *data*, or raise EOFError
        
        :param data: a string of binary data
        """
        raise NotImplementedError()


class ClosedFile(object):
    """Represents a closed file object (singleton)"""
    __slots__ = ()
    def __getattr__(self, name):
        if name.startswith("__"): # issue 71
            raise AttributeError("stream has been closed")
        raise EOFError("stream has been closed")
    def close(self):
        pass
    @property
    def closed(self):
        return True
    def fileno(self):
        raise EOFError("stream has been closed")
ClosedFile = ClosedFile()


class SocketStream(Stream):
    """A stream over a socket"""
    
    __slots__ = ("sock",)
    MAX_IO_CHUNK = 8000
    def __init__(self, sock):
        self.sock = sock
        
    @classmethod
    def _connect(cls, host, port, family = socket.AF_INET, socktype = socket.SOCK_STREAM,
            proto = 0, timeout = 3, nodelay = False):
        s = socket.socket(family, socktype, proto)
        s.settimeout(timeout)
        s.connect((host, port))
        if nodelay:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return s
    
    @classmethod
    def connect(cls, host, port, **kwargs):
        """factory method that creates a ``SocketStream`` over a socket connected
        to *host* and *port*
        
        :param host: the host name
        :param port: the TCP port
        :param kwargs: additional keyword arguments: ``family``, ``socktype``,
                       ``proto``, ``timeout``, ``nodelay``, passed directly to 
                       the ``socket`` constructor, or ``ipv6``.
        :param ipv6: if True, creates an IPv6 socket (``AF_INET6``); otherwise
                     an IPv4 (``AF_INET``) socket is created
        
        :returns: a :class:`SocketStream`
        """
        if kwargs.pop("ipv6", False):
            kwargs["family"] = socket.AF_INET6
        return cls(cls._connect(host, port, **kwargs))

    @classmethod
    def unix_connect(cls, path, timeout = 3):
        """factory method that creates a ``SocketStream `` over a unix domain socket
        located in *path*

        :param path: the path to the unix domain socket
        :param timeout: socket timeout
        """
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(path)
        return cls(s)

    @classmethod
    def ssl_connect(cls, host, port, ssl_kwargs, **kwargs):
        """factory method that creates a ``SocketStream`` over an SSL-wrapped 
        socket, connected to *host* and *port* with the given credentials.
        
        :param host: the host name
        :param port: the TCP port
        :param ssl_kwargs: a dictionary of keyword arguments to be passed 
                           directly to ``ssl.wrap_socket``
        :param kwargs: additional keyword arguments: ``family``, ``socktype``,
                       ``proto``, ``timeout``, ``nodelay``, passed directly to 
                       the ``socket`` constructor, or ``ipv6``.
        :param ipv6: if True, creates an IPv6 socket (``AF_INET6``); otherwise
                     an IPv4 (``AF_INET``) socket is created
        
        :returns: a :class:`SocketStream`
        """
        if kwargs.pop("ipv6", False):
            kwargs["family"] = socket.AF_INET6
        s = cls._connect(host, port, **kwargs)
        s2 = ssl.wrap_socket(s, **ssl_kwargs)
        return cls(s2)
    
    @property
    def closed(self):
        return self.sock is ClosedFile
    def close(self):
        if not self.closed:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
        self.sock.close()
        self.sock = ClosedFile
    def fileno(self):
        try:
            return self.sock.fileno()
        except socket.error:
            self.close()
            ex = sys.exc_info()[1]
            if get_exc_errno(ex) == errno.EBADF:
                raise EOFError()
            else:
                raise
    
    def read(self, count):
        data = []
        while count > 0:
            try:
                buf = self.sock.recv(min(self.MAX_IO_CHUNK, count))
            except socket.timeout:
                continue
            except socket.error:
                ex = sys.exc_info()[1]
                if get_exc_errno(ex) in retry_errnos:
                    # windows just has to be a bitch
                    continue
                self.close()
                raise EOFError(ex)
            if not buf:
                self.close()
                raise EOFError("connection closed by peer")
            data.append(buf)
            count -= len(buf)
        return BYTES_LITERAL("").join(data)
    def write(self, data):
        try:
            while data:
                count = self.sock.send(data[:self.MAX_IO_CHUNK])
                data = data[count:]
        except socket.error:
            ex = sys.exc_info()[1]
            self.close()
            raise EOFError(ex)

class TunneledSocketStream(SocketStream):
    """A socket stream over an :class:`rpyc.utils.ssh.SshTunnel`"""
    
    __slots__ = ("tun",)
    def __init__(self, sock):
        self.sock = sock
        self.tun = None
    def close(self):
        SocketStream.close(self)
        if self.tun:
            self.tun.close()

class PipeStream(Stream):
    """A stream over two simplex pipes (one used to input, another for output)"""
    
    __slots__ = ("incoming", "outgoing")
    MAX_IO_CHUNK = 32000
    def __init__(self, incoming, outgoing):
        outgoing.flush()
        self.incoming = incoming
        self.outgoing = outgoing
    @classmethod
    def from_std(cls):
        """factory method that creates a PipeStream over the standard pipes 
        (``stdin`` and ``stdout``)
        
        :returns: a :class:`PipeStream` instance
        """
        return cls(sys.stdin, sys.stdout)
    @classmethod
    def create_pair(cls):
        """factory method that creates two pairs of anonymous pipes, and 
        creates two PipeStreams over them. Useful for ``fork()``.
        
        :returns: a tuple of two :class:`PipeStream` instances
        """
        r1, w1 = os.pipe()
        r2, w2 = os.pipe()
        side1 = cls(os.fdopen(r1, "rb"), os.fdopen(w2, "wb"))
        side2 = cls(os.fdopen(r2, "rb"), os.fdopen(w1, "wb"))
        return side1, side2
    @property
    def closed(self):
        return self.incoming is ClosedFile
    def close(self):
        self.incoming.close()
        self.outgoing.close()
        self.incoming = ClosedFile
        self.outgoing = ClosedFile
    def fileno(self):
        return self.incoming.fileno()
    def read(self, count):
        data = []
        try:
            while count > 0:
                buf = os.read(self.incoming.fileno(), min(self.MAX_IO_CHUNK, count))
                if not buf:
                    raise EOFError("connection closed by peer")
                data.append(buf)
                count -= len(buf)
        except EOFError:
            self.close()
            raise
        except EnvironmentError:
            ex = sys.exc_info()[1]
            self.close()
            raise EOFError(ex)
        return BYTES_LITERAL("").join(data)
    def write(self, data):
        try:
            while data:
                chunk = data[:self.MAX_IO_CHUNK]
                written = os.write(self.outgoing.fileno(), chunk)
                data = data[written:]
        except EnvironmentError:
            ex = sys.exc_info()[1]
            self.close()
            raise EOFError(ex)


class Win32PipeStream(Stream):
    """A stream over two simplex pipes (one used to input, another for output).
    This is an implementation for Windows pipes (which suck)"""
    
    __slots__ = ("incoming", "outgoing", "_fileno", "_keepalive")
    PIPE_BUFFER_SIZE = 130000
    MAX_IO_CHUNK = 32000

    def __init__(self, incoming, outgoing):
        self._keepalive = (incoming, outgoing)
        if hasattr(incoming, "fileno"):
            self._fileno = incoming.fileno()
            incoming = msvcrt.get_osfhandle(incoming.fileno())
        if hasattr(outgoing, "fileno"):
            outgoing = msvcrt.get_osfhandle(outgoing.fileno())
        self.incoming = incoming
        self.outgoing = outgoing
    @classmethod
    def from_std(cls):
        return cls(sys.stdin, sys.stdout)
    @classmethod
    def create_pair(cls):
        r1, w1 = win32pipe.CreatePipe(None, cls.PIPE_BUFFER_SIZE)
        r2, w2 = win32pipe.CreatePipe(None, cls.PIPE_BUFFER_SIZE)
        return cls(r1, w2), cls(r2, w1)

    def fileno(self):
        return self._fileno
    @property
    def closed(self):
        return self.incoming is ClosedFile
    def close(self):
        if self.closed:
            return
        try:
            win32file.CloseHandle(self.incoming)
        except Exception:
            pass
        self.incoming = ClosedFile
        try:
            win32file.CloseHandle(self.outgoing)
        except Exception:
            pass
        self.outgoing = ClosedFile
    def read(self, count):
        try:
            data = []
            while count > 0:
                dummy, buf = win32file.ReadFile(self.incoming, int(min(self.MAX_IO_CHUNK, count)))
                count -= len(buf)
                data.append(buf)
        except TypeError:
            ex = sys.exc_info()[1]
            if not self.closed:
                raise
            raise EOFError(ex)
        except win32file.error:
            ex = sys.exc_info()[1]
            self.close()
            raise EOFError(ex)
        return BYTES_LITERAL("").join(data)
    def write(self, data):
        try:
            while data:
                dummy, count = win32file.WriteFile(self.outgoing, data[:self.MAX_IO_CHUNK])
                data = data[count:]
        except TypeError:
            ex = sys.exc_info()[1]
            if not self.closed:
                raise
            raise EOFError(ex)
        except win32file.error:
            ex = sys.exc_info()[1]
            self.close()
            raise EOFError(ex)

    def poll(self, timeout, interval = 0.1):
        """a poor man's version of select()"""
        if timeout is None:
            timeout = maxint
        length = 0
        tmax = time.time() + timeout
        try:
            while length == 0:
                length = win32pipe.PeekNamedPipe(self.incoming, 0)[1]
                if time.time() >= tmax:
                    break
                time.sleep(interval)
        except TypeError:
            ex = sys.exc_info()[1]
            if not self.closed:
                raise
            raise EOFError(ex)
        return length != 0


class NamedPipeStream(Win32PipeStream):
    """A stream over two named pipes (one used to input, another for output).
    Windows implementation."""
    
    NAMED_PIPE_PREFIX = r'\\.\pipe\rpyc_'
    PIPE_IO_TIMEOUT = 3
    CONNECT_TIMEOUT = 3
    __slots__ = ("is_server_side",)

    def __init__(self, handle, is_server_side):
        Win32PipeStream.__init__(self, handle, handle)
        self.is_server_side = is_server_side
    @classmethod
    def from_std(cls):
        raise NotImplementedError()
    @classmethod
    def create_pair(cls):
        raise NotImplementedError()

    @classmethod
    def create_server(cls, pipename, connect = True):
        """factory method that creates a server-side ``NamedPipeStream``, over 
        a newly-created *named pipe* of the given name.
        
        :param pipename: the name of the pipe. It will be considered absolute if
                         it starts with ``\\\\.``; otherwise ``\\\\.\\pipe\\rpyc``
                         will be prepended.
        :param connect: whether to connect on creation or not
        
        :returns: a :class:`NamedPipeStream` instance
        """
        if not pipename.startswith("\\\\."):
            pipename = cls.NAMED_PIPE_PREFIX + pipename
        handle = win32pipe.CreateNamedPipe(
            pipename,
            win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT,
            1,
            cls.PIPE_BUFFER_SIZE,
            cls.PIPE_BUFFER_SIZE,
            cls.PIPE_IO_TIMEOUT * 1000,
            None
        )
        inst = cls(handle, True)
        if connect:
            inst.connect_server()
        return inst

    def connect_server(self):
        """connects the server side of an unconnected named pipe (blocks 
        until a connection arrives)"""
        if not self.is_server_side:
            raise ValueError("this must be the server side")
        win32pipe.ConnectNamedPipe(self.incoming, None)

    @classmethod
    def create_client(cls, pipename):
        """factory method that creates a client-side ``NamedPipeStream``, over 
        a newly-created *named pipe* of the given name.
        
        :param pipename: the name of the pipe. It will be considered absolute if
                         it starts with ``\\\\.``; otherwise ``\\\\.\\pipe\\rpyc``
                         will be prepended.
        
        :returns: a :class:`NamedPipeStream` instance
        """
        if not pipename.startswith("\\\\."):
            pipename = cls.NAMED_PIPE_PREFIX + pipename
        handle = win32file.CreateFile(
            pipename,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0,
            None,
            win32file.OPEN_EXISTING,
            0,
            None
        )
        return cls(handle, False)

    def close(self):
        if self.closed:
            return
        if self.is_server_side:
            win32file.FlushFileBuffers(self.outgoing)
            win32pipe.DisconnectNamedPipe(self.outgoing)
        Win32PipeStream.close(self)


if sys.platform == "win32":
    PipeStream = Win32PipeStream

