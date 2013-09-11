"""
The RPyC protocol
"""
import sys
import weakref
import itertools
import socket
import time

from threading import Lock
from rpyc.lib.compat import pickle, next, is_py3k, maxint, select_error
from rpyc.lib.colls import WeakValueDict, RefCountingColl
from rpyc.core import consts, brine, vinegar, netref
from rpyc.core.async import AsyncResult

class PingError(Exception):
    """The exception raised should :func:`Connection.ping` fail"""
    pass

DEFAULT_CONFIG = dict(
    # ATTRIBUTES
    allow_safe_attrs = True,
    allow_exposed_attrs = True,
    allow_public_attrs = False,
    allow_all_attrs = False,
    safe_attrs = set(['__abs__', '__add__', '__and__', '__bool__', '__cmp__', '__contains__',
        '__delitem__', '__delslice__', '__div__', '__divmod__', '__doc__',
        '__eq__', '__float__', '__floordiv__', '__ge__', '__getitem__',
        '__getslice__', '__gt__', '__hash__', '__hex__', '__iadd__', '__iand__',
        '__idiv__', '__ifloordiv__', '__ilshift__', '__imod__', '__imul__',
        '__index__', '__int__', '__invert__', '__ior__', '__ipow__', '__irshift__',
        '__isub__', '__iter__', '__itruediv__', '__ixor__', '__le__', '__len__',
        '__long__', '__lshift__', '__lt__', '__mod__', '__mul__', '__ne__',
        '__neg__', '__new__', '__nonzero__', '__oct__', '__or__', '__pos__',
        '__pow__', '__radd__', '__rand__', '__rdiv__', '__rdivmod__', '__repr__',
        '__rfloordiv__', '__rlshift__', '__rmod__', '__rmul__', '__ror__',
        '__rpow__', '__rrshift__', '__rshift__', '__rsub__', '__rtruediv__',
        '__rxor__', '__setitem__', '__setslice__', '__str__', '__sub__',
        '__truediv__', '__xor__', 'next', '__length_hint__', '__enter__',
        '__exit__', '__next__',]),
    exposed_prefix = "exposed_",
    allow_getattr = True,
    allow_setattr = False,
    allow_delattr = False,
    # EXCEPTIONS
    include_local_traceback = True,
    instantiate_custom_exceptions = False,
    import_custom_exceptions = False,
    instantiate_oldstyle_exceptions = False, # which don't derive from Exception
    propagate_SystemExit_locally = False, # whether to propagate SystemExit locally or to the other party
    log_exceptions = True,
    # MISC
    allow_pickle = False,
    connid = None,
    credentials = None,
    endpoints = None,
    logger = None,
)
"""
The default configuration dictionary of the protocol. You can override these parameters
by passing a different configuration dict to the :class:`Connection` class.

.. note::
   You only need to override the parameters you want to change. There's no need
   to repeat parameters whose values remain unchanged.

=====================================  ================  =====================================================
Parameter                              Default value     Description
=====================================  ================  =====================================================
``allow_safe_attrs``                   ``True``          Whether to allow the use of *safe* attributes
                                                         (only those listed as ``safe_attrs``)
``allow_exposed_attrs``                ``True``          Whether to allow exposed attributes 
                                                         (attributes that start with the ``exposed_prefix``)
``allow_public_attrs``                 ``False``         Whether to allow public attributes
                                                         (attributes that don't start with ``_``)
``allow_all_attrs``                    ``False``         Whether to allow all attributes (including private)
``safe_attrs``                         ``set([...])``    The set of attributes considered safe
``exposed_prefix``                     ``"exposed_"``    The prefix of exposed attributes
``allow_getattr``                      ``True``          Whether to allow getting of attributes (``getattr``)
``allow_setattr``                      ``False``         Whether to allow setting of attributes (``setattr``)
``allow_delattr``                      ``False``         Whether to allow deletion of attributes (``delattr``)
``allow_pickle``                       ``False``         Whether to allow the use of ``pickle``

``include_local_traceback``            ``True``          Whether to include the local traceback
                                                         in the remote exception
``instantiate_custom_exceptions``      ``False``         Whether to allow instantiation of
                                                         custom exceptions (not the built in ones)
``import_custom_exceptions``           ``False``         Whether to allow importing of 
                                                         exceptions from not-yet-imported modules
``instantiate_oldstyle_exceptions``    ``False``         Whether to allow instantiation of exceptions
                                                         which don't derive from ``Exception``. This
                                                         is not applicable for Python 3 and later.
``propagate_SystemExit_locally``       ``False``         Whether to propagate ``SystemExit``
                                                         locally (kill the server) or to the other 
                                                         party (kill the client)
``logger``                             ``None``          The logger instance to use to log exceptions
                                                         (before they are sent to the other party)
                                                         and other events. If ``None``, no logging takes place.

``connid``                             ``None``          **Runtime**: the RPyC connection ID (used
                                                         mainly for debugging purposes) 
``credentials``                        ``None``          **Runtime**: the credentails object that was returned
                                                         by the server's :ref:`authenticator <api-authenticators>`
                                                         or ``None``
``endpoints``                          ``None``          **Runtime**: The connection's endpoints. This is a tuple 
                                                         made of the local socket endpoint (``getsockname``) and the 
                                                         remote one (``getpeername``). This is set by the server
                                                         upon accepting a connection; client side connections
                                                         do no have this configuration option set.
=====================================  ================  =====================================================
"""


_connection_id_generator = itertools.count(1)

class Connection(object):
    """The RPyC *connection* (AKA *protocol*).
    
    :param service: the :class:`Service <rpyc.core.service.Service>` to expose
    :param channel: the :class:`Channel <rpyc.core.channel.Channel>` over which messages are passed
    :param config: the connection's configuration dict (overriding parameters 
                   from the :data:`default configuration <DEFAULT_CONFIG>`)
    :param _lazy: whether or not to initialize the service with the creation of
                  the connection. Default is True. If set to False, you will 
                  need to call :func:`_init_service` manually later
    """
    def __init__(self, service, channel, config = {}, _lazy = False):
        self._closed = True
        self._config = DEFAULT_CONFIG.copy()
        self._config.update(config)
        if self._config["connid"] is None:
            self._config["connid"] = "conn%d" % (next(_connection_id_generator),)

        self._channel = channel
        self._seqcounter = itertools.count()
        self._recvlock = Lock()
        self._sendlock = Lock()
        self._sync_replies = {}
        self._async_callbacks = {}
        self._local_objects = RefCountingColl()
        self._last_traceback = None
        self._proxy_cache = WeakValueDict()
        self._netref_classes_cache = {}
        self._remote_root = None
        self._local_root = service(weakref.proxy(self))
        if not _lazy:
            self._init_service()
        self._closed = False
    def _init_service(self):
        self._local_root.on_connect()

    def __del__(self):
        self.close()
    def __enter__(self):
        return self
    def __exit__(self, t, v, tb):
        self.close()
    def __repr__(self):
        a, b = object.__repr__(self).split(" object ")
        return "%s %r object %s" % (a, self._config["connid"], b)

    #
    # IO
    #
    def _cleanup(self, _anyway = True):
        if self._closed and not _anyway:
            return
        self._closed = True
        self._channel.close()
        self._local_root.on_disconnect()
        self._sync_replies.clear()
        self._async_callbacks.clear()
        self._local_objects.clear()
        self._proxy_cache.clear()
        self._netref_classes_cache.clear()
        self._last_traceback = None
        self._remote_root = None
        self._local_root = None
        #self._seqcounter = None
        #self._config.clear()
    
    def close(self, _catchall = True):
        """closes the connection, releasing all held resources"""
        if self._closed:
            return
        self._closed = True
        try:
            try:
                self._async_request(consts.HANDLE_CLOSE)
            except EOFError:
                pass
            except Exception:
                if not _catchall:
                    raise
        finally:
            self._cleanup(_anyway = True)

    @property
    def closed(self):
        """Indicates whether the connection has been closed or not"""
        return self._closed
    def fileno(self):
        """Returns the connectin's underlying file descriptor"""
        return self._channel.fileno()

    def ping(self, data = None, timeout = 3):
        """       
        Asserts that the other party is functioning properly, by making sure
        the *data* is echoed back before the *timeout* expires
        
        :param data: the data to send (leave ``None`` for the default buffer)
        :param timeout: the maximal time to wait for echo
        
        :raises: :class:`PingError` if the echoed data does not match
        """
        if data is None:
            data = "abcdefghijklmnopqrstuvwxyz" * 20
        res = self.async_request(consts.HANDLE_PING, data, timeout = timeout)
        if res.value != data:
            raise PingError("echo mismatches sent data")

    def _send(self, msg, seq, args):
        data = brine.dump((msg, seq, args))
        self._sendlock.acquire()
        try:
            self._channel.send(data)
        finally:
            self._sendlock.release()
    def _send_request(self, handler, args):
        seq = next(self._seqcounter)
        self._send(consts.MSG_REQUEST, seq, (handler, self._box(args)))
        return seq
    def _send_reply(self, seq, obj):
        self._send(consts.MSG_REPLY, seq, self._box(obj))
    def _send_exception(self, seq, exctype, excval, exctb):
        exc = vinegar.dump(exctype, excval, exctb,
            include_local_traceback = self._config["include_local_traceback"])
        self._send(consts.MSG_EXCEPTION, seq, exc)

    #
    # boxing
    #
    def _box(self, obj):
        """store a local object in such a way that it could be recreated on
        the remote party either by-value or by-reference"""
        if brine.dumpable(obj):
            return consts.LABEL_VALUE, obj
        if type(obj) is tuple:
            return consts.LABEL_TUPLE, tuple(self._box(item) for item in obj)
        elif isinstance(obj, netref.BaseNetref) and obj.____conn__() is self:
            return consts.LABEL_LOCAL_REF, obj.____oid__
        else:
            self._local_objects.add(obj)
            try:
                cls = obj.__class__
            except Exception:
                # see issue #16
                cls = type(obj)
            return consts.LABEL_REMOTE_REF, (id(obj), cls.__name__, cls.__module__)

    def _unbox(self, package):
        """recreate a local object representation of the remote object: if the
        object is passed by value, just return it; if the object is passed by
        reference, create a netref to it"""
        label, value = package
        if label == consts.LABEL_VALUE:
            return value
        if label == consts.LABEL_TUPLE:
            return tuple(self._unbox(item) for item in value)
        if label == consts.LABEL_LOCAL_REF:
            return self._local_objects[value]
        if label == consts.LABEL_REMOTE_REF:
            oid, clsname, modname = value
            if oid in self._proxy_cache:
                return self._proxy_cache[oid]
            proxy = self._netref_factory(oid, clsname, modname)
            self._proxy_cache[oid] = proxy
            return proxy
        raise ValueError("invalid label %r" % (label,))

    def _netref_factory(self, oid, clsname, modname):
        typeinfo = (clsname, modname)
        if typeinfo in self._netref_classes_cache:
            cls = self._netref_classes_cache[typeinfo]
        elif typeinfo in netref.builtin_classes_cache:
            cls = netref.builtin_classes_cache[typeinfo]
        else:
            info = self.sync_request(consts.HANDLE_INSPECT, oid)
            cls = netref.class_factory(clsname, modname, info)
            self._netref_classes_cache[typeinfo] = cls
        return cls(weakref.ref(self), oid)

    #
    # dispatching
    #
    def _dispatch_request(self, seq, raw_args):
        try:
            handler, args = raw_args
            args = self._unbox(args)
            res = self._HANDLERS[handler](self, *args)
        except KeyboardInterrupt:
            raise
        except:
            # need to catch old style exceptions too
            t, v, tb = sys.exc_info()
            self._last_traceback = tb
            if self._config["logger"]:
                self._config["logger"].debug("Exception caught", exc_info=True)
            if t is SystemExit and self._config["propagate_SystemExit_locally"]:
                raise
            self._send_exception(seq, t, v, tb)
        else:
            self._send_reply(seq, res)

    def _dispatch_reply(self, seq, raw):
        obj = self._unbox(raw)
        if seq in self._async_callbacks:
            self._async_callbacks.pop(seq)(False, obj)
        else:
            self._sync_replies[seq] = (False, obj)

    def _dispatch_exception(self, seq, raw):
        obj = vinegar.load(raw,
            import_custom_exceptions = self._config["import_custom_exceptions"],
            instantiate_custom_exceptions = self._config["instantiate_custom_exceptions"],
            instantiate_oldstyle_exceptions = self._config["instantiate_oldstyle_exceptions"])
        if seq in self._async_callbacks:
            self._async_callbacks.pop(seq)(True, obj)
        else:
            self._sync_replies[seq] = (True, obj)

    #
    # serving
    #
    def _recv(self, timeout, wait_for_lock):
        if not self._recvlock.acquire(wait_for_lock):
            return None
        try:
            try:
                if self._channel.poll(timeout):
                    data = self._channel.recv()
                else:
                    data = None
            except EOFError:
                self.close()
                raise
        finally:
            self._recvlock.release()
        return data

    def _dispatch(self, data):
        msg, seq, args = brine.load(data)
        if msg == consts.MSG_REQUEST:
            self._dispatch_request(seq, args)
        elif msg == consts.MSG_REPLY:
            self._dispatch_reply(seq, args)
        elif msg == consts.MSG_EXCEPTION:
            self._dispatch_exception(seq, args)
        else:
            raise ValueError("invalid message type: %r" % (msg,))

    def poll(self, timeout = 0):
        """Serves a single transaction, should one arrives in the given
        interval. Note that handling a request/reply may trigger nested
        requests, which are all part of a single transaction.

        :returns: ``True`` if a transaction was served, ``False`` otherwise"""
        data = self._recv(timeout, wait_for_lock = False)
        if not data:
            return False
        self._dispatch(data)
        return True

    def serve(self, timeout = 1):
        """Serves a single request or reply that arrives within the given
        time frame (default is 1 sec). Note that the dispatching of a request
        might trigger multiple (nested) requests, thus this function may be
        reentrant. 
        
        :returns: ``True`` if a request or reply were received, ``False``
                  otherwise.
        """
        data = self._recv(timeout, wait_for_lock = True)
        if not data:
            return False
        self._dispatch(data)
        return True

    def serve_all(self):
        """Serves all requests and replies for as long as the connection is 
        alive."""
        try:
            try:
                while True:
                    self.serve(0.1)
            except (socket.error, select_error, IOError):
                if not self.closed:
                    raise
            except EOFError:
                pass
        finally:
            self.close()

    def poll_all(self, timeout = 0):
        """Serves all requests and replies that arrive within the given interval.
        
        :returns: ``True`` if at least a single transaction was served, ``False`` otherwise
        """
        at_least_once = False
        t0 = time.time()
        duration = timeout
        try:
            while True:
                if self.poll(duration):
                    at_least_once = True
                if timeout is not None:
                    duration = t0 + timeout - time.time()
                    if duration < 0:
                        break
        except EOFError:
            pass
        return at_least_once

    #
    # requests
    #
    def sync_request(self, handler, *args):
        """Sends a synchronous request (waits for the reply to arrive)
        
        :raises: any exception that the requets may be generated
        :returns: the result of the request
        """
        seq = self._send_request(handler, args)
        while seq not in self._sync_replies:
            self.serve(0.1)
        isexc, obj = self._sync_replies.pop(seq)
        if isexc:
            raise obj
        else:
            return obj

    def _async_request(self, handler, args = (), callback = (lambda a, b: None)):
        seq = self._send_request(handler, args)
        self._async_callbacks[seq] = callback
    def async_request(self, handler, *args, **kwargs):
        """Send an asynchronous request (does not wait for it to finish)
        
        :returns: an :class:`rpyc.core.async.AsyncResult` object, which will
                  eventually hold the result (or exception)
        """
        timeout = kwargs.pop("timeout", None)
        if kwargs:
            raise TypeError("got unexpected keyword argument(s) %s" % (list(kwargs.keys()),))
        res = AsyncResult(weakref.proxy(self))
        self._async_request(handler, args, res)
        if timeout is not None:
            res.set_expiry(timeout)
        return res

    @property
    def root(self):
        """Fetches the root object (service) of the other party"""
        if self._remote_root is None:
            self._remote_root = self.sync_request(consts.HANDLE_GETROOT)
        return self._remote_root

    #
    # attribute access
    #
    def _check_attr(self, obj, name):
        if self._config["allow_exposed_attrs"]:
            if name.startswith(self._config["exposed_prefix"]):
                name2 = name
            else:
                name2 = self._config["exposed_prefix"] + name
            if hasattr(obj, name2):
                return name2
        if self._config["allow_all_attrs"]:
            return name
        if self._config["allow_safe_attrs"] and name in self._config["safe_attrs"]:
            return name
        if self._config["allow_public_attrs"] and not name.startswith("_"):
            return name
        return False

    def _access_attr(self, oid, name, args, overrider, param, default):
        if is_py3k:
            if type(name) is bytes:
                name = str(name, "utf8")
            elif type(name) is not str:
                raise TypeError("name must be a string")
        else:
            if type(name) not in (str, unicode):
                raise TypeError("name must be a string")
            name = str(name) # IronPython issue #10 + py3k issue
        obj = self._local_objects[oid]
        accessor = getattr(type(obj), overrider, None)
        if accessor is None:
            name2 = self._check_attr(obj, name)
            if not self._config[param] or not name2:
                raise AttributeError("cannot access %r" % (name,))
            accessor = default
            name = name2
        return accessor(obj, name, *args)

    #
    # request handlers
    #
    def _handle_ping(self, data):
        return data
    def _handle_close(self):
        self._cleanup()
    def _handle_getroot(self):
        return self._local_root
    def _handle_del(self, oid):
        self._local_objects.decref(oid)
    def _handle_repr(self, oid):
        return repr(self._local_objects[oid])
    def _handle_str(self, oid):
        return str(self._local_objects[oid])
    def _handle_cmp(self, oid, other):
        # cmp() might enter recursive resonance... yet another workaround
        #return cmp(self._local_objects[oid], other)
        obj = self._local_objects[oid]
        try:
            return type(obj).__cmp__(obj, other)
        except (AttributeError, TypeError):
            return NotImplemented
    def _handle_hash(self, oid):
        return hash(self._local_objects[oid])
    def _handle_call(self, oid, args, kwargs=()):
        return self._local_objects[oid](*args, **dict(kwargs))
    def _handle_dir(self, oid):
        return tuple(dir(self._local_objects[oid]))
    def _handle_inspect(self, oid):
        return tuple(netref.inspect_methods(self._local_objects[oid]))
    def _handle_getattr(self, oid, name):
        return self._access_attr(oid, name, (), "_rpyc_getattr", "allow_getattr", getattr)
    def _handle_delattr(self, oid, name):
        return self._access_attr(oid, name, (), "_rpyc_delattr", "allow_delattr", delattr)
    def _handle_setattr(self, oid, name, value):
        return self._access_attr(oid, name, (value,), "_rpyc_setattr", "allow_setattr", setattr)
    def _handle_callattr(self, oid, name, args, kwargs):
        return self._handle_getattr(oid, name)(*args, **dict(kwargs))
    def _handle_pickle(self, oid, proto):
        if not self._config["allow_pickle"]:
            raise ValueError("pickling is disabled")
        return pickle.dumps(self._local_objects[oid], proto)
    def _handle_buffiter(self, oid, count):
        items = []
        obj = self._local_objects[oid]
        i = 0
        try:
            while i < count:
                items.append(next(obj))
                i += 1
        except StopIteration:
            pass
        return tuple(items)
    def _handle_oldslicing(self, oid, attempt, fallback, start, stop, args):
        try:
            # first try __xxxitem__
            getitem = self._handle_getattr(oid, attempt)
            return getitem(slice(start, stop), *args)
        except Exception:
            # fallback to __xxxslice__. see issue #41
            if stop is None:
                stop = maxint
            getslice = self._handle_getattr(oid, fallback)
            return getslice(start, stop, *args)

    # collect handlers
    _HANDLERS = {}
    for name, obj in dict(locals()).items():
        if name.startswith("_handle_"):
            name2 = "HANDLE_" + name[8:].upper()
            if hasattr(consts, name2):
                _HANDLERS[getattr(consts, name2)] = obj
            else:
                raise NameError("no constant defined for %r", name)
    del name, name2, obj

