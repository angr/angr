"""
compatibility module for various versions of python (2.4/3+/jython)
and various platforms (posix/windows)
"""
import sys

is_py3k = (sys.version_info[0] >= 3)

if is_py3k:
    exec("execute = exec")
    def BYTES_LITERAL(text):
        return bytes(text, "utf8")
    maxint = sys.maxsize
else:
    exec("""def execute(code, globals = None, locals = None):
                exec code in globals, locals""")
    def BYTES_LITERAL(text):
        return text
    maxint = sys.maxint

try:
    from struct import Struct #@UnusedImport
except ImportError:
    import struct
    class Struct(object):
        __slots__ = ["format", "size"]
        def __init__(self, format):
            self.format = format
            self.size = struct.calcsize(format)
        def pack(self, *args):
            return struct.pack(self.format, *args)
        def unpack(self, data):
            return struct.unpack(self.format, data)

try:
    from cStringIO import StringIO as BytesIO
except ImportError:
    from io import BytesIO #@UnusedImport

try:
    next = next
except NameError:
    def next(iterator):
        return iterator.next()

try:
    all = all
except NameError:
    def all(seq):
        for elem in seq:
            if not elem:
                return False
        return True

try:
    import cPickle as pickle
except ImportError:
    import pickle #@UnusedImport

try:
    callable = callable
except NameError:
    def callable(obj):
        return hasattr(obj, "__call__")

try:
    import select as select_module
except ImportError:
    select_module = None
    def select(*args):
        raise ImportError("select not supported on this platform")
else:
    # jython
    if hasattr(select_module, 'cpython_compatible_select'):
        from select import cpython_compatible_select as select
    else:
        from select import select

def get_exc_errno(exc):
    if hasattr(exc, "errno"):
        return exc.errno
    else:
        return exc[0]

if select_module:
    select_error = select_module.error
else:
    select_error = IOError

if hasattr(select_module, "poll"):
    class PollingPoll(object):
        def __init__(self):
            self._poll = select_module.poll()
        def register(self, fd, mode):
            flags = 0
            if "r" in mode:
                flags |= select_module.POLLIN
            if "w" in mode:
                flags |= select_module.POLLOUT
            self._poll.register(fd, flags)
        modify = register
        def unregister(self, fd):
            self._poll.unregister(fd)
        def poll(self, timeout = None):
            events = self._poll.poll(timeout)
            processed = []
            for fd, evt in events:
                mask = ""
                if evt & (select_module.POLLIN | select_module.POLLPRI):
                    mask += "r"
                if evt & select_module.POLLOUT:
                    mask += "w"
                if evt & select_module.POLLERR:
                    mask += "e"
                if evt & select_module.POLLHUP:
                    mask += "h"
                if evt & select_module.POLLNVAL:
                    mask += "n"
                processed.append((fd, mask))
            return processed
    
    poll = PollingPoll
else:
    class SelectingPoll(object):
        def __init__(self):
            self.rlist = set()
            self.wlist = set()
        def register(self, fd, mode):
            if "r" in mode:
                self.rlist.append(fd)
            if "w" in mode:
                self.wlist.append(fd)
        modify = register
        def unregister(self, fd):
            self.rlist.discard(fd)
            self.wlist.discard(fd)
        def poll(self, timeout = None):
            rl, wl, _ = select(self.rlist, self.wlist, (), timeout)
            return [(fd, "r") for fd in rl] + [(fd, "w") for fd in wl]
    
    poll = SelectingPoll


