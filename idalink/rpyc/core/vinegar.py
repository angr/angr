"""
**Vinegar** ("when things go sour") is a safe serializer for exceptions.
The :data`configuration parameters <rpyc.core.protocol.DEFAULT_CONFIG>` control
its mode of operation, for instance, whether to allow *old-style* exceptions 
(that do not derive from ``Exception``), whether to allow the :func:`load` to
import custom modules (imposes a security risk), etc. 

Note that by changing the configuration parameters, this module can be made 
non-secure. Keep this in mind.
"""
import sys
import traceback
try:
    import exceptions as exceptions_module
except ImportError:
    import builtins as exceptions_module
try:
    from types import InstanceType, ClassType
except ImportError:
    ClassType = type

from rpyc.core import brine
from rpyc.core import consts
from rpyc.lib.compat import is_py3k


try:
    BaseException
except NameError:
    # python 2.4 compatible
    BaseException = Exception

def dump(typ, val, tb, include_local_traceback):
    """Dumps the given exceptions info, as returned by ``sys.exc_info()``
    
    :param typ: the exception's type (class)
    :param val: the exceptions' value (instance)
    :param tb: the exception's traceback (a ``traceback`` object)
    :param include_local_traceback: whether or not to include the local traceback
                                    in the dumped info. This may expose the other
                                    side to implementation details (code) and 
                                    package structure, and may theoretically impose
                                    a security risk.
    
    :returns: A tuple of ``((module name, exception name), arguments, attributes, 
              traceback text)``. This tuple can be safely passed to 
              :func:`brine.dump <rpyc.core.brine.dump>`
    """
    if typ is StopIteration:
        return consts.EXC_STOP_ITERATION # optimization
    if type(typ) is str:
        return typ

    if include_local_traceback:
        tbtext = "".join(traceback.format_exception(typ, val, tb))
    else:
        tbtext = "<traceback denied>"
    attrs = []
    args = []
    ignored_attrs = frozenset(["_remote_tb", "with_traceback"])
    for name in dir(val):
        if name == "args":
            for a in val.args:
                if brine.dumpable(a):
                    args.append(a)
                else:
                    args.append(repr(a))
        elif name.startswith("_") or name in ignored_attrs:
            continue
        else:
            attrval = getattr(val, name)
            if not brine.dumpable(attrval):
                attrval = repr(attrval)
            attrs.append((name, attrval))
    return (typ.__module__, typ.__name__), tuple(args), tuple(attrs), tbtext

def load(val, import_custom_exceptions, instantiate_custom_exceptions, instantiate_oldstyle_exceptions):
    """
    Loads a dumped exception (the tuple returned by :func:`dump`) info a 
    throwable exception object. If the exception cannot be instantiated for any
    reason (i.e., the security parameters do not allow it, or the exception 
    class simply doesn't exist on the local machine), a :class:`GenericException`
    instance will be returned instead, containing all of the original exception's
    details.
    
    :param val: the dumped exception
    :param import_custom_exceptions: whether to allow this function to import custom modules 
                                     (imposes a security risk)
    :param instantiate_custom_exceptions: whether to allow this function to instantiate "custom 
                                          exceptions" (i.e., not one of the built-in exceptions,
                                          such as ``ValueError``, ``OSError``, etc.)
    :param instantiate_oldstyle_exceptions: whether to allow this function to instantiate exception 
                                            classes that do not derive from ``BaseException``.
                                            This is required to support old-style exceptions. 
                                            Not applicable for Python 3 and above.
    
    :returns: A throwable exception object
    """
    if val == consts.EXC_STOP_ITERATION:
        return StopIteration # optimization
    if type(val) is str:
        return val # deprecated string exceptions

    (modname, clsname), args, attrs, tbtext = val
    if import_custom_exceptions and modname not in sys.modules:
        try:
            __import__(modname, None, None, "*")
        except ImportError:
            pass
    
    if instantiate_custom_exceptions:
        if modname in sys.modules:
            cls = getattr(sys.modules[modname], clsname, None)
        else:
            cls = None
    elif modname == exceptions_module.__name__:
        cls = getattr(exceptions_module, clsname, None)
    else:
        cls = None

    if is_py3k:
        if not isinstance(cls, type) or not issubclass(cls, BaseException):
            cls = None
    else:
        if not isinstance(cls, (type, ClassType)):
            cls = None
        elif issubclass(cls, ClassType) and not instantiate_oldstyle_exceptions:
            cls = None
        elif not issubclass(cls, BaseException):
            cls = None

    if cls is None:
        fullname = "%s.%s" % (modname, clsname)
        if fullname not in _generic_exceptions_cache:
            fakemodule = {"__module__" : "%s/%s" % (__name__, modname)}
            if isinstance(GenericException, ClassType):
                _generic_exceptions_cache[fullname] = ClassType(fullname, (GenericException,), fakemodule)
            else:
                _generic_exceptions_cache[fullname] = type(fullname, (GenericException,), fakemodule)
        cls = _generic_exceptions_cache[fullname]

    cls = _get_exception_class(cls)
    
    # support old-style exception classes
    if ClassType is not type and isinstance(cls, ClassType):
        exc = InstanceType(cls)
    else:
        exc = cls.__new__(cls)

    exc.args = args
    for name, attrval in attrs:
        setattr(exc, name, attrval)
    exc._remote_tb = tbtext
    return exc


class GenericException(Exception):
    """A 'generic exception' that is raised when the exception the gotten from
    the other party cannot be instantiated locally"""
    pass

_generic_exceptions_cache = {}
_exception_classes_cache = {}

def _get_exception_class(cls):
    if cls in _exception_classes_cache:
        return _exception_classes_cache[cls]

    # subclass the exception class' to provide a version of __str__ that supports _remote_tb
    class Derived(cls):
        def __str__(self):
            text = cls.__str__(self)
            if hasattr(self, "_remote_tb"):
                text += "\n\n========= Remote Traceback (%d) =========\n%s" % (
                    self._remote_tb.count("\n\n========= Remote Traceback") + 1, self._remote_tb)
            return text
    Derived.__name__ = cls.__name__
    Derived.__module__ = cls.__module__
    _exception_classes_cache[cls] = Derived
    return Derived

