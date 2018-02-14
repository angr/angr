
from archinfo.arch_soot import SootAddressDescriptor, SootMethodDescriptor


def repr_addr(addr, x=True):
    if type(addr) in (int, long):
        if x:
            return "%#x" % addr
        else:
            return hex(addr)
    elif isinstance(addr, (SootAddressDescriptor, SootMethodDescriptor)):
        return repr(addr)
    else:
        raise NotImplementedError("Unsupported address type %s." % type(addr))
