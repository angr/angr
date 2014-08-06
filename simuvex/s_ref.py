# This module contains data structures for handling memory, code, and register references.

import logging
l = logging.getLogger('s_ref')

#
# Some utility functions
#

# Get a string description of the data
def dep_str(data, data_reg_deps=None, data_tmp_deps=None):
    if type(data) in (int, long):
        dstr = "0x%x" % data
    elif data.symbolic:
        dstr = "symbolic"
    else:
        e = data.eval()
        if type(e) in (int, long): dstr = "0x%x" % e
        else: dstr = "%s" % e

    if data_reg_deps is not None and data_tmp_deps is not None:
        return "(%s, reg_deps %s, tmp_deps %s)" % (dstr, tuple(data_reg_deps), tuple(data_tmp_deps))
    else:
        return "(%s)" % dstr

#
# Check if a ref is symbolic.
#

# A SimRef tracks a code, register, or memory reference. Depending on the type
# of subclass used, it has different members to access data. The subclass has:
#
#    inst_addr - the (int) address of the instruction where the reference occurred
class SimRef(object):
    symbolic_keys = [ ]

    def __init__(self, inst_addr, stmt_idx):
        self.inst_addr = inst_addr
        self.stmt_idx = stmt_idx

    def __repr__(self):
        if self.inst_addr is None:
            return "(stmt %d)" % (self.stmt_idx)
        else:
            return "(inst 0x%x, stmt %d)" % (self.inst_addr, self.stmt_idx)

    def is_symbolic(self):
        for k in self.symbolic_keys:
            v = getattr(self, k)
            if type(v) not in (int, long, float, str, bool, unicode) and v.symbolic:
                return True
        return False

# A SimMemRead tracks memory read operations. It has the following members:
#
#    addr - the (SimValue) address of the memory location
#    data - the (SimValue) data that was read
#    size - the (int) size of the read
#    addr_reg_deps - a list of register dependencies of the address, in offset form
#    addr_tmp_deps - a list of tmp dependencies of the address, in offset form
class SimMemRead(SimRef):
    symbolic_keys = [ 'addr' ]

    def __init__(self, inst_addr, stmt_idx, addr, data, size, addr_reg_deps = (), addr_tmp_deps = ()):
        SimRef.__init__(self, inst_addr, stmt_idx)
        self.addr = addr
        self.data = data
        self.size = size
        self.addr_reg_deps = tuple(addr_reg_deps)
        self.addr_tmp_deps = tuple(addr_tmp_deps)
        l.debug("Created ref: %s", self)

    def __repr__(self):
        return "<SimMemRead at %s: *%s == %s, size %s>" % (SimRef.__repr__(self), dep_str(self.addr, self.addr_reg_deps, self.addr_tmp_deps), dep_str(self.data), self.size)

# A SimMemWrite tracks memory write operations. It has the following members:
#
#    addr - the (SimValue) address of the memory location
#    data - the (SimValue) data that was written
#    size - the (int) size of the write
#    addr_reg_deps - a list of register dependencies of the address, in offset form
#    addr_tmp_deps - a list of tmp dependencies of the address, in offset form
#    data_reg_deps - a list of register dependencies of the data, in offset form
#    data_tmp_deps - a list of tmp dependencies of the data, in offset form
class SimMemWrite(SimRef):
    symbolic_keys = [ 'addr' ]

    def __init__(self, inst_addr, stmt_idx, addr, data, size, addr_reg_deps=(), addr_tmp_deps=(), data_reg_deps=(), data_tmp_deps=()):
        SimRef.__init__(self, inst_addr, stmt_idx)
        self.addr = addr
        self.data = data
        self.size = size
        self.addr_reg_deps = tuple(addr_reg_deps)
        self.addr_tmp_deps = tuple(addr_tmp_deps)
        self.data_reg_deps = tuple(data_reg_deps)
        self.data_tmp_deps = tuple(data_tmp_deps)
        l.debug("Created ref: %s", self)

    def __repr__(self):
        return "<SimMemWrite at %s: *%s = %s, size %s>" % (SimRef.__repr__(self), dep_str(self.addr, self.addr_reg_deps, self.addr_tmp_deps), dep_str(self.data, self.data_reg_deps, self.data_tmp_deps), self.size)

# A SimMemRef tracks memory references (for example, computed addresses). It has the following members:
#
#    addr - the (SimValue) address of the memory reference
#    addr_reg_deps - a list of register dependencies of the address, in offset form
#    addr_tmp_deps - a list of tmp dependencies of the address, in offset form
class SimMemRef(SimRef):
    symbolic_keys = [ 'addr' ]

    def __init__(self, inst_addr, stmt_idx, addr, addr_reg_deps = (), addr_tmp_deps = ()):
        SimRef.__init__(self, inst_addr, stmt_idx)
        self.addr = addr
        self.addr_reg_deps = tuple(addr_reg_deps)
        self.addr_tmp_deps = tuple(addr_tmp_deps)
        l.debug("Created ref: %s", self)

    def __repr__(self):
        return "<SimMemRef at %s to %s>" % (SimRef.__repr__(self), dep_str(self.addr, self.addr_reg_deps, self.addr_tmp_deps))

# A SimRegRead tracks register read operations. It has the following members:
#
#    offset - the (int) offset of the register
#    data - the (SimValue) data that was written
#    size - the (int) size of the write
class SimRegRead(SimRef):
    symbolic_keys = [ ]

    def __init__(self, inst_addr, stmt_idx, offset, data, size):
        SimRef.__init__(self, inst_addr, stmt_idx)
        self.offset = offset
        self.data = data
        self.size = size
        l.debug("Created ref: %s", self)

    def __repr__(self):
        return "<SimRegRead at %s: regs[%d] == %s, size %s>" % (SimRef.__repr__(self), self.offset, dep_str(self.data), self.size)

# A SimRegWrite tracks register write operations. It has the following members:
#
#    offset - the (int) offset of the memory location
#    data - the (SimValue) data that was written
#    size - the (int) size of the write
#    data_reg_deps - a list of register dependencies of the data, in offset form
#    data_tmp_deps - a list of tmp dependencies of the data, in offset form
class SimRegWrite(SimRef):
    symbolic_keys = [ ]

    def __init__(self, inst_addr, stmt_idx, offset, data, size, data_reg_deps=(), data_tmp_deps=()):
        SimRef.__init__(self, inst_addr, stmt_idx)
        self.offset = offset
        self.data = data
        self.data_reg_deps = tuple(data_reg_deps)
        self.data_tmp_deps = tuple(data_tmp_deps)
        self.size = size
        l.debug("Created ref: %s", self)

    def __repr__(self):
        return "<SimRegWrite at %s: regs[%d] = %s, size %s>" % (SimRef.__repr__(self), self.offset, dep_str(self.data, self.data_reg_deps, self.data_tmp_deps), self.size)

# A SimTmpRead tracks register read operations. It has the following members:
#
#    tmp - the (int) tmp
#    data - the (SimValue) data that was written
#    size - the (int) size of the tmp
class SimTmpRead(SimRef):
    symbolic_keys = [ ]

    def __init__(self, inst_addr, stmt_idx, tmp, data, size):
        SimRef.__init__(self, inst_addr, stmt_idx)
        self.tmp = tmp
        self.data = data
        self.size = size
        l.debug("Created ref: %s", self)

    def __repr__(self):
        return "<SimTmpRead at %s: t%d == %s, size %s>" % (SimRef.__repr__(self), self.tmp, dep_str(self.data), self.size)

# A SimTmpWrite tracks register write operations. It has the following members:
#
#    tmp - the (int) tmp
#    data - the (SimValue) data that was written
#    size - the (int) size of the tmp
#    data_reg_deps - a list of register dependencies of the data, in offset form
#    data_tmp_deps - a list of tmp dependencies of the data, in offset form
class SimTmpWrite(SimRef):
    symbolic_keys = [ ]

    def __init__(self, inst_addr, stmt_idx, tmp, data, size, data_reg_deps, data_tmp_deps):
        SimRef.__init__(self, inst_addr, stmt_idx)
        self.tmp = tmp
        self.data = data
        self.data_reg_deps = tuple(data_reg_deps)
        self.data_tmp_deps = tuple(data_tmp_deps)
        self.size = size
        l.debug("Created ref: %s", self)

    def __repr__(self):
        return "<SimTmpWrite at %s: t%d = %s, size %s>" % (SimRef.__repr__(self), self.tmp, dep_str(self.data, self.data_reg_deps, self.data_tmp_deps), self.size)

# A SimCodeRef tracks code references. It has the following members:
#
#    addr - the (SimValue) address of the code reference
#    addr_reg_deps - a list of register dependencies of the address, in offset form
#    addr_tmp_deps - a list of tmp dependencies of the address, in offset form
class SimCodeRef(SimRef):
    symbolic_keys = [ 'addr' ]

    def __init__(self, inst_addr, stmt_idx, addr, addr_reg_deps = (), addr_tmp_deps = ()):
        SimRef.__init__(self, inst_addr, stmt_idx)
        self.addr = addr
        self.addr_reg_deps = tuple(addr_reg_deps)
        self.addr_tmp_deps = tuple(addr_tmp_deps)
        l.debug("Created ref: %s", self)

    def __repr__(self):
        return "<SimCodeRef at %s to %s>" % (SimRef.__repr__(self), dep_str(self.addr, self.addr_reg_deps, self.addr_tmp_deps))

# A SimFileRead tracks memory read operations. It has the following members:
#
#    fd - the file descriptor
#    addr - the (SimValue) address of the memory location
#    data - the (SimValue) data that was read
#    size - the (int) size of the read
#    addr_reg_deps - a list of register dependencies of the address, in offset form
#    addr_tmp_deps - a list of tmp dependencies of the address, in offset form
class SimFileRead(SimRef):
    symbolic_keys = [ 'addr', 'fd' ]

    def __init__(self, inst_addr, stmt_idx, fd, addr, data, size, addr_reg_deps = (), addr_tmp_deps = ()):
        SimRef.__init__(self, inst_addr, stmt_idx)
        self.fd = fd
        self.addr = addr
        self.data = data
        self.size = size
        self.addr_reg_deps = tuple(addr_reg_deps)
        self.addr_tmp_deps = tuple(addr_tmp_deps)
        l.debug("Created ref: %s", self)

    def __repr__(self):
        return "<SimFileRead at %s: fd %s, *%s == %s, size %s>" % (SimRef.__repr__(self), dep_str(self.fd), dep_str(self.addr, self.addr_reg_deps, self.addr_tmp_deps), dep_str(self.data), self.size)

# A SimFileWrite tracks memory write operations. It has the following members:
#
#    fd - the file descriptor
#    addr - the (SimValue) address of the memory location
#    data - the (SimValue) data that was written
#    size - the (int) size of the write
#    addr_reg_deps - a list of register dependencies of the address, in offset form
#    addr_tmp_deps - a list of tmp dependencies of the address, in offset form
#    data_reg_deps - a list of register dependencies of the data, in offset form
#    data_tmp_deps - a list of tmp dependencies of the data, in offset form
class SimFileWrite(SimRef):
    symbolic_keys = [ 'addr', 'fd' ]

    def __init__(self, inst_addr, stmt_idx, fd, addr, data, size, addr_reg_deps=(), addr_tmp_deps=(), data_reg_deps=(), data_tmp_deps=()):
        SimRef.__init__(self, inst_addr, stmt_idx)
        self.fd = fd
        self.addr = addr
        self.data = data
        self.size = size
        self.addr_reg_deps = tuple(addr_reg_deps)
        self.addr_tmp_deps = tuple(addr_tmp_deps)
        self.data_reg_deps = tuple(data_reg_deps)
        self.data_tmp_deps = tuple(data_tmp_deps)
        l.debug("Created ref: %s", self)

    def __repr__(self):
        return "<SimFileWrite at %s: fd %s, *%s = %s, size %s>" % (SimRef.__repr__(self), dep_str(self.fd), dep_str(self.addr, self.addr_reg_deps, self.addr_tmp_deps), dep_str(self.data, self.data_reg_deps, self.data_tmp_deps), self.size)

RefTypes = ( SimMemWrite, SimMemRead, SimMemRef, SimCodeRef, SimRegRead, SimRegWrite, SimTmpRead, SimTmpWrite, SimFileRead, SimFileWrite )
