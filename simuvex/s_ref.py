# This module contains data structures for handling memory, code, and register references.

import abc
import logging
l = logging.getLogger('s_ref')

# A SimRef tracks a code, register, or memory reference. Depending on the type
# of subclass used, it has different members to access data. The subclass has:
#
# 	inst_addr - the (int) address of the instruction where the reference occurred
class SimRef(object):
	def __init__(self, inst_addr):
		self.inst_addr = inst_addr

	@abc.abstractmethod
	def is_symbolic(self):
		self = self

# A SimMemRead tracks memory read operations. It has the following members:
#
#	addr - the (SimValue) address of the memory location
#	data - the (SimValue) data that was read
#	size - the (int) size of the read
#	addr_reg_deps - a list of register dependencies of the address, in offset form
#	addr_tmp_deps - a list of tmp dependencies of the address, in offset form
class SimMemRead(SimRef):
	def __init__(self, inst_addr, addr, data, size, addr_reg_deps, addr_tmp_deps):
		SimRef.__init__(self, inst_addr)
		self.addr = addr
		self.data = data
		self.size = size
		self.addr_reg_deps = addr_reg_deps
		self.addr_tmp_deps = addr_tmp_deps
		l.debug("Created ref: %s", self)

	def is_symbolic(self):
		return self.addr.is_symbolic()

	def __repr__(self):
		addr_str = "0x%x" % self.addr.any() if not self.addr.is_symbolic() else "(symbolic)"
		data_str = None if self.data is None else "0x%x" % self.data.any() if not self.data.is_symbolic() else "(symbolic)"
		return "<SimMemRead from 0x%x: *%s == %s, size %d, regdeps %s, tmpdeps %s>" % (self.inst_addr, addr_str, data_str, self.size, self.addr_reg_deps, self.addr_tmp_deps)

# A SimMemWrite tracks memory write operations. It has the following members:
#
#	addr - the (SimValue) address of the memory location
#	data - the (SimValue) data that was written
#	size - the (int) size of the write
#	addr_reg_deps - a list of register dependencies of the address, in offset form
#	addr_tmp_deps - a list of tmp dependencies of the address, in offset form
class SimMemWrite(SimRef):
	def __init__(self, inst_addr, addr, data, size, addr_reg_deps, addr_tmp_deps):
		SimRef.__init__(self, inst_addr)
		self.addr = addr
		self.data = data
		self.size = size
		self.addr_reg_deps = addr_reg_deps
		self.addr_tmp_deps = addr_tmp_deps
		l.debug("Created ref: %s", self)

	def is_symbolic(self):
		return self.addr.is_symbolic()

	def __repr__(self):
		addr_str = "0x%x" % self.addr.any() if not self.addr.is_symbolic() else "(symbolic)"
		data_str = None if self.data is None else "0x%x" % self.data.any() if not self.data.is_symbolic() else "(symbolic)"
		return "<SimMemWrite from 0x%x: *%s = %s, size %d, regdeps %s, tmpdeps %s>" % (self.inst_addr, addr_str, data_str, self.size, self.addr_reg_deps, self.addr_tmp_deps)

# A SimMemRef tracks memory references (for example, computed addresses). It has the following members:
#
#	addr - the (SimValue) address of the memory reference
#	addr_reg_deps - a list of register dependencies of the address, in offset form
#	addr_tmp_deps - a list of tmp dependencies of the address, in offset form
class SimMemRef(SimRef):
	def __init__(self, inst_addr, addr, addr_reg_deps, addr_tmp_deps):
		SimRef.__init__(self, inst_addr)
		self.addr = addr
		self.addr_reg_deps = addr_reg_deps
		self.addr_tmp_deps = addr_tmp_deps
		l.debug("Created ref: %s", self)

	def is_symbolic(self):
		return self.addr.is_symbolic()

	def __repr__(self):
		addr_str = "0x%x" % self.addr.any() if not self.addr.is_symbolic() else "(symbolic)"
		return "<SimMemRef at 0x%x to %s, regdeps %s, tmpdeps %s>" % (self.inst_addr, addr_str, self.addr_reg_deps, self.addr_tmp_deps)

# A SimRegRead tracks register read operations. It has the following members:
#
#	offset - the (int) offset of the register
#	data - the (SimValue) data that was written
#	size - the (int) size of the write
class SimRegRead(SimRef):
	def __init__(self, inst_addr, offset, data, size):
		SimRef.__init__(self, inst_addr)
		self.offset = offset
		self.data = data
		self.size = size
		l.debug("Created ref: %s", self)

	def is_symbolic(self):
		return False

	def __repr__(self):
		data_str = None if self.data is None else "0x%x" % self.data.any() if not self.data.is_symbolic() else "(symbolic)"
		return "<SimRegRead at 0x%x: regs[%d] == %s, size %d>" % (self.inst_addr, self.offset, data_str, self.size)

# A SimRegWrite tracks register write operations. It has the following members:
#
#	offset - the (int) offset of the memory location
#	data - the (SimValue) data that was written
#	size - the (int) size of the write
class SimRegWrite(SimRef):
	def __init__(self, inst_addr, offset, data, size):
		SimRef.__init__(self, inst_addr)
		self.offset = offset
		self.data = data
		self.size = size
		l.debug("Created ref: %s", self)

	def is_symbolic(self):
		return False

	def __repr__(self):
		data_str = None if self.data is None else "0x%x" % self.data.any() if not self.data.is_symbolic() else "(symbolic)"
		return "<SimRegWrite at 0x%x: regs[%d] = %s, size %d>" % (self.inst_addr, self.offset, data_str, self.size)

# A SimTmpRead tracks register read operations. It has the following members:
#
#	tmp - the (int) tmp
#	data - the (SimValue) data that was written
#	size - the (int) size of the tmp
class SimTmpRead(SimRef):
	def __init__(self, inst_addr, tmp, data, size):
		SimRef.__init__(self, inst_addr)
		self.tmp = tmp
		self.data = data
		self.size = size
		l.debug("Created ref: %s", self)

	def is_symbolic(self):
		return False

	def __repr__(self):
		data_str = None if self.data is None else "0x%x" % self.data.any() if not self.data.is_symbolic() else "(symbolic)"
		return "<SimTmpRead at 0x%x: t%d == %s, size %d>" % (self.inst_addr, self.tmp, data_str, self.size)

# A SimTmpWrite tracks register write operations. It has the following members:
#
#	tmp - the (int) tmp
#	data - the (SimValue) data that was written
#	size - the (int) size of the tmp
class SimTmpWrite(SimRef):
	def __init__(self, inst_addr, tmp, data, size):
		SimRef.__init__(self, inst_addr)
		self.tmp = tmp
		self.data = data
		self.size = size
		l.debug("Created ref: %s", self)

	def is_symbolic(self):
		return False

	def __repr__(self):
		data_str = None if self.data is None else "0x%x" % self.data.any() if not self.data.is_symbolic() else "(symbolic)"
		return "<SimTmpWrite at 0x%x: t%d = %s, size %d>" % (self.inst_addr, self.tmp, data_str, self.size)

# A SimCodeRef tracks code references. It has the following members:
#
#	addr - the (SimValue) address of the code reference
#	addr_reg_deps - a list of register dependencies of the address, in offset form
#	addr_tmp_deps - a list of tmp dependencies of the address, in offset form
class SimCodeRef(SimRef):
	def __init__(self, inst_addr, addr, addr_reg_deps, addr_tmp_deps):
		SimRef.__init__(self, inst_addr)
		self.addr = addr
		self.addr_reg_deps = addr_reg_deps
		self.addr_tmp_deps = addr_tmp_deps
		l.debug("Created ref: %s", self)

	def is_symbolic(self):
		return self.addr.is_symbolic()

	def __repr__(self):
		addr_str = "0x%x" % self.addr.any() if not self.addr.is_symbolic() else "(symbolic)"
		return "<SimCodeRef at 0x%x to %s, regdeps %s, tmpdeps %s>" % (self.inst_addr, addr_str, self.addr_reg_deps, self.addr_tmp_deps)

RefTypes = ( SimMemWrite, SimMemRead, SimMemRef, SimCodeRef, SimRegRead, SimRegWrite, SimTmpRead, SimTmpWrite )
