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
#	register_deps - a list of register dependencies of the address, in offset form
class SimMemRead(SimRef):
	def __init__(self, inst_addr, addr, data, size, reg_deps):
		SimRef.__init__(self, inst_addr)
		self.addr = addr
		self.data = data
		self.size = size
		self.register_deps = reg_deps
		l.debug("Created ref: %s" % self)

	def is_symbolic(self):
		return self.addr.is_symbolic()

	def __repr__(self):
		addr_str = "0x%x" % self.addr.any() if not self.addr.is_symbolic() else "(symbolic)"
		data_str = "0x%x" % self.data.any() if not self.data.is_symbolic() else "(symbolic)"
		return "SimMemRead from 0x%x: *%s == %s, size %d, regdeps %s" % (self.inst_addr, addr_str, data_str, self.size, self.register_deps)

# A SimMemWrite tracks memory write operations. It has the following members:
#
#	addr - the (SimValue) address of the memory location
#	data - the (SimValue) data that was written
#	size - the (int) size of the write
#	register_deps - a list of register dependencies of the address, in offset form
class SimMemWrite(SimRef):
	def __init__(self, inst_addr, addr, data, size, reg_deps):
		SimRef.__init__(self, inst_addr)
		self.addr = addr
		self.data = data
		self.size = size
		self.register_deps = reg_deps
		l.debug("Created ref: %s" % self)

	def is_symbolic(self):
		return self.addr.is_symbolic()

	def __repr__(self):
		addr_str = "0x%x" % self.addr.any() if not self.addr.is_symbolic() else "(symbolic)"
		data_str = "0x%x" % self.data.any() if not self.data.is_symbolic() else "(symbolic)"
		return "SimMemWrite from 0x%x: *%s = %s, size %d, regdeps %s" % (self.inst_addr, addr_str, data_str, self.size, self.register_deps)

# A SimMemRef tracks memory references (for example, computed addresses). It has the following members:
#
#	addr - the (SimValue) address of the memory reference
#	register_deps - a list of register dependencies of the address, in offset form
class SimMemRef(SimRef):
	def __init__(self, inst_addr, addr, reg_deps):
		SimRef.__init__(self, inst_addr)
		self.addr = addr
		self.register_deps = reg_deps
		l.debug("Created ref: %s" % self)

	def is_symbolic(self):
		return self.addr.is_symbolic()

	def __repr__(self):
		addr_str = "0x%x" % self.addr.any() if not self.addr.is_symbolic() else "(symbolic)"
		return "SimMemRef at 0x%x to %s, regdeps %s" % (self.inst_addr, addr_str, self.register_deps)

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
		l.debug("Created ref: %s" % self)

	def is_symbolic(self):
		return False

	def __repr__(self):
		data_str = "0x%x" % self.data.any() if not self.data.is_symbolic() else "(symbolic)"
		return "SimRegRead at 0x%x: regs[%d] == %s, size %d" % (self.inst_addr, self.offset, data_str, self.size)

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
		l.debug("Created ref: %s" % self)

	def is_symbolic(self):
		return False

	def __repr__(self):
		data_str = "0x%x" % self.data.any() if not self.data.is_symbolic() else "(symbolic)"
		return "SimRegWrite at 0x%x: regs[%d] = %s, size %d" % (self.inst_addr, self.offset, data_str, self.size)

# A SimCodeRef tracks code references. It has the following members:
#
#	addr - the (SimValue) address of the code reference
#	register_deps - a list of register dependencies of the address, in offset form
class SimCodeRef(SimRef):
	def __init__(self, inst_addr, addr, reg_deps):
		SimRef.__init__(self, inst_addr)
		self.addr = addr
		self.register_deps = reg_deps
		l.debug("Created ref: %s" % self)

	def is_symbolic(self):
		return self.addr.is_symbolic()

	def __repr__(self):
		addr_str = "0x%x" % self.addr.any() if not self.addr.is_symbolic() else "(symbolic)"
		return "SimCodeRef at 0x%x to %s, regdeps %s" % (self.inst_addr, addr_str, self.register_deps)
