import capstone

class Block(object):
	def __init__(self, byte_string, vex, thumb):
		self._bytes = byte_string
		self.vex = vex
		self._thumb = thumb
		self._arch = vex.arch
		self._capstone = None
		self.addr = None
		self.size = vex.size
		self.instructions = vex.instructions
		self.instruction_addrs = []

		for stmt in vex.statements:
			if stmt.tag != 'Ist_IMark':
				continue
			if self.addr is None:
				self.addr = stmt.addr
			self.instruction_addrs.append(stmt.addr)

		if self.addr is None:
			l.warning('Lifted basic block with no IMarks!')
			self.addr = 0

	def __repr__(self):
		return '<Block for %#x, %d bytes>' % (self.addr, self.size)

	def __getstate__(self):
		self._bytes = self.bytes
		return self.__dict__

	def __setstate__(self, data):
		self.__dict__.update(data)

	def pp(self):
		return self.capstone.pp()

	@property
	def bytes(self):
		bytestring = self._bytes
		if not isinstance(bytestring, str):
			bytestring = str(pyvex.ffi.buffer(bytestring, self.size))
		return bytestring

	@property
	def capstone(self):
		if self._capstone: return self._capstone

		cs = self._arch.capstone if not self._thumb else self._arch.capstone_thumb

		insns = []

		for cs_insn in cs.disasm(self.bytes, self.addr):
			insns.append(CapstoneInsn(cs_insn))
		block = CapstoneBlock(self.addr, insns, self._thumb, self._arch)

		self._capstone = block
		return block

class CopyClass:
	def __init__(self, obj):
		for attr in dir(obj):
			if attr.startswith('_'):
				continue
			val = getattr(obj, attr)
			if type(val) in (int, long, list, tuple, str, dict, float): # pylint: disable=unidiomatic-typecheck
				setattr(self, attr, val)
			else:
				setattr(self, attr, CopyClass(val))

class CapstoneInsn(object):
	def __init__(self, insn):
		self._cs = insn._cs
		self.address = insn.address
		self.bytes = insn.bytes
		if hasattr(insn, 'cc'):
			self.cc = insn.cc
		self.groups = insn.groups
		self.id = insn.id
		self._insn_name = insn.insn_name()
		self.mnemonic = insn.mnemonic
		self.op_str = insn.op_str
		self.operands = map(CopyClass, insn.operands)
		self.size = insn.size

	def group(self, grpnum):
		return grpnum in self.groups

	def insn_name(self):
		return self._insn_name

	def reg_name(self, reg_id):
		# I don't like this API, but it's replicating Capstone's...
		return capstone._cs.cs_reg_name(self._cs.csh, reg_id).decode('ascii')

	def __str__(self):
		return "0x%x:\t%s\t%s" % (self.address, self.mnemonic, self.op_str)

	def __repr__(self):
		return '<CapstoneInsn "%s" for %#x>' % (self.mnemonic, self.address)

class CapstoneBlock(object):
	def __init__(self, addr, insns, thumb, arch):
		self.addr = addr
		self.insns = insns
		self.thumb = thumb
		self.arch = arch

	def pp(self):
		print str(self)

	def __str__(self):
		return '\n'.join(map(str, self.insns))

	def __repr__(self):
		return '<CapstoneBlock for %#x>' % self.addr

