import logging
l = logging.getLogger("angr.block")

import pyvex
from archinfo import ArchARM
from .engines import SimEngineVEX

DEFAULT_VEX_ENGINE = SimEngineVEX()  # this is only used when Block is not initialized with a project


class Block(object):
    BLOCK_MAX_SIZE = 4096

    __slots__ = ['_project', '_bytes', '_vex', 'thumb', '_capstone', 'addr', 'size', 'arch', 'instructions',
                 '_instruction_addrs', '_opt_level'
                 ]

    def __init__(self, addr, project=None, arch=None, size=None, byte_string=None, vex=None, thumb=False, backup_state=None,
                 opt_level=None, num_inst=None, traceflags=0):

        # set up arch
        if project is not None:
            self.arch = project.arch
        else:
            self.arch = arch

        if self.arch is None:
            raise ValueError('Either "project" or "arch" has to be specified.')

        if isinstance(self.arch, ArchARM):
            if addr & 1 == 1:
                thumb = True
            if thumb:
                addr |= 1
        else:
            thumb = False

        self._project = project
        self.thumb = thumb
        self.addr = addr
        self._opt_level = opt_level

        if self._project is None and byte_string is None:
            raise ValueError('"byte_string" has to be specified if "project" is not provided.')

        if size is None:
            if byte_string is not None:
                size = len(byte_string)
            elif vex is not None:
                size = vex.size
            else:
                vex = self._vex_engine.lift(
                        clemory=project.loader.memory,
                        state=backup_state,
                        insn_bytes=byte_string,
                        addr=addr,
                        thumb=thumb,
                        opt_level=opt_level,
                        num_inst=num_inst,
                        traceflags=traceflags)
                size = vex.size

        self._vex = vex
        self._capstone = None
        self.size = size

        self.instructions = num_inst
        self._instruction_addrs = []

        self._parse_vex_info()

        if byte_string is None:
            self._bytes = None
        elif type(byte_string) is str:
            if self.size is not None:
                self._bytes = byte_string[:self.size]
            else:
                self._bytes = byte_string
        else:
            # Convert bytestring to a str
            # size will ALWAYS be known at this point
            self._bytes = str(pyvex.ffi.buffer(byte_string, self.size))

    def _parse_vex_info(self):
        vex = self._vex
        if vex is not None:
            self.instructions = vex.instructions
            self._instruction_addrs = []
            self.size = vex.size

            for stmt in vex.statements:
                if stmt.tag != 'Ist_IMark':
                    continue
                if self.addr is None:
                    self.addr = stmt.addr + stmt.delta
                self._instruction_addrs.append(stmt.addr + stmt.delta)

    def __repr__(self):
        return '<Block for %#x, %d bytes>' % (self.addr, self.size)

    def __getstate__(self):
        return dict((k, getattr(self, k)) for k in self.__slots__ if k not in ('_capstone', ))

    def __setstate__(self, data):
        for k, v in data.iteritems():
            setattr(self, k, v)

    def __hash__(self):
        return hash((type(self), self.addr, self.bytes))

    def __eq__(self, other):
        return type(self) is type(other) and \
               self.addr == other.addr and \
               self.bytes == other.bytes

    def __ne__(self, other):
        return not self == other

    def pp(self):
        return self.capstone.pp()

    @property
    def _vex_engine(self):
        if self._project is None:
            return DEFAULT_VEX_ENGINE
        else:
            return self._project.factory.default_engine

    @property
    def vex(self):
        if not self._vex:
            self._vex = self._vex_engine.lift(
                    clemory=self._project.loader.memory if self._project is not None else None,
                    insn_bytes=self._bytes,
                    addr=self.addr,
                    thumb=self.thumb,
                    size=self.size,
                    num_inst=self.instructions,
                    opt_level=self._opt_level,
                    arch=self.arch,
            )
            self._parse_vex_info()

        return self._vex

    @property
    def capstone(self):
        if self._capstone: return self._capstone

        cs = self.arch.capstone if not self.thumb else self.arch.capstone_thumb

        insns = []

        for cs_insn in cs.disasm(self.bytes, self.addr):
            insns.append(CapstoneInsn(cs_insn))
        block = CapstoneBlock(self.addr, insns, self.thumb, self.arch)

        self._capstone = block
        return block

    @property
    def codenode(self):
        return BlockNode(self.addr, self.size, bytestr=self.bytes)

    @property
    def bytes(self):
        if self._bytes is None:
            addr = self.addr
            if self.thumb:
                addr = (addr >> 1) << 1
            self._bytes = ''.join(self._project.loader.memory.read_bytes(addr, self.size))
        return self._bytes

    @property
    def instruction_addrs(self):
        if not self._instruction_addrs and self._vex is None:
            # initialize instruction addrs
            _ = self.vex

        return self._instruction_addrs

class CapstoneBlock(object):
    """
    Deep copy of the capstone blocks, which have serious issues with having extended lifespans
    outside of capstone itself
    """
    __slots__ = [ 'addr', 'insns', 'thumb', 'arch' ]

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


class CapstoneInsn(object):
    def __init__(self, capstone_insn):
        self.insn = capstone_insn

    def __getattr__(self, item):
        if item in ('__str__', '__repr__'):
            return self.__getattribute__(item)
        if hasattr(self.insn, item):
            return getattr(self.insn, item)
        raise AttributeError()

    def __str__(self):
        return "%#x:\t%s\t%s" % (self.address, self.mnemonic, self.op_str)

    def __repr__(self):
        return '<CapstoneInsn "%s" for %#x>' % (self.mnemonic, self.address)


from .knowledge.codenode import BlockNode
