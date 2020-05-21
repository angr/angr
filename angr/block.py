import logging
from typing import List

from pyvex import IRSB

l = logging.getLogger(name=__name__)

import pyvex
from archinfo import ArchARM

from .protos import primitives_pb2 as pb2
from .serializable import Serializable
from .engines.vex import VEXLifter

DEFAULT_VEX_ENGINE = VEXLifter(None)  # this is only used when Block is not initialized with a project


class Block(Serializable):
    BLOCK_MAX_SIZE = 4096

    __slots__ = ['_project', '_bytes', '_vex', 'thumb', '_capstone', 'addr', 'size', 'arch', '_instructions',
                 '_instruction_addrs', '_opt_level', '_vex_nostmt', '_collect_data_refs', '_strict_block_end',
                 '_cross_insn_opt',
                 ]

    def __init__(self, addr, project=None, arch=None, size=None, byte_string=None, vex=None, thumb=False, backup_state=None,
                 extra_stop_points=None, opt_level=None, num_inst=None, traceflags=0, strict_block_end=None,
                 collect_data_refs=False, cross_insn_opt=True):

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
            elif thumb:
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
                vex = self._vex_engine.lift_vex(
                        clemory=project.loader.memory,
                        state=backup_state,
                        insn_bytes=byte_string,
                        addr=addr,
                        thumb=thumb,
                        extra_stop_points=extra_stop_points,
                        opt_level=opt_level,
                        num_inst=num_inst,
                        traceflags=traceflags,
                        strict_block_end=strict_block_end,
                        collect_data_refs=collect_data_refs,
                        cross_insn_opt=cross_insn_opt,
                )
                size = vex.size

        self._vex = vex
        self._vex_nostmt = None
        self._capstone = None
        self.size = size
        self._collect_data_refs = collect_data_refs
        self._strict_block_end = strict_block_end
        self._cross_insn_opt = cross_insn_opt

        self._instructions = num_inst
        self._instruction_addrs = [] # type: List[int]

        self._parse_vex_info()

        if byte_string is None:
            if backup_state is not None:
                self._bytes = self._vex_engine._load_bytes(addr - thumb, size, state=backup_state)[0]
                if type(self._bytes) is not bytes:
                    self._bytes = bytes(pyvex.ffi.buffer(self._bytes, size))
            else:
                self._bytes = None
        elif type(byte_string) is bytes:
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
            self._instructions = vex.instructions
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
        for k, v in data.items():
            setattr(self, k, v)
        self._capstone = None

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
    def vex(self) -> IRSB:
        if not self._vex:
            self._vex = self._vex_engine.lift_vex(
                    clemory=self._project.loader.memory if self._project is not None else None,
                    insn_bytes=self._bytes,
                    addr=self.addr,
                    thumb=self.thumb,
                    size=self.size,
                    num_inst=self._instructions,
                    opt_level=self._opt_level,
                    arch=self.arch,
                    collect_data_refs=self._collect_data_refs,
                    strict_block_end=self._strict_block_end,
                    cross_insn_opt=self._cross_insn_opt,
            )
            self._parse_vex_info()

        return self._vex

    @property
    def vex_nostmt(self):
        if self._vex_nostmt:
            return self._vex_nostmt

        if self._vex:
            return self._vex

        self._vex_nostmt = self._vex_engine.lift_vex(
            clemory=self._project.loader.memory if self._project is not None else None,
            insn_bytes=self._bytes,
            addr=self.addr,
            thumb=self.thumb,
            size=self.size,
            num_inst=self._instructions,
            opt_level=self._opt_level,
            arch=self.arch,
            skip_stmts=True,
            collect_data_refs=self._collect_data_refs,
            strict_block_end=self._strict_block_end,
            cross_insn_opt=self._cross_insn_opt,
        )
        return self._vex_nostmt

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
        return BlockNode(self.addr, self.size, bytestr=self.bytes, thumb=self.thumb)

    @property
    def bytes(self):
        if self._bytes is None:
            addr = self.addr
            if self.thumb:
                addr = (addr >> 1) << 1
            self._bytes = self._project.loader.memory.load(addr, self.size)
        return self._bytes

    @property
    def instructions(self):
        if not self._instructions and self._vex is None:
            # initialize from VEX
            _ = self.vex

        return self._instructions

    @property
    def instruction_addrs(self):
        if not self._instruction_addrs and self._vex is None:
            # initialize instruction addrs
            _ = self.vex

        return self._instruction_addrs

    @classmethod
    def _get_cmsg(cls):
        return pb2.Block()

    def serialize_to_cmessage(self):
        obj = self._get_cmsg()
        obj.ea = self.addr
        obj.size = self.size
        obj.bytes = self.bytes

        return obj

    @classmethod
    def parse_from_cmessage(cls, cmsg):
        obj = cls(cmsg.ea,
                  size=cmsg.size,
                  byte_string=cmsg.bytes,
                  )
        return obj


class SootBlock:
    def __init__(self, addr, project=None, arch=None):

        self.addr = addr
        self.arch = arch
        self._project = project
        self._the_binary = project.loader.main_object

    @property
    def _soot_engine(self):
        if self._project is None:
            raise Exception('SHIIIIIIIT')
        else:
            return self._project.factory.default_engine

    @property
    def soot(self):
        return self._soot_engine.lift_soot(self.addr, the_binary=self._the_binary)

    @property
    def size(self):
        stmts = None if self.soot is None else self.soot.statements
        stmts_len = len(stmts) if stmts else 0
        return stmts_len

    @property
    def codenode(self):
        stmts = None if self.soot is None else self.soot.statements
        stmts_len = len(stmts) if stmts else 0
        return SootBlockNode(self.addr, stmts_len, stmts=stmts)


class CapstoneBlock:
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
        print(str(self))

    def __str__(self):
        return '\n'.join(map(str, self.insns))

    def __repr__(self):
        return '<CapstoneBlock for %#x>' % self.addr


class CapstoneInsn:
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


from .codenode import BlockNode, SootBlockNode
