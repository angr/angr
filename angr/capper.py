import capstone

import vexer

import logging
l = logging.getLogger("angr.capper")

class CopyClass:
    def __init__(self, obj):
        for attr in dir(obj):
            if attr.startswith('_'):
                continue
            val = getattr(obj, attr)
            if type(val) in (int, long, list, tuple, str, dict, float):
                setattr(self, attr, val)
            else:
                setattr(self, attr, CopyClass(val))

class CapstoneInsn(object):
    def __init__(self, insn):
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

        def insn_name(self):
            return self._insn_name

    def group(self, grpnum):
        return grpnum in self.groups

    def insn_name(self):
        return self._insn_name

    def __str__(self):
        return "0x%x:\t%s\t%s" % (self.address, self.mnemonic, self.op_str)

    def __repr__(self):
        return '<CapstoneInsn "%s" at 0x%x>' % (self.mnemonic, self.address)

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
        return '<CapstoneBlock at 0x%x>' % self.addr

class Capper:
    def __init__(self, mem, arch, max_size=None, num_inst=None, use_cache=None):
        self._vexer = vexer.VEXer(mem, arch, max_size, num_inst, use_cache=False)
        self.mem = mem
        self.arch = arch
        self.max_size = 400 if max_size is None else max_size
        self.num_inst = 99 if num_inst is None else num_inst
        self.use_cache = True if use_cache is None else use_cache
        self.insn_cache = { }
        self.block_cache = { }

    def block(self, addr, max_size=None, num_inst=None, thumb=False):
        actual_size = self._vexer.block(addr, max_size, num_inst, thumb=thumb).size

        if thumb:
            addr &= ~1

        if self.use_cache and (addr, thumb) in self.block_cache:
            return self.block_cache[(addr, thumb)]

        max_size = self.max_size if max_size is None else max_size
        num_inst = self.num_inst if num_inst is None else num_inst

        cs = self.arch.capstone if not thumb else self.arch.capstone_thumb

        insn_count = 0
        byte_count = 0

        insns = []
        byte_cache = []

        for i in xrange(actual_size):
            byte_cache.append(self.mem[addr + i])

        for cs_insn in cs.disasm(''.join(byte_cache), addr):
            insns.append(CapstoneInsn(cs_insn))
        block = CapstoneBlock(addr, insns, thumb, self.arch)

        if self.use_cache:
            self.block_cache[(addr, thumb)] = block

        return block

        #while insn_count <= num_inst and byte_count <= max_size:
        #    cur_addr = byte_count + addr
        #    while len(byte_cache) < self.arch.max_inst_bytes:
        #        try:
        #            byte_cache.append(self.mem[cur_addr + len(byte_cache)])
        #        except KeyError:
        #            break

        #    mightcache = False
        #    if self.use_cache and (cur_addr, thumb) in self.insn_cache:
        #        insn = self.insn_cache[(cur_addr, thumb)]
        #    else:
        #        mightcache = True
        #        try:
        #            iterator = cs.disasm(''.join(byte_cache), cur_addr, 1)
        #            insn = iterator.next()
        #            # Exhaust the iterator, trigger memory release
        #            [x for x in iterator]
        #        except capstone.CsError as e:
        #            raise AngrTranslationError(str(e))
        #        except StopIteration:
        #            raise AngrMemoryError("Not enough memory for instruction at 0x%x!" % cur_addr)

        #    if self.use_cache and mightcache:
        #        self.insn_cache[(cur_addr, thumb)] = insn

        #    self.insns.append(insn)
        #    self.byte_cache = self.byte_cache[insn.size:]
        #    byte_count += insn.size
        #    insn_count += 1

        # uh... how do we detect the end of the basic block? fuck.

from .errors import AngrMemoryError, AngrTranslationError
