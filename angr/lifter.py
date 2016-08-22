import sys
import logging
from cachetools import LRUCache

import pyvex
import simuvex
from archinfo import ArchARM



l = logging.getLogger("angr.lifter")

VEX_IRSB_MAX_SIZE = 400
VEX_IRSB_MAX_INST = 99
VEX_DEFAULT_OPT_LEVEL = 1


class Lifter(object):
    """
    The lifter is the part of the factory that deals with the logic related to lifting blocks to IR.
    It is complicated enough that it gets its own class!

    Usually, the only way you'll ever have to interact with this class is that its `lift` method has
    been transplanted into the factory as `project.factory.block`.
    """

    LRUCACHE_SIZE = 10000

    def __init__(self, project=None, arch=None, cache=False):
        if project:
            self._arch = project.arch
        elif arch:
            self._arch = arch
        else:
            self._arch = None

        self._project = project
        self._thumbable = isinstance(self._arch, ArchARM) if self._arch is not None else False
        self._cache_enabled = cache
        self._block_cache = LRUCache(maxsize=self.LRUCACHE_SIZE)

        self._cache_hit_count = 0
        self._cache_miss_count = 0

    def clear_cache(self):
        self._block_cache = LRUCache(maxsize=self.LRUCACHE_SIZE)

        self._cache_hit_count = 0
        self._cache_miss_count = 0

    def _normalize_options(self, addr, arch, thumb):
        """
        Given a subset of the arguments to lift or fresh_block, perform all the sanity checks
        and normalize the form of the args
        """
        if arch is None:
            if self._arch is None:
                raise AngrLifterError('"arch" must be specified')

            thumbable = self._thumbable
            arch = self._arch
        else:
            thumbable = isinstance(arch, ArchARM)

        if thumbable and addr % 2 == 1:
            thumb = True
        elif not thumbable and thumb:
            l.warning("Why did you pass in thumb=True on a non-ARM architecture")
            thumb = False

        if thumb:
            addr &= ~1

        return addr, arch, thumb

    def fresh_block(self, addr, size, arch=None, insn_bytes=None, thumb=False):
        """
        Returns a Block object with the specified size. No lifting will be performed.

        :param int addr: Address at which to start the block.
        :param int size: Size of the block.
        :return: A Block instance.
        :rtype: Block
        """
        addr, arch, thumb = self._normalize_options(addr, arch, thumb)

        if self._cache_enabled:
            for opt_level in (0, 1):
                cache_key = (addr, insn_bytes, size, None, thumb, opt_level)
                if cache_key in self._block_cache:
                    return self._block_cache[cache_key]

        if insn_bytes is None:
            if self._project is None:
                raise AngrLifterError("Lifter does not have an associated angr Project. "
                                      "You must specify \"insn_bytes\".")
            insn_bytes, size = self._load_bytes(addr, size, None)

        if thumb:
            addr += 1

        b = Block(insn_bytes, arch=arch, addr=addr, size=size, thumb=thumb)

        if self._cache_enabled:
            self._block_cache[cache_key] = b

        return b

    def lift(self, addr, arch=None, insn_bytes=None, max_size=None, num_inst=None,
             traceflags=0, thumb=False, backup_state=None, opt_level=None):
        """
        Returns a pyvex block starting at address `addr`.

        :param addr:    The address at which to start the block.

        The following parameters are optional:

        :param thumb:           Whether the block should be lifted in ARM's THUMB mode.
        :param backup_state:    A state to read bytes from instead of using project memory.
        :param opt_level:       The VEX optimization level to use.
        :param insn_bytes:      A string of bytes to use for the block instead of the project.
        :param max_size:        The maximum size of the block, in bytes.
        :param num_inst:        The maximum number of instructions.
        :param traceflags:      traceflags to be passed to VEX. (default: 0)
        """

        passed_max_size = max_size is not None
        passed_num_inst = num_inst is not None
        max_size = VEX_IRSB_MAX_SIZE if max_size is None else max_size
        num_inst = VEX_IRSB_MAX_INST if num_inst is None else num_inst
        opt_level = VEX_DEFAULT_OPT_LEVEL if opt_level is None else opt_level

        addr, arch, thumb = self._normalize_options(addr, arch, thumb)

        cache_key = (addr, insn_bytes, max_size, num_inst, thumb, opt_level)
        if self._cache_enabled and cache_key in self._block_cache and self._block_cache[cache_key].vex is not None:
            self._cache_hit_count += 1
            return self._block_cache[cache_key]
        else:
            self._cache_miss_count += 1

        if insn_bytes is not None:
            buff, size = insn_bytes, len(insn_bytes)
            passed_max_size = True
        else:
            if self._project is None:
                raise AngrLifterError("Lifter does not have an associated angr Project. "
                                      "You must specify \"insn_bytes\".")
            buff, size = self._load_bytes(addr, max_size, state=backup_state)

        if not buff or size == 0:
            raise AngrMemoryError("No bytes in memory for block starting at %#x." % addr)

        # deal with thumb mode in ARM, sending an odd address and an offset
        # into the string
        byte_offset = 0
        real_addr = addr
        if thumb:
            byte_offset = 1
            addr += 1

        l.debug("Creating pyvex.IRSB of arch %s at %#x", arch.name, addr)

        pyvex.set_iropt_level(opt_level)
        try:
            if passed_max_size and not passed_num_inst:
                irsb = pyvex.IRSB(buff, addr, arch,
                                  num_bytes=size,
                                  bytes_offset=byte_offset,
                                  traceflags=traceflags)
            elif not passed_max_size and passed_num_inst:
                irsb = pyvex.IRSB(buff, addr, arch,
                                  num_bytes=VEX_IRSB_MAX_SIZE,
                                  num_inst=num_inst,
                                  bytes_offset=byte_offset,
                                  traceflags=traceflags)
            elif passed_max_size and passed_num_inst:
                irsb = pyvex.IRSB(buff, addr, arch,
                                  num_bytes=size,
                                  num_inst=num_inst,
                                  bytes_offset=byte_offset,
                                  traceflags=traceflags)
            else:
                irsb = pyvex.IRSB(buff, addr, arch,
                                  num_bytes=size,
                                  bytes_offset=byte_offset,
                                  traceflags=traceflags)
        except pyvex.PyVEXError:
            l.debug("VEX translation error at %#x", addr)
            if isinstance(buff, str):
                l.debug('Using bytes: ' + buff)
            else:
                l.debug("Using bytes: " + str(pyvex.ffi.buffer(buff, size)).encode('hex'))
            e_type, value, traceback = sys.exc_info()
            raise AngrTranslationError, ("Translation error", e_type, value), traceback

        if insn_bytes is None and self._project is not None:
            for stmt in irsb.statements:
                if stmt.tag != 'Ist_IMark' or stmt.addr == real_addr:
                    continue
                if self._project.is_hooked(stmt.addr):
                    size = stmt.addr - real_addr
                    irsb = pyvex.IRSB(buff, addr, arch,
                                      num_bytes=size,
                                      bytes_offset=byte_offset,
                                      traceflags=traceflags)
                    break

        irsb = self._post_process(irsb, arch)
        b = Block(buff, arch=arch, addr=addr, vex=irsb, thumb=thumb)
        if self._cache_enabled:
            self._block_cache[cache_key] = b
        return b

    def _load_bytes(self, addr, max_size, state=None):
        buff, size = "", 0
        if self._project._support_selfmodifying_code and state:
            buff, size = self._bytes_from_state(state, addr, max_size)
        else:
            try:
                buff, size = self._project.loader.memory.read_bytes_c(addr)
            except KeyError:
                if state:
                    buff, size = self._bytes_from_state(state, addr, max_size)

        size = min(max_size, size)
        return buff, size

    @staticmethod
    def _bytes_from_state(backup_state, addr, max_size):
        arr = []

        for i in range(addr, addr + max_size):
            if i in backup_state.memory:
                val = backup_state.memory.load(i, 1, inspect=False)
                try:
                    val = backup_state.se.exactly_n_int(val, 1)[0]
                    val = chr(val)
                except simuvex.SimValueError:
                    break

                arr.append(val)
            else:
                break

        buff = "".join(arr)
        size = len(buff)

        return buff, size

    def _post_process(self, block, arch):
        """
        Do some post-processing work here.

        :param block:
        :return:
        """

        block.statements = [x for x in block.statements if x.tag != 'Ist_NoOp']

        funcname = "_post_process_%s" % arch.name
        if hasattr(self, funcname):
            block = getattr(self, funcname)(block, arch)

        return block

    @staticmethod
    def _post_process_ARM(block, arch):

        # Jumpkind
        if block.jumpkind == "Ijk_Boring":
            # If PC is moved to LR, then this should be an Ijk_Call
            #
            # Example:
            # MOV LR, PC
            # MOV PC, R8

            stmts = block.statements

            lr_store_id = None
            inst_ctr = 1
            for i, stmt in reversed(list(enumerate(stmts))):
                if isinstance(stmt, pyvex.IRStmt.Put):
                    if stmt.offset == arch.registers['lr'][0]:
                        lr_store_id = i
                        break
                if isinstance(stmt, pyvex.IRStmt.IMark):
                    inst_ctr += 1

            if lr_store_id is not None and inst_ctr == 2:
                block.jumpkind = "Ijk_Call"

        return block

    _post_process_ARMEL = _post_process_ARM
    _post_process_ARMHF = _post_process_ARM

    @staticmethod
    def _post_process_MIPS32(block, arch):  #pylint:disable=unused-argument

        # Handle unconditional branches
        # `beq $zero, $zero, xxxx`
        # It is translated to
        #
        # 15 | ------ IMark(0x401684, 4, 0) ------
        # 16 | t0 = CmpEQ32(0x00000000, 0x00000000)
        # 17 | PUT(128) = 0x00401688
        # 18 | ------ IMark(0x401688, 4, 0) ------
        # 19 | if (t0) goto {Ijk_Boring} 0x401684
        # 20 | PUT(128) = 0x0040168c
        # 21 | t4 = GET:I32(128)
        # NEXT: PUT(128) = t4; Ijk_Boring
        #

        stmts = block.statements
        tmp_exit = None
        exit_stmt_idx = None
        dst = None

        for i, stmt in reversed(list(enumerate(stmts))):
            if tmp_exit is None:
                # Looking for the Exit statement
                if isinstance(stmt, pyvex.IRStmt.Exit) and \
                        isinstance(stmt.guard, pyvex.IRExpr.RdTmp):
                    tmp_exit = stmt.guard.tmp
                    dst = stmt.dst
                    exit_stmt_idx = i
            else:
                # Looking for the WrTmp statement
                if isinstance(stmt, pyvex.IRStmt.WrTmp) and \
                                stmt.tmp == tmp_exit:
                    if isinstance(stmt.data, pyvex.IRExpr.Binop) and \
                                    stmt.data.op == 'Iop_CmpEQ32' and \
                            isinstance(stmt.data.child_expressions[0], pyvex.IRExpr.Const) and \
                            isinstance(stmt.data.child_expressions[1], pyvex.IRExpr.Const) and \
                                    stmt.data.child_expressions[0].con.value == stmt.data.child_expressions[
                                1].con.value:

                        # Create a new IRConst
                        irconst = pyvex.IRExpr.Const.__new__()  # XXX: does this work???
                        irconst.con = dst
                        irconst.is_atomic = True
                        irconst.result_type = dst.type
                        irconst.tag = 'Iex_Const'

                        block.statements = block.statements[: exit_stmt_idx] + block.statements[exit_stmt_idx + 1:]
                        # Replace the default exit!
                        block.next = irconst

                    else:
                        break

        return block

    @staticmethod
    def _find_source(statements, put_stmt_id):
        '''
        Execute the statements backwards and figure out where the value comes from
        This is not a slicer. It only take care of a small portion of statement types.
        :param statements:
        :param put_stmt_id:
        :return:
        '''
        temps = set()
        src_stmt_ids = set()

        if not isinstance(statements[put_stmt_id], pyvex.IRStmt.Put):
            return None

        if not isinstance(statements[put_stmt_id].data, pyvex.IRExpr.RdTmp):
            return None

        temps.add(statements[put_stmt_id].data.tmp)

        for i in xrange(put_stmt_id, -1, -1):
            stmt = statements[i]
            if isinstance(stmt, pyvex.IRStmt.WrTmp):
                data = None
                if stmt.tmp in temps:
                    data = stmt.data
                if isinstance(data, pyvex.IRExpr.RdTmp):
                    temps.add(data.tmp)
                elif isinstance(data, pyvex.IRExpr.Get):
                    src_stmt_ids.add(i)
                    temps.remove(stmt.tmp)

        return src_stmt_ids


class Block(object):
    BLOCK_MAX_SIZE = 4096

    __slots__ = ['bytes', '_vex', '_thumb', '_arch', '_capstone', 'addr', 'size', 'instructions', 'instruction_addrs']

    def __init__(self, byte_string, arch, addr=None, size=None, vex=None, thumb=None):
        self._vex = vex
        self._thumb = thumb
        self._arch = arch
        self._capstone = None
        self.addr = addr
        self.size = size

        self.instructions = None
        self.instruction_addrs = []

        self._parse_vex_info()

        if self.addr is None:
            l.warning('Lifted basic block with no IMarks!')
            self.addr = 0

        if type(byte_string) is str:
            if self.size is not None:
                self.bytes = byte_string[:self.size]
            else:
                self.bytes = byte_string
        else:
            # Convert bytestring to a str
            if self.size is not None:
                self.bytes = str(pyvex.ffi.buffer(byte_string, self.size))
            else:
                l.warning("Block size is unknown. Truncate it to BLOCK_MAX_SIZE")
                self.bytes = str(pyvex.ffi.buffer(byte_string), Block.BLOCK_MAX_SIZE)

    def _parse_vex_info(self):
        vex = self._vex
        if vex is not None:
            self.instructions = vex.instructions

            if self._arch is None:
                self._arch = vex.arch

            if self.size is None:
                self.size = vex.size

            for stmt in vex.statements:
                if stmt.tag != 'Ist_IMark':
                    continue
                if self.addr is None:
                    self.addr = stmt.addr + stmt.delta
                self.instruction_addrs.append(stmt.addr + stmt.delta)

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
    def vex(self):
        if not self._vex:
            offset = 1 if self._thumb else 0
            self._vex = pyvex.IRSB(self.bytes, self.addr, self._arch, bytes_offset=offset)
            self._parse_vex_info()

        return self._vex

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

    @property
    def codenode(self):
        return BlockNode(self.addr, self.size, bytestr=self.bytes)


class CapstoneBlock(object):
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


from .errors import AngrMemoryError, AngrTranslationError, AngrLifterError
from .knowledge.codenode import BlockNode
