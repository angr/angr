import sys
import pyvex
import simuvex
from archinfo import ArchARM

import capstone

import logging
l = logging.getLogger("angr.lifter")

VEX_IRSB_MAX_SIZE = 400
VEX_IRSB_MAX_INST = 99
VEX_DEFAULT_OPT_LEVEL = 1

class Lifter:
    def __init__(self, project):
        self._project = project
        self._thumbable = isinstance(project.arch, ArchARM)

    def lift(self, addr, insn_bytes=None, max_size=None, num_inst=None,
             traceflags=0, thumb=False, backup_state=None, opt_level=None):
        """
        Returns a pyvex block starting at address addr

        @param addr: the address at which to start the block

        The below parameters are optional:
        @param thumb: whether the block should be lifted in ARM's THUMB mode
        @param backup_state: a state to read bytes from instead of using project memory
        @param opt_level: the VEX optimization level to use
        @param insn_bytes: a string of bytes to use for the block instead of the project
        @param max_size: the maximum size of the block, in bytes
        @param num_inst: the maximum number of instructions
        @param traceflags: traceflags to be passed to VEX. Default: 0
        """
        passed_max_size = max_size is not None
        passed_num_inst = num_inst is not None
        max_size = VEX_IRSB_MAX_SIZE if max_size is None else max_size
        num_inst = VEX_IRSB_MAX_INST if num_inst is None else num_inst
        opt_level = VEX_DEFAULT_OPT_LEVEL if opt_level is None else opt_level

        if self._thumbable and addr % 2 == 1:
            thumb = True
        elif not self._thumbable and thumb:
            l.warning("Why did you pass in thumb=True on a non-ARM architecture")
            thumb = False

        if thumb:
            addr &= ~1

        # TODO: FIXME: figure out what to do if we're about to exhaust the memory
        # (we can probably figure out how many instructions we have left by talking to IDA)

        if insn_bytes is not None:
            buff, size = insn_bytes, len(insn_bytes)
            max_size = min(max_size, size)
            passed_max_size = True
        else:
            buff, size = "", 0

            if backup_state:
                buff, size = self._bytes_from_state(backup_state, addr, max_size)
                max_size = min(max_size, size)
            else:
                try:
                    buff, size = self._project.loader.memory.read_bytes_c(addr)
                except KeyError:
                    pass

            if not buff or size == 0:
                raise AngrMemoryError("No bytes in memory for block starting at 0x%x." % addr)

        # deal with thumb mode in ARM, sending an odd address and an offset
        # into the string
        byte_offset = 0
        real_addr = addr
        if thumb:
            byte_offset = 1
            addr += 1

        l.debug("Creating pyvex.IRSB of arch %s at 0x%x", self._project.arch.name, addr)

        pyvex.set_iropt_level(opt_level)
        try:
            if passed_max_size and not passed_num_inst:
                irsb = pyvex.IRSB(bytes=buff,
                                  mem_addr=addr,
                                  num_bytes=max_size,
                                  arch=self._project.arch,
                                  bytes_offset=byte_offset,
                                  traceflags=traceflags)
            elif not passed_max_size and passed_num_inst:
                irsb = pyvex.IRSB(bytes=buff,
                                  mem_addr=addr,
                                  num_bytes=VEX_IRSB_MAX_SIZE,
                                  num_inst=num_inst,
                                  arch=self._project.arch,
                                  bytes_offset=byte_offset,
                                  traceflags=traceflags)
            elif passed_max_size and passed_num_inst:
                irsb = pyvex.IRSB(bytes=buff,
                                  mem_addr=addr,
                                  num_bytes=min(size, max_size),
                                  num_inst=num_inst,
                                  arch=self._project.arch,
                                  bytes_offset=byte_offset,
                                  traceflags=traceflags)
            else:
                irsb = pyvex.IRSB(bytes=buff,
                                  mem_addr=addr,
                                  num_bytes=min(size, max_size),
                                  arch=self._project.arch,
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

        if insn_bytes is None:
            for stmt in irsb.statements:
                if stmt.tag != 'Ist_IMark' or stmt.addr == real_addr:
                    continue
                if self._project.is_hooked(stmt.addr):
                    size = stmt.addr - real_addr
                    irsb = pyvex.IRSB(bytes=buff, mem_addr=addr, num_bytes=size, arch=self._project.arch, bytes_offset=byte_offset, traceflags=traceflags)
                    break

        irsb = self._post_process(irsb)
        return Block(buff, irsb, thumb)

    @staticmethod
    def _bytes_from_state(backup_state, addr, max_size):
        arr = [ ]

        for i in range(addr, addr + max_size):
            if i in backup_state.memory:
                val = backup_state.memory.load(backup_state.BVV(i), backup_state.BVV(1))
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

    def _post_process(self, block):
        '''
        Do some post-processing work here.
        :param block:
        :return:
        '''

        block.statements = [ x for x in block.statements if x.tag != 'Ist_NoOp' ]

        funcname = "_post_process_%s" % self._project.arch.name
        if hasattr(self, funcname):
            block = getattr(self, funcname)(block)

        return block

    def _post_process_ARM(self, block):

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
                    if stmt.offset == self._project.arch.registers['lr'][0]:
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
    def _post_process_MIPS32(block):

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
                            stmt.data.child_expressions[0].con.value == stmt.data.child_expressions[1].con.value:

                        # Create a new IRConst
                        irconst = pyvex.IRExpr.Const.__new__()      # XXX: does this work???
                        irconst.con = dst
                        irconst.is_atomic = True
                        irconst.result_type = dst.type
                        irconst.tag = 'Iex_Const'

                        block.statements = block.statements[ : exit_stmt_idx] + block.statements[exit_stmt_idx + 1 : ]
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

        if not isinstance(statements[put_stmt_id],pyvex.IRStmt.Put):
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


from .errors import AngrMemoryError, AngrTranslationError
