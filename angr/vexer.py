import sys
import types

import ana
import pyvex
import simuvex
import logging
l = logging.getLogger("angr.vexer")

class SerializableIRSB(ana.Storable):
    __slots__ = [ '_state', '_irsb', '_addr' ]

    def __init__(self, *args, **kwargs):
        self._state = args, kwargs
        self._irsb = pyvex.IRSB(*args, **kwargs)
        self._addr = next(a.addr for a in self._irsb.statements if isinstance(a, pyvex.IRStmt.IMark))

    def __dir__(self):
        return dir(self._irsb) + self._all_slots()

    def __getattr__(self, a):
        try:
            return object.__getattribute__(self, a)
        except AttributeError:
            return getattr(self._irsb, a)

    def __setattr__(self, a, v):
        try:
            return object.__setattr__(self, a, v)
        except AttributeError:
            return setattr(self._irsb, a, v)

    def _ana_getstate(self):
        return self._state

    def _ana_setstate(self, s):
        self.__init__(*(s[0]), **(s[1]))

    def _ana_getliteral(self):
        return self._crawl_vex(self._irsb)

    def instruction_addrs(self):
        return [ s.addr for s in self._irsb.statements if isinstance(s, pyvex.IRStmt.IMark) ]

    @property
    def json(self):
        return self._ana_getliteral()

    def _crawl_vex(self, p):
        if isinstance(p, (int, str, float, long, bool)): return p
        elif isinstance(p, (tuple, list, set)): return [ self._crawl_vex(e) for e in p ]
        elif isinstance(p, dict): return { k:self._crawl_vex(p[k]) for k in p }

        attr_keys = set()
        for k in dir(p):
            if k in [ 'wrapped' ] or k.startswith('_'):
                continue

            if isinstance(getattr(p, k), (types.BuiltinFunctionType, types.BuiltinMethodType, types.FunctionType, types.ClassType, type, types.UnboundMethodType)):
                continue

            attr_keys.add(k)

        vdict = { }
        for k in attr_keys:
            vdict[k] = self._crawl_vex(getattr(p, k))

        if isinstance(p, pyvex.IRSB):
            vdict['statements'] = self._crawl_vex(p.statements)
            vdict['instructions'] = self._crawl_vex(p.instructions)
            vdict['addr'] = self._addr
        elif isinstance(p, pyvex.IRTypeEnv):
            vdict['types'] = self._crawl_vex(p.types)

        return vdict

class VEXer:
    def __init__(self, mem, arch, max_size=None, num_inst=None, traceflags=None, use_cache=None, opt_level=None):
        self.mem = mem
        self.arch = arch
        self.max_size = 400 if max_size is None else max_size
        self.num_inst = 99 if num_inst is None else num_inst
        self.traceflags = 0 if traceflags is None else traceflags
        self.use_cache = True if use_cache is None else use_cache
        self.opt_level = 1 if opt_level is None else opt_level
        self.irsb_cache = { }


    def block(self, addr, max_size=None, num_inst=None, traceflags=0, thumb=False, backup_state=None, opt_level=None):
        """
        Returns a pyvex block starting at address addr

        Optional params:

        @param max_size: the maximum size of the block, in bytes
        @param num_inst: the maximum number of instructions
        @param traceflags: traceflags to be passed to VEX. Default: 0
        """
        max_size = self.max_size if max_size is None else max_size
        num_inst = self.num_inst if num_inst is None else num_inst
        opt_level = self.opt_level if opt_level is None else opt_level

        if thumb:
            addr &= ~1

        # TODO: FIXME: figure out what to do if we're about to exhaust the memory
        # (we can probably figure out how many instructions we have left by talking to IDA)

        # Try to find the actual size of the block, stop at the first keyerror
        arr = []
        for i in range(addr, addr+max_size):
            try:
                arr.append(self.mem[i])
            except KeyError:
                if backup_state:
                    if i in backup_state.memory:
                        val = backup_state.mem_expr(backup_state.BVV(i), backup_state.BVV(1))
                        try:
                            val = backup_state.se.exactly_n_int(val, 1)[0]
                            val = chr(val)
                        except simuvex.SimValueError:
                            break

                        arr.append(val)
                    else:
                        break
                else:
                    break

        buff = "".join(arr)

        if not buff:
            raise AngrMemoryError("No bytes in memory for block starting at 0x%x." % addr)

        # deal with thumb mode in ARM, sending an odd address and an offset
        # into the string
        byte_offset = 0
        if thumb:
            byte_offset = 1
            addr += 1

        l.debug("Creating pyvex.IRSB of arch %s at 0x%x", self.arch.name, addr)

        if self.use_cache:
            cache_key = (buff, addr, num_inst, self.arch.vex_arch, byte_offset, thumb, opt_level)
            if cache_key in self.irsb_cache:
                return self.irsb_cache[cache_key]

        pyvex.set_iropt_level(opt_level)
        try:
            if num_inst:
                block = SerializableIRSB(bytes=buff, mem_addr=addr, num_inst=num_inst, arch=self.arch.vex_arch,
                                   endness=self.arch.vex_endness, bytes_offset=byte_offset, traceflags=traceflags)
            else:
                block = SerializableIRSB(bytes=buff, mem_addr=addr, arch=self.arch.vex_arch,
                                   endness=self.arch.vex_endness, bytes_offset=byte_offset, traceflags=traceflags)
        except pyvex.PyVEXError:
            l.debug("VEX translation error at 0x%x", addr)
            l.debug("Using bytes: " + buff.encode('hex'))
            e_type, value, traceback = sys.exc_info()
            raise AngrTranslationError, ("Translation error", e_type, value), traceback

        if self.use_cache:
            self.irsb_cache[cache_key] = block

        block = self._post_process(block)

        return block

    def _post_process(self, block):
        '''
        Do some post-processing work here.
        :param block:
        :return:
        '''

        block.statements = [ x for x in block.statements if x.tag != 'Ist_NoOp' ]

        funcname = "_post_process_%s" % self.arch.name
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
                    if stmt.offset == self.arch.registers['lr'][0]:
                        lr_store_id = i
                        break
                if isinstance(stmt, pyvex.IRStmt.IMark):
                    inst_ctr += 1

            if lr_store_id is not None and inst_ctr == 2:
                block.jumpkind = "Ijk_Call"

        return block

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
                        irconst = pyvex.IRExpr.Const()
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

    def __getitem__(self, addr):
        return self.block(addr)

from .errors import AngrMemoryError, AngrTranslationError
