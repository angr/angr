from cachetools import LRUCache

import pyvex
import claripy
from archinfo import ArchARM

from ... import sim_options as o
from ...state_plugins.inspect import BP_AFTER, BP_BEFORE
from ...state_plugins.sim_action import SimActionExit, SimActionObject
from ...errors import (SimError, SimIRSBError, SimSolverError, SimMemoryAddressError, SimReliftException,
                       UnsupportedDirtyError, SimTranslationError, SimEngineError, SimSegfaultError,
                       SimMemoryError, SimIRSBNoDecodeError, AngrAssemblyError, UnsupportedIRExprError,
                       UnsupportedIRStmtError)

from ...misc.ux import once
from ..engine import SimEngine
from .statements import STMT_CLASSES
from .expressions import EXPR_CLASSES, SimIRExpr_Unsupported

import logging
l = logging.getLogger(name=__name__)

#pylint: disable=arguments-differ

VEX_IRSB_MAX_SIZE = 400
VEX_IRSB_MAX_INST = 99

class SimEngineVEX(SimEngine):
    """
    Execution engine based on VEX, Valgrind's IR.
    """

    def __init__(self, project=None,
            stop_points=None,
            use_cache=None,
            cache_size=50000,
            default_opt_level=1,
            support_selfmodifying_code=None,
            single_step=False,
            default_strict_block_end=False):

        super(SimEngineVEX, self).__init__(project)

        self._stop_points = stop_points
        self._use_cache = use_cache
        self._default_opt_level = default_opt_level
        self._support_selfmodifying_code = support_selfmodifying_code
        self._single_step = single_step
        self._cache_size = cache_size
        self.default_strict_block_end = default_strict_block_end

        if self._use_cache is None:
            if project is not None:
                self._use_cache = project._translation_cache
            else:
                self._use_cache = False
        if self._support_selfmodifying_code is None:
            if project is not None:
                self._support_selfmodifying_code = project._support_selfmodifying_code
            else:
                self._support_selfmodifying_code = False

        # block cache
        self._block_cache = None
        self._block_cache_hits = 0
        self._block_cache_misses = 0

        self._initialize_block_cache()

        self.stmt_handlers = list(STMT_CLASSES)
        self.expr_handlers = list(EXPR_CLASSES)

    def is_stop_point(self, addr, extra_stop_points=None):
        if self.project is not None and addr in self.project._sim_procedures:
            return True
        elif self._stop_points is not None and addr in self._stop_points:
            return True
        elif extra_stop_points is not None and addr in extra_stop_points:
            return True
        return False

    def _initialize_block_cache(self):
        self._block_cache = LRUCache(maxsize=self._cache_size)
        self._block_cache_hits = 0
        self._block_cache_misses = 0

    def process(self, state,
            irsb=None,
            skip_stmts=0,
            last_stmt=99999999,
            whitelist=None,
            inline=False,
            force_addr=None,
            insn_bytes=None,
            size=None,
            num_inst=None,
            traceflags=0,
            thumb=False,
            extra_stop_points=None,
            opt_level=None,
            **kwargs):
        """
        :param state:       The state with which to execute
        :param irsb:        The PyVEX IRSB object to use for execution. If not provided one will be lifted.
        :param skip_stmts:  The number of statements to skip in processing
        :param last_stmt:   Do not execute any statements after this statement
        :param whitelist:   Only execute statements in this set
        :param inline:      This is an inline execution. Do not bother copying the state.
        :param force_addr:  Force execution to pretend that we're working at this concrete address

        :param thumb:       Whether the block should be lifted in ARM's THUMB mode.
        :param extra_stop_points:
                            An extra set of points at which to break basic blocks
        :param opt_level:   The VEX optimization level to use.
        :param insn_bytes:  A string of bytes to use for the block instead of the project.
        :param size:        The maximum size of the block, in bytes.
        :param num_inst:    The maximum number of instructions.
        :param traceflags:  traceflags to be passed to VEX. (default: 0)
        :returns:           A SimSuccessors object categorizing the block's successors
        """
        if 'insn_text' in kwargs:

            if insn_bytes is not None:
                raise SimEngineError("You cannot provide both 'insn_bytes' and 'insn_text'!")

            insn_bytes = \
                self.project.arch.asm(kwargs['insn_text'], addr=kwargs.get('addr', 0),
                                      thumb=thumb, as_bytes=True)

            if insn_bytes is None:
                raise AngrAssemblyError("Assembling failed. Please make sure keystone is installed, and the assembly"
                                        " string is correct.")

        return super(SimEngineVEX, self).process(state, irsb,
                skip_stmts=skip_stmts,
                last_stmt=last_stmt,
                whitelist=whitelist,
                inline=inline,
                force_addr=force_addr,
                insn_bytes=insn_bytes,
                size=size,
                num_inst=num_inst,
                traceflags=traceflags,
                thumb=thumb,
                extra_stop_points=extra_stop_points,
                opt_level=opt_level)

    def _check(self, state, *args, **kwargs):
        return True

    def _process(self, state, successors, irsb=None, skip_stmts=0, last_stmt=None, whitelist=None, insn_bytes=None, size=None, num_inst=None, traceflags=0, thumb=False, extra_stop_points=None, opt_level=None):
        successors.sort = 'IRSB'
        successors.description = 'IRSB'
        state.history.recent_block_count = 1
        state.scratch.guard = claripy.true
        state.scratch.sim_procedure = None
        addr = successors.addr

        state._inspect('irsb', BP_BEFORE, address=addr)
        while True:
            if irsb is None:
                irsb = self.lift(
                    addr=addr,
                    state=state,
                    insn_bytes=insn_bytes,
                    size=size,
                    num_inst=num_inst,
                    traceflags=traceflags,
                    thumb=thumb,
                    extra_stop_points=extra_stop_points,
                    opt_level=opt_level)

            if irsb.size == 0:
                if irsb.jumpkind == 'Ijk_NoDecode' and not state.project.is_hooked(irsb.addr):
                    raise SimIRSBNoDecodeError("IR decoding error at %#x. You can hook this instruction with "
                                               "a python replacement using project.hook"
                                               "(%#x, your_function, length=length_of_instruction)." % (addr, addr))

                raise SimIRSBError("Empty IRSB passed to SimIRSB.")

            # check permissions, are we allowed to execute here? Do we care?
            if o.STRICT_PAGE_ACCESS in state.options:
                try:
                    perms = state.memory.permissions(addr)
                except SimMemoryError:
                    raise SimSegfaultError(addr, 'exec-miss')
                else:
                    if not perms.symbolic:
                        perms = state.solver.eval(perms)
                        if not perms & 4 and o.ENABLE_NX in state.options:
                            raise SimSegfaultError(addr, 'non-executable')

            state.scratch.set_tyenv(irsb.tyenv)
            state.scratch.irsb = irsb

            try:
                self._handle_irsb(state, successors, irsb, skip_stmts, last_stmt, whitelist)
            except SimReliftException as e:
                state = e.state
                if insn_bytes is not None:
                    raise SimEngineError("You cannot pass self-modifying code as insn_bytes!!!")
                new_ip = state.scratch.ins_addr
                if size is not None:
                    size -= new_ip - addr
                if num_inst is not None:
                    num_inst -= state.scratch.num_insns
                addr = new_ip

                # clear the stage before creating the new IRSB
                state.scratch.dirty_addrs.clear()
                irsb = None

            except SimError as ex:
                ex.record_state(state)
                raise
            else:
                break
        state._inspect('irsb', BP_AFTER, address=addr)

        successors.processed = True

    def _handle_irsb(self, state, successors, irsb, skip_stmts, last_stmt, whitelist):
        # shortcut. we'll be typing this a lot
        ss = irsb.statements
        num_stmts = len(ss)

        # fill in artifacts
        successors.artifacts['irsb'] = irsb
        successors.artifacts['irsb_size'] = irsb.size
        successors.artifacts['irsb_direct_next'] = irsb.direct_next
        successors.artifacts['irsb_default_jumpkind'] = irsb.jumpkind

        insn_addrs = [ ]

        has_default_exit = True
        if irsb.next is None:
            l.warning("The .next property of IRSB %#x has an unexpected value None. "
                      "has_default_exit will be set to False.",
                      irsb.addr)
            has_default_exit = False

        # if we've told the block to truncate before it ends, it will definitely have a default
        # exit barring errors
        has_default_exit = has_default_exit and (last_stmt in (None, 'default') or num_stmts <= last_stmt)

        # This option makes us only execute the last four instructions
        if o.SUPER_FASTPATH in state.options:
            imark_counter = 0
            for i in range(len(ss) - 1, -1, -1):
                if type(ss[i]) is pyvex.IRStmt.IMark:
                    imark_counter += 1
                if imark_counter >= 4:
                    skip_stmts = max(skip_stmts, i)
                    break

        # set the current basic block address that's being processed
        state.scratch.bbl_addr = irsb.addr

        for stmt_idx, stmt in enumerate(ss):
            if isinstance(stmt, pyvex.IRStmt.IMark):
                insn_addrs.append(stmt.addr + stmt.delta)

            if stmt_idx < skip_stmts:
                l.debug("Skipping statement %d", stmt_idx)
                continue
            if last_stmt is not None and last_stmt != 'default' and stmt_idx > last_stmt:
                l.debug("Truncating statement %d", stmt_idx)
                continue
            if whitelist is not None and stmt_idx not in whitelist:
                l.debug("Blacklisting statement %d", stmt_idx)
                continue

            try:
                state.scratch.stmt_idx = stmt_idx
                state._inspect('statement', BP_BEFORE, statement=stmt_idx)
                cont = self._handle_statement(state, successors, stmt)
                state._inspect('statement', BP_AFTER)
                if not cont:
                    return
            except UnsupportedDirtyError:
                if o.BYPASS_UNSUPPORTED_IRDIRTY not in state.options:
                    raise
                if stmt.tmp not in (0xffffffff, -1):
                    retval_size = state.scratch.tyenv.sizeof(stmt.tmp)
                    retval = state.solver.Unconstrained("unsupported_dirty_%s" % stmt.cee.name, retval_size, key=('dirty', stmt.cee.name))
                    state.scratch.store_tmp(stmt.tmp, retval, None, None)
                state.history.add_event('resilience', resilience_type='dirty', dirty=stmt.cee.name,
                                    message='unsupported Dirty call')
            except (SimSolverError, SimMemoryAddressError):
                l.warning("%#x hit an error while analyzing statement %d", successors.addr, stmt_idx, exc_info=True)
                has_default_exit = False
                break

        state.scratch.stmt_idx = num_stmts

        successors.artifacts['insn_addrs'] = insn_addrs

        # If there was an error, and not all the statements were processed,
        # then this block does not have a default exit. This can happen if
        # the block has an unavoidable "conditional" exit or if there's a legitimate
        # error in the simulation
        if has_default_exit:
            l.debug("%s adding default exit.", self)

            try:
                with state.history.subscribe_actions() as next_deps:
                    next_expr = self.handle_expression(state, irsb.next)

                if o.TRACK_JMP_ACTIONS in state.options:
                    target_ao = SimActionObject(next_expr, deps=next_deps, state=state)
                    state.history.add_action(SimActionExit(state, target_ao, exit_type=SimActionExit.DEFAULT))
                successors.add_successor(state, next_expr, state.scratch.guard, irsb.jumpkind,
                                         exit_stmt_idx='default', exit_ins_addr=state.scratch.ins_addr)

            except KeyError:
                # For some reason, the temporary variable that the successor relies on does not exist.
                # It can be intentional (e.g. when executing a program slice)
                # We save the current state anyways
                successors.unsat_successors.append(state)
                l.debug("The temporary variable for default exit of %s is missing.", self)
        else:
            l.debug("%s has no default exit", self)

        # do return emulation and calless stuff
        for exit_state in list(successors.all_successors):
            exit_jumpkind = exit_state.history.jumpkind
            if exit_jumpkind is None: exit_jumpkind = ""

            if o.CALLLESS in state.options and exit_jumpkind == "Ijk_Call":
                exit_state.registers.store(
                    exit_state.arch.ret_offset,
                    exit_state.solver.Unconstrained('fake_ret_value', exit_state.arch.bits)
                )
                exit_state.scratch.target = exit_state.solver.BVV(
                    successors.addr + irsb.size, exit_state.arch.bits
                )
                exit_state.history.jumpkind = "Ijk_Ret"
                exit_state.regs.ip = exit_state.scratch.target

            elif o.DO_RET_EMULATION in exit_state.options and \
                (exit_jumpkind == "Ijk_Call" or exit_jumpkind.startswith('Ijk_Sys')):
                l.debug("%s adding postcall exit.", self)

                ret_state = exit_state.copy()
                guard = ret_state.solver.true if o.TRUE_RET_EMULATION_GUARD in state.options else ret_state.solver.false
                target = ret_state.solver.BVV(successors.addr + irsb.size, ret_state.arch.bits)
                if ret_state.arch.call_pushes_ret and not exit_jumpkind.startswith('Ijk_Sys'):
                    ret_state.regs.sp = ret_state.regs.sp + ret_state.arch.bytes
                successors.add_successor(
                    ret_state, target, guard, 'Ijk_FakeRet', exit_stmt_idx='default',
                    exit_ins_addr=state.scratch.ins_addr
                )

        if whitelist and successors.is_empty:
            # If statements of this block are white-listed and none of the exit statement (not even the default exit) is
            # in the white-list, successors will be empty, and there is no way for us to get the final state.
            # To this end, a final state is manually created
            l.debug('Add an incomplete successor state as the result of an incomplete execution due to the white-list.')
            successors.flat_successors.append(state)

    def _handle_statement(self, state, successors, stmt):
        """
        This function receives an initial state and imark and processes a list of pyvex.IRStmts
        It annotates the request with a final state, last imark, and a list of SimIRStmts
        """
        if type(stmt) == pyvex.IRStmt.IMark:
            # TODO how much of this could be moved into the imark handler
            ins_addr = stmt.addr + stmt.delta
            state.scratch.ins_addr = ins_addr

            # Raise an exception if we're suddenly in self-modifying code
            for subaddr in range(stmt.len):
                if subaddr + stmt.addr in state.scratch.dirty_addrs:
                    raise SimReliftException(state)
            state._inspect('instruction', BP_AFTER)

            l.debug("IMark: %#x", stmt.addr)
            state.scratch.num_insns += 1
            state._inspect('instruction', BP_BEFORE, instruction=ins_addr)

        # process it!
        try:
            stmt_handler = self.stmt_handlers[stmt.tag_int]
        except IndexError:
            l.error("Unsupported statement type %s", (type(stmt)))
            if o.BYPASS_UNSUPPORTED_IRSTMT not in state.options:
                raise UnsupportedIRStmtError("Unsupported statement type %s" % (type(stmt)))
            state.history.add_event('resilience', resilience_type='irstmt', stmt=type(stmt).__name__, message='unsupported IRStmt')
            return None
        else:
            exit_data = stmt_handler(self, state, stmt)

        # for the exits, put *not* taking the exit on the list of constraints so
        # that we can continue on. Otherwise, add the constraints
        if exit_data is not None:
            l.debug("%s adding conditional exit", self)

            target, guard, jumpkind = exit_data

            # Produce our successor state!
            # Let SimSuccessors.add_successor handle the nitty gritty details

            cont_state = None
            exit_state = None

            if o.COPY_STATES not in state.options:
                # very special logic to try to minimize copies
                # first, check if this branch is impossible
                if guard.is_false():
                    cont_state = state
                elif o.LAZY_SOLVES not in state.options and not state.solver.satisfiable(extra_constraints=(guard,)):
                    cont_state = state

                # then, check if it's impossible to continue from this branch
                elif guard.is_true():
                    exit_state = state
                elif o.LAZY_SOLVES not in state.options and not state.solver.satisfiable(extra_constraints=(claripy.Not(guard),)):
                    exit_state = state
                else:
                    exit_state = state.copy()
                    cont_state = state
            else:
                exit_state = state.copy()
                cont_state = state

            if exit_state is not None:
                successors.add_successor(exit_state, target, guard, jumpkind,
                                         exit_stmt_idx=state.scratch.stmt_idx, exit_ins_addr=state.scratch.ins_addr)

            if cont_state is None:
                return False

            # Do our bookkeeping on the continuing state
            cont_condition = claripy.Not(guard)
            cont_state.add_constraints(cont_condition)
            cont_state.scratch.guard = claripy.And(cont_state.scratch.guard, cont_condition)

        return True

    def handle_expression(self, state, expr):
        try:
            handler = self.expr_handlers[expr.tag_int]
            if handler is None:
                raise IndexError
        except IndexError:
            if o.BYPASS_UNSUPPORTED_IREXPR not in state.options:
                raise UnsupportedIRExprError("Unsupported expression type %s" % (type(expr)))
            else:
                handler = SimIRExpr_Unsupported

        state._inspect('expr', BP_BEFORE, expr=expr)
        result = handler(self, state, expr)

        if o.SIMPLIFY_EXPRS in state.options:
            result = state.solver.simplify(result)

        if state.solver.symbolic(result) and o.CONCRETIZE in state.options:
            concrete_value = state.solver.BVV(state.solver.eval(result), len(result))
            state.add_constraints(result == concrete_value)
            result = concrete_value

        state._inspect('expr', BP_AFTER, expr=expr, expr_result=result)
        return result

    def lift(self,
             state=None,
             clemory=None,
             insn_bytes=None,
             arch=None,
             addr=None,
             size=None,
             num_inst=None,
             traceflags=0,
             thumb=False,
             extra_stop_points=None,
             opt_level=None,
             strict_block_end=None,
             skip_stmts=False,
             collect_data_refs=False):

        """
        Lift an IRSB.

        There are many possible valid sets of parameters. You at the very least must pass some
        source of data, some source of an architecture, and some source of an address.

        Sources of data in order of priority: insn_bytes, clemory, state

        Sources of an address, in order of priority: addr, state

        Sources of an architecture, in order of priority: arch, clemory, state

        :param state:           A state to use as a data source.
        :param clemory:         A cle.memory.Clemory object to use as a data source.
        :param addr:            The address at which to start the block.
        :param thumb:           Whether the block should be lifted in ARM's THUMB mode.
        :param opt_level:       The VEX optimization level to use. The final IR optimization level is determined by
                                (ordered by priority):
                                - Argument opt_level
                                - opt_level is set to 1 if OPTIMIZE_IR exists in state options
                                - self._default_opt_level
        :param insn_bytes:      A string of bytes to use as a data source.
        :param size:            The maximum size of the block, in bytes.
        :param num_inst:        The maximum number of instructions.
        :param traceflags:      traceflags to be passed to VEX. (default: 0)
        :param strict_block_end:   Whether to force blocks to end at all conditional branches (default: false)
        """

        # phase 0: sanity check
        if not state and not clemory and not insn_bytes:
            raise ValueError("Must provide state or clemory or insn_bytes!")
        if not state and not clemory and not arch:
            raise ValueError("Must provide state or clemory or arch!")
        if addr is None and not state:
            raise ValueError("Must provide state or addr!")
        if arch is None:
            arch = clemory._arch if clemory else state.arch
        if arch.name.startswith("MIPS") and self._single_step:
            l.error("Cannot specify single-stepping on MIPS.")
            self._single_step = False

        # phase 1: parameter defaults
        if addr is None:
            addr = state.solver.eval(state._ip)
        if size is not None:
            size = min(size, VEX_IRSB_MAX_SIZE)
        if size is None:
            size = VEX_IRSB_MAX_SIZE
        if num_inst is not None:
            num_inst = min(num_inst, VEX_IRSB_MAX_INST)
        if num_inst is None and self._single_step:
            num_inst = 1
        if opt_level is None:
            if state and o.OPTIMIZE_IR in state.options:
                opt_level = 1
            else:
                opt_level = self._default_opt_level
        if strict_block_end is None:
            strict_block_end = self.default_strict_block_end
        if self._support_selfmodifying_code:
            if opt_level > 0:
                if once('vex-engine-smc-opt-warning'):
                    l.warning("Self-modifying code is not always correctly optimized by PyVEX. "
                              "To guarantee correctness, VEX optimizations have been disabled.")
                opt_level = 0
                if state and o.OPTIMIZE_IR in state.options:
                    state.options.remove(o.OPTIMIZE_IR)
        if skip_stmts is not True:
            skip_stmts = False

        use_cache = self._use_cache
        if skip_stmts or collect_data_refs:
            # Do not cache the blocks if skip_stmts or collect_data_refs are enabled
            use_cache = False

        # phase 2: thumb normalization
        thumb = int(thumb)
        if isinstance(arch, ArchARM):
            if addr % 2 == 1:
                thumb = 1
            if thumb:
                addr &= ~1
        elif thumb:
            l.error("thumb=True passed on non-arm architecture!")
            thumb = 0

        # phase 3: check cache
        cache_key = None
        if use_cache:
            cache_key = (addr, insn_bytes, size, num_inst, thumb, opt_level, strict_block_end)
            if cache_key in self._block_cache:
                self._block_cache_hits += 1
                irsb = self._block_cache[cache_key]
                stop_point = self._first_stoppoint(irsb, extra_stop_points)
                if stop_point is None:
                    return irsb
                else:
                    size = stop_point - addr
                    # check the cache again
                    cache_key = (addr, insn_bytes, size, num_inst, thumb, opt_level, strict_block_end)
                    if cache_key in self._block_cache:
                        self._block_cache_hits += 1
                        return self._block_cache[cache_key]
                    else:
                        self._block_cache_misses += 1
            else:
                # a special case: `size` is used as the maximum allowed size
                tmp_cache_key = (addr, insn_bytes, VEX_IRSB_MAX_SIZE, num_inst, thumb, opt_level, strict_block_end)
                try:
                    irsb = self._block_cache[tmp_cache_key]
                    if irsb.size <= size:
                        self._block_cache_hits += 1
                        return self._block_cache[tmp_cache_key]
                except KeyError:
                    self._block_cache_misses += 1

        # phase 4: get bytes
        if insn_bytes is not None:
            buff, size = insn_bytes, len(insn_bytes)
        else:
            buff, size = self._load_bytes(addr, size, state, clemory)

        if not buff or size == 0:
            raise SimEngineError("No bytes in memory for block starting at %#x." % addr)

        # phase 5: call into pyvex
        # l.debug("Creating pyvex.IRSB of arch %s at %#x", arch.name, addr)
        try:
            for subphase in range(2):

                irsb = pyvex.lift(buff, addr + thumb, arch,
                                  max_bytes=size,
                                  max_inst=num_inst,
                                  bytes_offset=thumb,
                                  traceflags=traceflags,
                                  opt_level=opt_level,
                                  strict_block_end=strict_block_end,
                                  skip_stmts=skip_stmts,
                                  collect_data_refs=collect_data_refs,
                                  )

                if subphase == 0 and irsb.statements is not None:
                    # check for possible stop points
                    stop_point = self._first_stoppoint(irsb, extra_stop_points)
                    if stop_point is not None:
                        size = stop_point - addr
                        continue

                if use_cache:
                    self._block_cache[cache_key] = irsb
                return irsb

        # phase x: error handling
        except pyvex.PyVEXError as e:
            l.debug("VEX translation error at %#x", addr)
            if isinstance(buff, bytes):
                l.debug('Using bytes: %r', buff)
            else:
                l.debug("Using bytes: %r", pyvex.ffi.buffer(buff, size))
            raise SimTranslationError("Unable to translate bytecode") from e

    def _load_bytes(self, addr, max_size, state=None, clemory=None):
        if not clemory:
            if state is None:
                raise SimEngineError('state and clemory cannot both be None in _load_bytes().')
            if o.ABSTRACT_MEMORY in state.options:
                # abstract memory
                clemory = state.memory.regions['global'].memory.mem._memory_backer
            else:
                # symbolic memory
                clemory = state.memory.mem._memory_backer

        buff, size = b"", 0

        # Load from the clemory if we can
        smc = self._support_selfmodifying_code
        if state:
            try:
                p = state.memory.permissions(addr)
                if p.symbolic:
                    smc = True
                else:
                    smc = claripy.is_true(p & 2 != 0)
            except: # pylint: disable=bare-except
                smc = True # I don't know why this would ever happen, we checked this right?

        if not smc or not state:
            try:
                start, backer = next(clemory.backers(addr))
            except StopIteration:
                pass
            else:
                if start <= addr:
                    offset = addr - start
                    buff = pyvex.ffi.from_buffer(backer) + offset
                    size = len(backer) - offset

        # If that didn't work, try to load from the state
        if size == 0 and state:
            fallback = True
            if addr in state.memory and addr + max_size - 1 in state.memory:
                try:
                    buff = state.solver.eval(state.memory.load(addr, max_size, inspect=False), cast_to=bytes)
                    size = max_size
                    fallback = False
                except SimError:
                    l.warning("Cannot load bytes at %#x. Fallback to the slow path.", addr)

            if fallback:
                buff_lst = [ ]
                symbolic_warned = False
                for i in range(max_size):
                    if addr + i in state.memory:
                        try:
                            byte = state.memory.load(addr + i, 1, inspect=False)
                            if byte.symbolic and not symbolic_warned:
                                symbolic_warned = True
                                l.warning("Executing symbolic code at %#x", addr + i)
                            buff_lst.append(state.solver.eval(byte))
                        except SimError:
                            break
                    else:
                        break

                buff = bytes(buff_lst)
                size = len(buff)

        size = min(max_size, size)
        return buff, size

    def _first_stoppoint(self, irsb, extra_stop_points=None):
        """
        Enumerate the imarks in the block. If any of them (after the first one) are at a stop point, returns the address
        of the stop point. None is returned otherwise.
        """
        if self._stop_points is None and extra_stop_points is None and self.project is None:
            return None

        first_imark = True
        for stmt in irsb.statements:
            if type(stmt) is pyvex.stmt.IMark:  # pylint: disable=unidiomatic-typecheck
                addr = stmt.addr + stmt.delta
                if not first_imark:
                    if self.is_stop_point(addr, extra_stop_points):
                        # could this part be moved by pyvex?
                        return addr
                    if stmt.delta != 0 and self.is_stop_point(stmt.addr, extra_stop_points):
                        return addr

                first_imark = False
        return None

    def clear_cache(self):
        self._block_cache = LRUCache(maxsize=self._cache_size)

        self._block_cache_hits = 0
        self._block_cache_misses = 0

    #
    # Pickling
    #

    def __setstate__(self, state):
        self.project = state['project']
        self._stop_points = state['_stop_points']
        self._use_cache = state['_use_cache']
        self._default_opt_level = state['_default_opt_level']
        self._support_selfmodifying_code = state['_support_selfmodifying_code']
        self._single_step = state['_single_step']
        self._cache_size = state['_cache_size']
        self.default_strict_block_end = state['default_strict_block_end']
        self.expr_handlers = state['expr_handlers']
        self.stmt_handlers = state['stmt_handlers']

        # rebuild block cache
        self._initialize_block_cache()

    def __getstate__(self):
        s = {}
        s['project'] = self.project
        s['_stop_points'] = self._stop_points
        s['_use_cache'] = self._use_cache
        s['_default_opt_level'] = self._default_opt_level
        s['_support_selfmodifying_code'] = self._support_selfmodifying_code
        s['_single_step'] = self._single_step
        s['_cache_size'] = self._cache_size
        s['default_strict_block_end'] = self.default_strict_block_end
        s['expr_handlers'] = self.expr_handlers
        s['stmt_handlers'] = self.stmt_handlers

        return s
