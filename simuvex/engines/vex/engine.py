import logging
l = logging.getLogger("simuvex.engines.vex.engine")

import pyvex
import claripy
from ..engine import SimEngine

#pylint: disable=arguments-differ

class SimEngineVEX(SimEngine):
    """
    Execution engine based on VEX, Valgrind's IR.
    """
    def process(self, state, irsb,
            skip_stmts=0,
            last_stmt=99999999,
            whitelist=None,
            inline=False,
            force_addr=None):
        """
        :param state:       The state with which to execute
        :param irsb:        The PyVEX IRSB object to use for execution. If not provided one will be lifted.
        :param skip_stmts:  The number of statements to skip in processing
        :param last_stmt:   Do not execute any statements after this statement
        :param whitelist:   Only execute statements in this set
        :param inline:      This is an inline execution. Do not bother copying the state.
        :param force_addr:  Force execution to pretend that we're working at this concrete address
        :returns:           A SimSuccessors object categorizing the block's successors
        """
        return super(SimEngineVEX, self).process(state, irsb,
                skip_stmts=skip_stmts,
                last_stmt=last_stmt,
                whitelist=whitelist,
                inline=inline,
                force_addr=force_addr)

    def _process(self, state, successors, irsb, skip_stmts=0, last_stmt=99999999, whitelist=None):
        successors.sort = 'IRSB'
        successors.description = 'IRSB'
        if irsb.size == 0:
            raise SimIRSBError("Empty IRSB passed to SimIRSB.")

        state.scratch.executed_block_count = 1
        state.scratch.guard = claripy.true
        state.scratch.sim_procedure = None
        state.scratch.tyenv = irsb.tyenv
        state.scratch.irsb = irsb

        state._inspect('irsb', BP_BEFORE, address=successors.addr)
        try:
            self._handle_irsb(state, successors, irsb, skip_stmts, last_stmt, whitelist)
        except SimError as e:
            e.record_state(state)
            raise
        state._inspect('irsb', BP_AFTER)

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

        # if we've told the block to truncate before it ends, it will definitely have a default
        # exit barring errors
        has_default_exit = num_stmts <= last_stmt

        # This option makes us only execute the last two instructions
        if o.SUPER_FASTPATH in state.options:
            imark_counter = 0
            for i in xrange(len(ss) - 1, -1, -1):
                if type(ss[i]) is pyvex.IRStmt.IMark:
                    imark_counter += 1
                if imark_counter >= 2:
                    skip_stmts = max(skip_stmts, i)
                    break

        for stmt_idx, stmt in enumerate(ss):
            if isinstance(stmt, pyvex.IRStmt.IMark):
                insn_addrs.append(stmt.addr + stmt.delta)

            if stmt_idx < skip_stmts:
                l.debug("Skipping statement %d", stmt_idx)
                continue
            if stmt_idx > last_stmt:
                l.debug("Truncating statement %d", stmt_idx)
                continue
            if whitelist is not None and stmt_idx not in whitelist:
                l.debug("Blacklisting statement %d", stmt_idx)
                continue

            try:
                state.scratch.stmt_idx = stmt_idx
                state._inspect('statement', BP_BEFORE, statement=stmt_idx)
                self._handle_statement(state, successors, stmt)
                state._inspect('statement', BP_AFTER)
            except UnsupportedDirtyError:
                if o.BYPASS_UNSUPPORTED_IRDIRTY not in state.options:
                    raise
                if stmt.tmp not in (0xffffffff, -1):
                    retval_size = stmt.result_size/8
                    retval = state.se.Unconstrained("unsupported_dirty_%s" % stmt.cee.name, retval_size)
                    state.scratch.store_tmp(stmt.tmp, retval, None, None)
                state.log.add_event('resilience', resilience_type='dirty', dirty=stmt.cee.name, message='unsupported Dirty call')
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
                next_expr = translate_expr(irsb.next, state)
                state.log.extend_actions(next_expr.actions)

                if o.TRACK_JMP_ACTIONS in state.options:
                    target_ao = SimActionObject(
                        next_expr.expr,
                        reg_deps=next_expr.reg_deps(), tmp_deps=next_expr.tmp_deps()
                    )
                    state.log.add_action(SimActionExit(state, target_ao, exit_type=SimActionExit.DEFAULT))

                successors.add_successor(state, next_expr.expr, state.scratch.guard, irsb.jumpkind,
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
            exit_jumpkind = exit_state.scratch.jumpkind
            if exit_jumpkind is None: exit_jumpkind = ""

            if o.CALLLESS in state.options and exit_jumpkind == "Ijk_Call":
                exit_state.registers.store(
                    exit_state.arch.ret_offset,
                    exit_state.se.Unconstrained('fake_ret_value', exit_state.arch.bits)
                )
                exit_state.scratch.target = exit_state.se.BVV(
                    successors.addr + irsb.size, exit_state.arch.bits
                )
                exit_state.scratch.jumpkind = "Ijk_Ret"
                exit_state.regs.ip = exit_state.scratch.target

            elif o.DO_RET_EMULATION in exit_state.options and \
                (exit_jumpkind == "Ijk_Call" or exit_jumpkind.startswith('Ijk_Sys')):
                l.debug("%s adding postcall exit.", self)

                ret_state = exit_state.copy()
                guard = ret_state.se.true if o.TRUE_RET_EMULATION_GUARD in state.options else ret_state.se.false
                target = ret_state.se.BVV(successors.addr + irsb.size, ret_state.arch.bits)
                if ret_state.arch.call_pushes_ret:
                    ret_state.regs.sp = ret_state.regs.sp + ret_state.arch.bytes
                successors.add_successor(
                    ret_state, target, guard, 'Ijk_FakeRet', exit_stmt_idx='default',
                    exit_ins_addr=state.scratch.ins_addr
                )

    def _handle_statement(self, state, successors, stmt):
        """
        This function receives an initial state and imark and processes a list of pyvex.IRStmts
        It annotates the request with a final state, last imark, and a list of SimIRStmts
        """
        if type(stmt) == pyvex.IRStmt.IMark:
            state.scratch.ins_addr = stmt.addr + stmt.delta

            # Raise an exception if we're suddenly in self-modifying code
            for subaddr in xrange(stmt.addr, stmt.addr + stmt.len):
                if subaddr in state.scratch.dirty_addrs:
                    raise SimReliftException(state)
            state._inspect('instruction', BP_AFTER)

            l.debug("IMark: %#x", stmt.addr)
            state.scratch.num_insns += 1
            state._inspect('instruction', BP_BEFORE, instruction=stmt.addr)

        # process it!
        s_stmt = translate_stmt(stmt, state)
        if s_stmt is not None:
            state.log.extend_actions(s_stmt.actions)

        # for the exits, put *not* taking the exit on the list of constraints so
        # that we can continue on. Otherwise, add the constraints
        if type(stmt) == pyvex.IRStmt.Exit:
            l.debug("%s adding conditional exit", self)

            # Produce our successor state!
            # Let SimSuccessors.add_successor handle the nitty gritty details
            exit_state = state.copy()
            successors.add_successor(exit_state, s_stmt.target, s_stmt.guard, s_stmt.jumpkind,
                                     exit_stmt_idx=state.scratch.stmt_idx, exit_ins_addr=state.scratch.ins_addr)

            # Do our bookkeeping on the continuing state
            cont_condition = claripy.Not(s_stmt.guard)
            state.add_constraints(cont_condition)
            state.scratch.guard = claripy.And(state.scratch.guard, cont_condition)

from .statements import translate_stmt
from .expressions import translate_expr

from ... import s_options as o
from ...plugins.inspect import BP_AFTER, BP_BEFORE
from ...s_errors import SimError, SimIRSBError, SimSolverError, SimMemoryAddressError, SimReliftException, UnsupportedDirtyError
from ...s_action import SimActionExit, SimActionObject
