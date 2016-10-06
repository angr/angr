import logging
l = logging.getLogger("simuvex.vex.irsb")
#l.setLevel(logging.DEBUG)

# because pylint can't load pyvex
# pylint: disable=F0401
import pyvex
import claripy
from ..engine import SimEngine

#pylint:disable=unidiomatic-typecheck

class SimEngineVEX(SimEngine):
    """
    Execution engine based on VEX, Valgrind's IR.
    """

    def _process_request(self, request):
        request.irsb = irsb = request.args[0]

        if irsb.size == 0:
            raise SimIRSBError("Empty IRSB passed to SimIRSB.")

        # victims of the industrial revolution
        #self.first_imark = IMark(next(i for i in self.irsb.statements if type(i) is pyvex.IRStmt.IMark))
        #self.last_imark = self.first_imark
        request.active_state.scratch.bbl_addr = request.addr
        request.active_state.scratch.executed_block_count = 1
        request.active_state.sim_procedure = None

        request.active_state._inspect('irsb', BP_BEFORE, address=request.addr)
        try:
            self._handle_irsb(request)
        except SimError as e:
            e.record_state(request.active_state)
            raise
        request.active_state._inspect('irsb', BP_AFTER)

    def _handle_irsb(self, request):
        # some finalization
        num_stmts = len(request.irsb.statements)
        has_default_exit = request.kwargs.get('last_stmt', num_stmts) <= num_stmts

        # handle the statements
        try:
            # handle_statements will fill these out
            request.conditional_guards = self._handle_statements(request)
        except (SimSolverError, SimMemoryAddressError):
            l.warning("%s hit an error while analyzing statement %d", self, request.active_state.scratch.stmt_idx, exc_info=True)
            has_default_exit = False

        request.active_state.scratch.stmt_idx = num_stmts

        # If there was an error, and not all the statements were processed,
        # then this block does not have a default exit. This can happen if
        # the block has an unavoidable "conditional" exit or if there's a legitimate
        # error in the simulation
        if has_default_exit:
            l.debug("%s adding default exit.", self)

            try:
                next_expr = translate_expr(request.irsb.next, num_stmts, request.active_state)
                request.active_state.log.extend_actions(next_expr.actions)

                if o.TRACK_JMP_ACTIONS in request.active_state.options:
                    target_ao = SimActionObject(
                        next_expr.expr,
                        reg_deps=next_expr.reg_deps(), tmp_deps=next_expr.tmp_deps()
                    )
                    request.active_state.log.add_action(SimActionExit(
                        request.active_state, target_ao, exit_type=SimActionExit.DEFAULT
                    ))

                default_guard = claripy.And(*map(
                    claripy.Not, request.conditional_guards
                )) if len(request.conditional_guards) else claripy.true
                self.add_successor(
                    request, request.active_state, next_expr.expr,
                    default_guard, request.irsb.jumpkind, 'default'
                )

            except KeyError:
                # For some reason, the temporary variable that the successor relies on does not exist.
                # It can be intentional (e.g. when executing a program slice)
                # We save the current state anyways
                request.unsat_successors.append(request.active_state)
                l.debug("The temporary variable for default exit of %s is missing.", self)
        else:
            l.debug("%s has no default exit", self)

        # do return emulation and calless stuff
        all_successors = request.successors + request.unsat_successors

        for exit_state in all_successors:
            exit_jumpkind = exit_state.scratch.jumpkind
            if exit_jumpkind is None: exit_jumpkind = ""

            if o.CALLLESS in request.active_state.options and exit_jumpkind == "Ijk_Call":
                exit_state.registers.store(
                    exit_state.arch.ret_offset,
                    exit_state.se.Unconstrained('fake_ret_value', exit_state.arch.bits)
                )
                exit_state.scratch.target = exit_state.se.BVV(
                    request.addr + request.irsb.size, exit_state.arch.bits
                )
                exit_state.scratch.jumpkind = "Ijk_Ret"
                exit_state.regs.ip = exit_state.scratch.target

            elif (
                o.DO_RET_EMULATION in exit_state.options and
                (exit_jumpkind == "Ijk_Call" or exit_jumpkind.startswith('Ijk_Sys'))
            ):
                l.debug("%s adding postcall exit.", self)

                ret_state = exit_state.copy()
                guard = ret_state.se.true if o.TRUE_RET_EMULATION_GUARD in request.active_state.options else ret_state.se.false
                target = ret_state.se.BVV(request.addr + request.irsb.size, ret_state.arch.bits)
                if ret_state.arch.call_pushes_ret:
                    ret_state.regs.sp = ret_state.regs.sp + ret_state.arch.bytes
                self.add_successor(
                    request, ret_state, target, guard, 'Ijk_FakeRet', exit_stmt_idx='default'
                )

    def _handle_statements(self, request):
        """
        This function receives an initial state and imark and processes a list of pyvex.IRStmts
        It annotates the request with a final state, last imark, and a list of SimIRStmts
        """

        # Translate all statements until something errors out
        stmts = request.irsb.statements

        skip_stmts = 0
        if o.SUPER_FASTPATH in request.active_state.options:
            # Only execute the last but two instructions
            imark_counter = 0
            for i in xrange(len(stmts) - 1, -1, -1):
                if type(stmts[i]) is pyvex.IRStmt.IMark:
                    imark_counter += 1
                if imark_counter >= 2:
                    skip_stmts = i
                    break

        whitelist = request.kwargs.get('whitelist')
        last_stmt = request.kwargs.get('last_stmt')

        for stmt_idx, stmt in enumerate(stmts):
            if last_stmt is not None and stmt_idx > last_stmt:
                l.debug("%s stopping analysis at statement %d.", self, last_stmt)
                break

            if stmt_idx < skip_stmts:
                continue

            #l.debug("%s processing statement %s of max %s", self, stmt_idx, self.last_stmt)
            request.active_state.scratch.stmt_idx = stmt_idx

            # we'll pass in the imark to the statements
            if type(stmt) == pyvex.IRStmt.IMark:
                request.active_state.scratch.ins_addr = stmt.addr + stmt.delta

                for subaddr in xrange(stmt.addr, stmt.addr + stmt.len):
                    if subaddr in request.active_state.scratch.dirty_addrs:
                        raise SimReliftException(request.active_state)
                request.active_state._inspect('instruction', BP_AFTER)

                l.debug("IMark: %#x", stmt.addr)
                request.active_state.scratch.num_insns += 1
                request.active_state._inspect('instruction', BP_BEFORE, instruction=stmt.addr)

            if whitelist is not None and stmt_idx not in whitelist:
                l.debug("... whitelist says skip it!")
                continue
            elif whitelist is not None:
                l.debug("... whitelist says analyze it!")

            # process it!
            request.active_state._inspect('statement', BP_BEFORE, statement=stmt_idx)
            s_stmt = translate_stmt(request.irsb, stmt_idx, request.active_state)
            if s_stmt is not None:
                request.active_state.log.extend_actions(s_stmt.actions)
            request.active_state._inspect('statement', BP_AFTER)

            # for the exits, put *not* taking the exit on the list of constraints so
            # that we can continue on. Otherwise, add the constraints
            if type(stmt) == pyvex.IRStmt.Exit:
                l.debug("%s adding conditional exit", self)

                e = request.active_state.copy()
                self.add_successor(request, e, s_stmt.target, s_stmt.guard, s_stmt.jumpkind, stmt_idx)
                request.conditional_guards.append(e.scratch.guard)
                request.active_state.add_constraints(request.active_state.se.Not(e.scratch.guard))

    @staticmethod
    def imark_addrs(request):
        """
        Returns a list of instructions that are part of this block.
        """
        return [ i.addr for i in request.irsb.statements if type(i) == pyvex.IRStmt.IMark ]

from .statements import translate_stmt
from .expressions import translate_expr

from simuvex import s_options as o
from simuvex.plugins.inspect import BP_AFTER, BP_BEFORE
from simuvex.s_errors import SimError, SimIRSBError, SimSolverError, SimMemoryAddressError, SimReliftException
from simuvex.s_action import SimActionExit, SimActionObject
