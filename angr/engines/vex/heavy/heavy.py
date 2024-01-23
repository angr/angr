import logging
import claripy
import pyvex

from angr.engines.engine import SuccessorsMixin
from ..light import VEXMixin
from ..lifter import VEXLifter
from ..claripy.datalayer import ClaripyDataMixin, symbol
from ....utils.constants import DEFAULT_STATEMENT
from .... import sim_options as o
from .... import errors
from . import dirty

l = logging.getLogger(__name__)


class VEXEarlyExit(Exception):
    # pylint:disable=missing-class-docstring
    pass


class SimStateStorageMixin(VEXMixin):
    # pylint:disable=arguments-differ,missing-class-docstring
    def _perform_vex_expr_Get(self, offset, ty, action=None, inspect=True):
        return self.state.registers.load(offset, self._ty_to_bytes(ty), action=action, inspect=inspect)

    def _perform_vex_expr_RdTmp(self, tmp):
        return self.state.scratch.tmp_expr(tmp)

    def _perform_vex_expr_Load(self, addr, ty, endness, action=None, inspect=True, condition=None, **kwargs):
        return self.state.memory.load(
            addr, self._ty_to_bytes(ty), endness=endness, action=action, inspect=inspect, condition=condition
        )

    def _perform_vex_stmt_Put(self, offset, data, action=None, inspect=True):
        self.state.registers.store(offset, data, action=action, inspect=inspect)

    def _perform_vex_stmt_Store(self, addr, data, endness, action=None, inspect=True, condition=None):
        if (
            o.UNICORN_HANDLE_SYMBOLIC_ADDRESSES in self.state.options
            or o.UNICORN_HANDLE_SYMBOLIC_CONDITIONS in self.state.options
        ) and data.symbolic:
            # Update the concrete memory value before updating symbolic value so that correct values are mapped into
            # native interface
            concrete_data = claripy.BVV(self.state.solver.eval(data), data.size())
            self.state.memory.store(
                addr, concrete_data, endness=endness, action=None, inspect=False, condition=condition
            )

        self.state.memory.store(
            addr, data, size=data.size() // 8, endness=endness, action=action, inspect=inspect, condition=condition
        )

    def _perform_vex_stmt_WrTmp(self, tmp, data, deps=None):
        self.state.scratch.store_tmp(tmp, data, deps=deps)


# pylint:disable=arguments-differ
class HeavyVEXMixin(SuccessorsMixin, ClaripyDataMixin, SimStateStorageMixin, VEXMixin, VEXLifter):
    """
    Execution engine based on VEX, Valgrind's IR.

    Responds to the following parameters to the step stack:

    - irsb:        The PyVEX IRSB object to use for execution. If not provided one will be lifted.
    - skip_stmts:  The number of statements to skip in processing
    - last_stmt:   Do not execute any statements after this statement
    - whitelist:   Only execute statements in this set
    - thumb:       Whether the block should be force to be lifted in ARM's THUMB mode.
    - extra_stop_points:
                   An extra set of points at which to break basic blocks
    - opt_level:   The VEX optimization level to use.
    - insn_bytes:  A string of bytes to use for the block instead of the project.
    - size:        The maximum size of the block, in bytes.
    - num_inst:    The maximum number of instructions.
    - traceflags:  traceflags to be passed to VEX. (default: 0)
    """

    # entry point

    def process_successors(
        self,
        successors,
        irsb=None,
        insn_text=None,
        insn_bytes=None,
        thumb=False,
        size=None,
        num_inst=None,
        extra_stop_points=None,
        opt_level=None,
        **kwargs,
    ):
        if not pyvex.lifting.lifters[self.state.arch.name] or type(successors.addr) is not int:
            return super().process_successors(
                successors,
                extra_stop_points=extra_stop_points,
                num_inst=num_inst,
                size=size,
                insn_text=insn_text,
                insn_bytes=insn_bytes,
                **kwargs,
            )

        if insn_text is not None:
            if insn_bytes is not None:
                raise errors.SimEngineError("You cannot provide both 'insn_bytes' and 'insn_text'!")

            insn_bytes = self.project.arch.asm(insn_text, addr=successors.addr, thumb=thumb)
            if insn_bytes is None:
                raise errors.AngrAssemblyError(
                    "Assembling failed. Please make sure keystone is installed, and the assembly string is correct."
                )

        successors.sort = "IRSB"
        successors.description = "IRSB"
        self.state.history.recent_block_count = 1
        self.state.scratch.guard = claripy.true
        self.state.scratch.sim_procedure = None
        addr = successors.addr
        self.state.scratch.bbl_addr = addr

        while True:
            if irsb is None:
                irsb = self.lift_vex(
                    addr=addr,
                    state=self.state,
                    insn_bytes=insn_bytes,
                    thumb=thumb,
                    size=size,
                    num_inst=num_inst,
                    extra_stop_points=extra_stop_points,
                    opt_level=opt_level,
                )

            if (
                irsb.jumpkind == "Ijk_NoDecode"
                and irsb.next.tag == "Iex_Const"
                and irsb.next.con.value == irsb.addr
                and not self.state.project.is_hooked(irsb.addr)
            ):
                raise errors.SimIRSBNoDecodeError(
                    f"IR decoding error at 0x{addr:02x}. You can hook this "
                    "instruction with a python replacement using project.hook"
                    f"(0x{addr:02x}, your_function, length=length_of_instruction)."
                )

            if irsb.size == 0:
                raise errors.SimIRSBError("Empty IRSB passed to HeavyVEXMixin.")

            # check permissions, are we allowed to execute here? Do we care?
            if o.STRICT_PAGE_ACCESS in self.state.options:
                try:
                    perms = self.state.memory.permissions(addr)
                except errors.SimMemoryError as sim_mem_err:
                    raise errors.SimSegfaultError(addr, "exec-miss") from sim_mem_err
                else:
                    if not self.state.solver.symbolic(perms):
                        perms = self.state.solver.eval(perms)
                        if not perms & 4 and o.ENABLE_NX in self.state.options:
                            raise errors.SimSegfaultError(addr, "non-executable")

            self.state.scratch.set_tyenv(irsb.tyenv)
            self.state.scratch.irsb = irsb

            # fill in artifacts
            successors.artifacts["irsb"] = irsb
            successors.artifacts["irsb_size"] = irsb.size
            successors.artifacts["irsb_direct_next"] = irsb.direct_next
            successors.artifacts["irsb_default_jumpkind"] = irsb.jumpkind
            successors.artifacts["insn_addrs"] = []

            try:
                self.handle_vex_block(irsb)
            except errors.SimReliftException as e:
                self.state = e.state
                if insn_bytes is not None:
                    raise errors.SimEngineError("You cannot pass self-modifying code as insn_bytes!!!")
                new_ip = self.state.scratch.ins_addr
                if size is not None:
                    size -= new_ip - addr
                if num_inst is not None:
                    num_inst -= self.state.scratch.num_insns
                addr = new_ip

                # clear the stage before creating the new IRSB
                self.state.scratch.dirty_addrs.clear()
                irsb = None

            except errors.SimError as ex:
                ex.record_state(self.state)
                raise
            except VEXEarlyExit:
                break
            else:
                break

        # do return emulation and calless stuff
        for exit_state in list(successors.all_successors):
            exit_jumpkind = exit_state.history.jumpkind if exit_state.history.jumpkind else ""

            if o.CALLLESS in self.state.options and exit_jumpkind == "Ijk_Call":
                exit_state.registers.store(
                    exit_state.arch.ret_offset, exit_state.solver.Unconstrained("fake_ret_value", exit_state.arch.bits)
                )
                exit_state.scratch.target = exit_state.solver.BVV(successors.addr + irsb.size, exit_state.arch.bits)
                exit_state.history.jumpkind = "Ijk_Ret"
                exit_state.regs.ip = exit_state.scratch.target
                if exit_state.arch.call_pushes_ret:
                    exit_state.regs.sp = exit_state.regs.sp + exit_state.arch.bytes

            elif o.DO_RET_EMULATION in exit_state.options and (
                exit_jumpkind == "Ijk_Call" or exit_jumpkind.startswith("Ijk_Sys")
            ):
                l.debug("%s adding postcall exit.", self)

                ret_state = exit_state.copy()
                guard = (
                    ret_state.solver.true
                    if o.TRUE_RET_EMULATION_GUARD in self.state.options
                    else ret_state.solver.false
                )
                ret_target = ret_state.solver.BVV(successors.addr + irsb.size, ret_state.arch.bits)
                ret_state.registers.store(
                    ret_state.arch.ret_offset, ret_state.solver.Unconstrained("fake_ret_value", ret_state.arch.bits)
                )
                if ret_state.arch.call_pushes_ret and not exit_jumpkind.startswith("Ijk_Sys"):
                    ret_state.regs.sp = ret_state.regs.sp + ret_state.arch.bytes
                successors.add_successor(
                    ret_state,
                    ret_target,
                    guard,
                    "Ijk_FakeRet",
                    exit_stmt_idx=DEFAULT_STATEMENT,
                    exit_ins_addr=self.state.scratch.ins_addr,
                )

        successors.processed = True

    #
    # behavior instrumenting the VEXMixin
    #

    # statements

    def _handle_vex_stmt(self, stmt):
        self.state.scratch.stmt_idx = self.stmt_idx
        super()._handle_vex_stmt(stmt)

    def _handle_vex_stmt_IMark(self, stmt):
        ins_addr = stmt.addr + stmt.delta
        self.state.scratch.ins_addr = ins_addr

        # Raise an exception if we're suddenly in self-modifying code
        if (self.project is None or self.project.selfmodifying_code) and self.state.scratch.dirty_addrs:
            for subaddr in range(stmt.len):
                if subaddr + stmt.addr in self.state.scratch.dirty_addrs:
                    raise errors.SimReliftException(self.state)

        # HACK: mips64 may put an instruction which may fault in the delay slot of a branch likely instruction
        # if the branch is not taken, we must not execute that instruction if the condition fails (i.e. the current
        # guard is False)
        if self.state.scratch.guard.is_false():
            self.successors.add_successor(self.state, ins_addr, self.state.scratch.guard, "Ijk_Boring")
            raise VEXEarlyExit

        self.state.scratch.num_insns += 1
        self.successors.artifacts["insn_addrs"].append(ins_addr)

        self.state.history.recent_instruction_count += 1
        l.debug("IMark: %#x", stmt.addr)
        super()._handle_vex_stmt_IMark(stmt)

    def _perform_vex_stmt_Exit(self, guard, target, jumpkind):
        cont_state = None
        exit_state = None
        guard = guard != 0

        if o.COPY_STATES not in self.state.options:
            # very special logic to try to minimize copies
            # first, check if this branch is impossible
            if guard.is_false():
                cont_state = self.state
            elif o.LAZY_SOLVES not in self.state.options and not self.state.solver.satisfiable(
                extra_constraints=(guard,)
            ):
                cont_state = self.state

            # then, check if it's impossible to continue from this branch
            elif guard.is_true():
                exit_state = self.state
            elif o.LAZY_SOLVES not in self.state.options and not self.state.solver.satisfiable(
                extra_constraints=(claripy.Not(guard),)
            ):
                exit_state = self.state
            # one more step, when LAZY_SOLVES is enabled, ignore "bad" jumpkinds
            elif o.LAZY_SOLVES in self.state.options and jumpkind.startswith("Ijk_Sig"):
                cont_state = self.state
            else:
                if o.LAZY_SOLVES not in self.state.options or not jumpkind.startswith("Ijk_Sig"):
                    # when LAZY_SOLVES is enabled, we ignore "bad" jumpkinds
                    exit_state = self.state.copy()
                cont_state = self.state
        else:
            exit_state = self.state.copy()
            cont_state = self.state

        if exit_state is not None:
            self.successors.add_successor(
                exit_state,
                target,
                guard,
                jumpkind,
                exit_stmt_idx=self.stmt_idx,
                exit_ins_addr=self.state.scratch.ins_addr,
            )

        if cont_state is None:
            raise VEXEarlyExit

        # Do our bookkeeping on the continuing self.state
        cont_condition = ~guard
        cont_state.add_constraints(cont_condition)
        cont_state.scratch.guard = claripy.And(cont_state.scratch.guard, cont_condition)

    def _perform_vex_stmt_Dirty_call(self, func_name, ty, args, func=None):
        if func is None:
            try:
                func = getattr(dirty, func_name)
            except AttributeError as e:
                raise errors.UnsupportedDirtyError(f"Unsupported dirty helper {func_name}") from e
        retval, retval_constraints = func(self.state, *args)
        self.state.add_constraints(*retval_constraints)
        return retval

    # expressions

    def _instrument_vex_expr(self, result):
        if o.SIMPLIFY_EXPRS in self.state.options:
            result = self.state.solver.simplify(result)

        if self.state.solver.symbolic(result) and o.CONCRETIZE in self.state.options:
            concrete_value = self.state.solver.BVV(self.state.solver.eval(result), len(result))
            self.state.add_constraints(result == concrete_value)
            result = concrete_value

        return super()._instrument_vex_expr(result)

    def _perform_vex_expr_Load(self, addr, ty, endness, **kwargs):
        result = super()._perform_vex_expr_Load(addr, ty, endness, **kwargs)
        if o.UNINITIALIZED_ACCESS_AWARENESS in self.state.options:
            if getattr(addr._model_vsa, "uninitialized", False):
                raise errors.SimUninitializedAccessError("addr", addr)
        return result

    def _perform_vex_expr_CCall(self, func_name, ty, args, func=None):
        if o.DO_CCALLS not in self.state.options:
            return symbol(ty, "ccall_ret")
        return super()._perform_vex_expr_CCall(func_name, ty, args, func=None)

    def _analyze_vex_defaultexit(self, expr):
        self.state.scratch.stmt_idx = DEFAULT_STATEMENT
        return super()._analyze_vex_defaultexit(expr)

    def _perform_vex_defaultexit(self, expr, jumpkind):
        if expr is None:
            expr = self.state.regs.ip
        self.successors.add_successor(
            self.state,
            expr,
            self.state.scratch.guard,
            jumpkind,
            add_guard=False,  # if there is any guard, it has been added by the Exit statement
            # that we come across prior to the default exit. adding guard
            # again is unnecessary and will cause trouble in abstract solver
            # mode,
            exit_stmt_idx=DEFAULT_STATEMENT,
            exit_ins_addr=self.state.scratch.ins_addr,
        )
