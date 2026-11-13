from __future__ import annotations

import contextlib
import logging
from typing import TYPE_CHECKING

from angr import sim_options as o
from angr.calling_conventions import (
    SYSCALL_CC,
    SimCCAMD64LinuxSyscall,
    SimCCO32LinuxSyscall,
    SimCCSyscall,
    SimCCX86LinuxSyscall,
)
from angr.engines.vex.lifter import VEXLifter
from angr.errors import (
    AngrUnsupportedSyscallError,
    SimError,
    SimOperationError,
)
from angr.simos import SimLinux, SimOS
from angr.state_plugins.inspect import BP, BP_AFTER

from .constant_value_manager import ConstantValueManager
from .resolver import IndirectJumpResolver

if TYPE_CHECKING:
    from collections.abc import Callable

    from angr import Block
    from angr.engines import SimSuccessors
    from angr.sim_procedure import SimProcedure
    from angr.sim_state import SimState


_l = logging.getLogger(name=__name__)


class SyscallResolver(IndirectJumpResolver):
    """
    Resolve syscalls to SimProcedures.
    """

    def __init__(self, project):
        super().__init__(project, timeless=True)
        simos = project.simos
        self._os_resolves_syscalls = simos is not None and type(simos).syscall is not SimOS.syscall

    # the register cc.syscall_num() reads
    _SYSCALL_NUM_REGS: dict[type[SimCCSyscall], str] = {
        SimCCO32LinuxSyscall: "v0",
        SimCCX86LinuxSyscall: "eax",
        SimCCAMD64LinuxSyscall: "rax",
    }

    def rust_fast_path(
        self,
    ) -> tuple[tuple[int, int], dict[str, str] | None, int, Callable[[int, str | None], int]] | None:
        """
        What the Rust SyscallResolver needs to resolve a syscall whose number is a block-local constant without
        symbolic execution: the number register (offset, size), the ABI by jumpkind (None when syscall_abi() is None
        for every jumpkind), the VEX optimization level of the fastpath engine, and the stub address of a (number,
        ABI). None when this project needs symbolic execution for every syscall.
        """
        project = self.project
        simos = project.simos
        engine = project.factory.default_engine
        if type(simos) is not SimLinux or not isinstance(engine, VEXLifter) or engine.selfmodifying_code:
            return None
        arch = project.arch
        ccs = SYSCALL_CC.get(arch.name)
        if ccs is None:
            return None
        # SimUserland.syscall_cc() with state.os_name == simos.name
        cc = ccs[simos.name] if simos.name in ccs else ccs["default"]
        reg = self._SYSCALL_NUM_REGS.get(cc)
        if reg is None:
            return None
        # SimLinux.syscall_abi()
        abis = {"Ijk_Sys_syscall": "amd64", "Ijk_Sys_int128": "i386"} if arch.name == "AMD64" else None
        # VEXLifter.lift_vex() under a fastpath state
        opt_level = 1 if o.OPTIMIZE_IR in o.modes["fastpath"] else engine._default_opt_level
        return arch.registers[reg], abis, opt_level, self._syscall_stub_addr

    def _syscall_stub_addr(self, number: int, abi: str | None) -> int:
        stub = self.project.simos.syscall_from_number(number, allow_unsupported=True, abi=abi)
        assert stub is not None and stub.addr is not None
        return stub.addr

    def filter(self, cfg, addr, func_addr, block, jumpkind):
        return self._os_resolves_syscalls and jumpkind.startswith("Ijk_Sys")

    def resolve(  # pylint:disable=unused-argument
        self, cfg, addr: int, func_addr: int, block: Block, jumpkind: str, func_graph_complete: bool = True, **kwargs
    ):
        stub = self._resolve_syscall_to_stub(cfg, addr, func_addr, block)
        return (True, [stub.addr]) if stub else (False, [])

    def _resolve_syscall_to_stub(self, cfg, addr: int, func_addr: int, block: Block) -> SimProcedure | None:
        if not cfg.functions.contains_addr(func_addr):
            return None
        func = cfg.functions.get_by_addr(func_addr)

        cv_manager = ConstantValueManager(self.project, cfg.kb, func, addr, fcp=cfg._ijr_fcp, cfg=cfg)
        constant_value_reg_read_bp = BP(when=BP_AFTER, enabled=True, action=cv_manager.reg_read_callback)

        state = self.project.factory.blank_state(
            mode="fastpath",
            addr=block.addr,
            add_options={o.SYMBOL_FILL_UNCONSTRAINED_MEMORY, o.SYMBOL_FILL_UNCONSTRAINED_REGISTERS},
        )
        state.inspect.add_breakpoint("reg_read", constant_value_reg_read_bp)

        try:
            successors = self._simulate_block_with_resilience(state)
            if successors:
                state = self._get_syscall_state_from_successors(successors)
                if state:
                    with contextlib.suppress(AngrUnsupportedSyscallError):
                        return self.project.simos.syscall(state)
            return None
        finally:
            cv_manager.release()

    def _simulate_block_with_resilience(self, state: SimState) -> SimSuccessors | None:
        """
        Execute a basic block with "On Error Resume Next". Give up when there is no way moving forward.
        """

        stmt_idx = 0
        successors = None  # make PyCharm's linting happy

        while True:
            try:
                successors = self.project.factory.successors(state, skip_stmts=stmt_idx)
                break
            except SimOperationError:
                stmt_idx += 1
                continue
            except SimError:
                return None

        return successors

    @staticmethod
    def _get_syscall_state_from_successors(successors: SimSuccessors) -> SimState | None:
        for state in successors.flat_successors:
            if state.history.jumpkind and state.history.jumpkind.startswith("Ijk_Sys"):
                return state
        return None
