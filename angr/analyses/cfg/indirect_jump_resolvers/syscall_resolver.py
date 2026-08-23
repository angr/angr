from __future__ import annotations

import contextlib
import logging
from typing import TYPE_CHECKING

from angr import sim_options as o
from angr.errors import (
    AngrUnsupportedSyscallError,
    SimError,
    SimOperationError,
)
from angr.state_plugins.inspect import BP, BP_AFTER

from .constant_value_manager import ConstantValueManager
from .resolver import IndirectJumpResolver

if TYPE_CHECKING:
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
        # Resolving a syscall means asking the OS model to turn a syscall number into a SimProcedure. The base SimOS
        # cannot do that: SimOS.syscall() unconditionally returns None. So on a project with no OS model -- a firmware
        # blob or any other bare-metal image -- every resolution attempt is guaranteed to come back empty, and the
        # symbolic execution below is spent only to reach that conclusion. Decide it once, here.
        from angr.simos import SimOS  # pylint:disable=import-outside-toplevel

        simos = project.simos
        self._os_resolves_syscalls = simos is not None and type(simos).syscall is not SimOS.syscall

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

        cv_manager = ConstantValueManager(self.project, cfg.kb, func, addr)
        constant_value_reg_read_bp = BP(when=BP_AFTER, enabled=True, action=cv_manager.reg_read_callback)

        state = self.project.factory.blank_state(
            mode="fastpath",
            addr=block.addr,
            add_options={o.SYMBOL_FILL_UNCONSTRAINED_MEMORY, o.SYMBOL_FILL_UNCONSTRAINED_REGISTERS},
        )
        state.inspect.add_breakpoint("reg_read", constant_value_reg_read_bp)

        successors = self._simulate_block_with_resilience(state)
        if successors:
            state = self._get_syscall_state_from_successors(successors)
            if state:
                with contextlib.suppress(AngrUnsupportedSyscallError):
                    return self.project.simos.syscall(state)
        return None

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
