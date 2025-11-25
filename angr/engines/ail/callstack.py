from __future__ import annotations
import claripy
from angr import ailment
from angr.state_plugins.callstack import CallStack
from angr.storage.memory_mixins.memory_mixin import MemoryMixin


class AILCallStack(CallStack):
    """
    An implementation of state.callstack for AIL symbolic execution

    Contains extra state for local vars and AIL calling conventions
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.passed_args: tuple[claripy.ast.Bits, ...] | None = None
        self.passed_rets: tuple[tuple[claripy.ast.Bits, ...], ...] = ()
        self.resume_at: int | None = None
        self.vars: dict[int, claripy.ast.Bits | MemoryMixin] = {}
        self.var_refs: dict[claripy.ast.BV, int] = {}
        self.var_refs_rev: dict[int, claripy.ast.BV] = {}
        self.return_addr: ailment.Address | None = None

    @CallStack.memo
    def copy(self, memo):
        o = super().copy(memo)
        o.passed_args = self.passed_args
        o.passed_rets = self.passed_rets
        o.resume_at = self.resume_at
        o.vars = {idx: v.copy(memo) if isinstance(v, MemoryMixin) else v for idx, v in self.vars.items()}
        o.var_refs = dict(self.var_refs)
        o.var_refs_rev = dict(self.var_refs_rev)
        o.return_addr = self.return_addr
        return o

    @CallStack.memo
    def copy_without_tail(self, memo):
        o = super().copy_without_tail(memo)
        o.passed_args = self.passed_args
        o.passed_rets = self.passed_rets
        o.resume_at = self.resume_at
        o.vars = {idx: v.copy(memo) if isinstance(v, MemoryMixin) else v for idx, v in self.vars.items()}
        o.var_refs = dict(self.var_refs)
        o.var_refs_rev = dict(self.var_refs_rev)
        o.return_addr = self.return_addr
        return o

    def set_state(self, state):
        super().set_state(state)
        for val in self.vars.values():
            if isinstance(val, MemoryMixin):
                val.set_state(state)

    def _manage(self):
        # this is managed by the engine
        pass
