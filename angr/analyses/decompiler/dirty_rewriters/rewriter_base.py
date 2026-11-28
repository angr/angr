from __future__ import annotations

from typing import TYPE_CHECKING

from angr import sim_type
from angr.ailment.expression import Call, DirtyExpression, Expression
from angr.ailment.statement import DirtyStatement, SideEffectStatement, Statement
from angr.analyses.decompiler.variable_map import variable_map_of

if TYPE_CHECKING:
    from angr.ailment.manager import Manager

# IRStmt_MBE(Imbe_Fence), the architecture-independent statement libVEX lifts memory barriers to
MEMORY_FENCE = "MBusEvent-Imbe_Fence"


class DirtyRewriterBase:
    """
    The base class for DirtyStatement and DirtyExpression rewriters. On its own it rewrites only the memory fence, into
    a call to MEMORY_FENCE_INTRINSIC, and AILSimplifier uses it that way on architectures without a rewriter of their
    own. Subclasses add the dirty helpers of one architecture.
    """

    __slots__ = (
        "arch",
        "manager",
        "result",
    )

    # the fence does not record which barrier the instruction was, so render it as GCC's full barrier
    MEMORY_FENCE_INTRINSIC = "__sync_synchronize"

    def __init__(self, dirty: DirtyExpression | DirtyStatement, arch, manager: Manager):
        self.arch = arch
        self.manager = manager
        self.result: Expression | Statement | None = (
            self._rewrite_expr(dirty) if isinstance(dirty, DirtyExpression) else self._rewrite_stmt(dirty)
        )

    def _rewrite_stmt(self, dirty: DirtyStatement) -> Statement | None:
        dirty_expr = dirty.dirty
        assert isinstance(dirty_expr, DirtyExpression)
        if dirty_expr.callee != MEMORY_FENCE:
            return None
        call_expr = self._make_call(dirty_expr, self.MEMORY_FENCE_INTRINSIC, (), (), "void")
        return SideEffectStatement(self.manager.next_atom(), call_expr, **dirty.tags)

    def _rewrite_expr(self, dirty: DirtyExpression) -> Expression | None:  # pylint:disable=unused-argument,no-self-use
        return None

    def _make_call(
        self,
        dirty: DirtyExpression,
        target: str,
        args: tuple[Expression, ...],
        param_kinds: tuple[str, ...],
        ret_kind: str,
        bits: int | None = None,
    ) -> Call:
        if bits is None:
            bits = dirty.bits
        # intrinsic prototypes are exact
        tags = dict(dirty.tags)
        tags["is_prototype_guessed"] = False
        call = Call(
            self.manager.next_atom(),
            target,
            args=args,
            bits=bits or None,
            **tags,
        )
        prototype = sim_type.SimTypeFunction(
            [self._param_type(kind, arg) for kind, arg in zip(param_kinds, args)],
            self._return_type(ret_kind, bits),
        ).with_arch(self.arch)
        assert isinstance(prototype, sim_type.SimTypeFunction)
        variable_map_of(self.manager).set_prototype(call, prototype)
        return call

    @staticmethod
    def _param_type(kind: str, arg: Expression) -> sim_type.SimType:
        match kind:
            case "ptr":
                return sim_type.SimTypePointer(sim_type.SimTypeBottom(label="void"))
            case "u16":
                return sim_type.SimTypeNum(16, signed=False)
            case _:
                return sim_type.SimTypeNum(arg.bits, signed=False)

    @staticmethod
    def _return_type(kind: str, bits: int) -> sim_type.SimType:
        match kind:
            case "void":
                return sim_type.SimTypeBottom(label="void")
            case "u64":
                return sim_type.SimTypeNum(64, signed=False)
            case _:
                return sim_type.SimTypeNum(bits, signed=False) if bits else sim_type.SimTypeBottom(label="void")
