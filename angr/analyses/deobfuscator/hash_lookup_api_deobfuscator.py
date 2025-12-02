from __future__ import annotations
from collections.abc import Callable, Sequence

import claripy

import angr
from angr import sim_type
from angr.analyses import Analysis
from angr import ailment
from angr.ailment.block_walker import AILBlockWalkerBase
from angr.errors import AngrCallableError
from angr.knowledge_plugins.functions.function import Function


class HashLookupAPIDeobfuscator(Analysis):
    """
    An analysis that finds functions accessing loader metadata which take concrete arguments and executes them to
    see if they resolve symbols.
    """

    def __init__(
        self, lifter: Callable[[Function], angr.analyses.decompiler.Clinic], functions: Sequence[Function] | None = None
    ):
        self.lifter = lifter
        self.results: dict[int, tuple[str, str]] = {}

        candidates_l0 = {
            func.addr for func in functions or self.kb.functions.values() if self._is_metadata_accessor_candidate(func)
        }

        # Consider predecessors to handle metadata loader wrappers
        # TODO: Constrain this more efficiently
        candidates_l1 = {p for c in candidates_l0 for p in self.kb.functions.callgraph.predecessors(c)}

        for func_addr in sorted(candidates_l0 | candidates_l1):
            self._analyze(self.kb.functions[func_addr])

        self.kb.obfuscations.type3_deobfuscated_apis.update(self.results)

    def _is_metadata_accessor_candidate(self, function: Function) -> bool:
        if function.is_simprocedure or function.is_plt or function.is_alignment:
            return False
        clinic = self.lifter(function)
        assert clinic.graph is not None
        walker0 = FindCallsTo(target="NtGetCurrentPeb")
        for node in clinic.graph:
            walker0.walk(node)
        return bool(walker0.found_calls)

    def _analyze(self, function: Function):
        clinic = self.lifter(function)
        assert clinic.graph is not None

        walker1 = FindCallsTo(target=function.addr)
        seen = set()
        cfg = self.kb.cfgs.get_most_accurate()
        assert cfg is not None
        succ = cfg.get_any_node(function.addr)
        assert succ is not None
        for pred in succ.predecessors:
            if pred.function_address in seen:
                continue
            seen.add(pred.function_address)
            pred_func = self.kb.functions[pred.function_address]
            pred_clinic = self.lifter(pred_func)
            assert pred_clinic.graph is not None
            for each_pred_node in pred_clinic.graph:
                walker1.walk(each_pred_node)

        callme = self.project.factory.callable(
            function.addr,
            prototype=function.prototype,
            cc=function.calling_convention,
            add_options=angr.options.unicorn
            | {angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.STRICT_PAGE_ACCESS},
        )
        for _, _, call_expr in walker1.found_calls:
            conc_args = []
            for arg in call_expr.args or []:
                if not isinstance(arg, ailment.expression.Const):
                    break
                conc_args.append(arg.value)
            else:
                try:
                    result_bv: claripy.ast.BV = callme(*conc_args)  # type: ignore
                except AngrCallableError:
                    continue
                if (
                    result_bv.concrete
                    and (result_sym := self.project.loader.find_symbol(result_bv.concrete_value)) is not None
                ):
                    self.results[call_expr.ins_addr] = (result_sym.owner.provides or "", result_sym.name)


class FindCallsTo(AILBlockWalkerBase):
    """
    Walker which stores calls with a given target.
    """

    def __init__(self, *args, target: str | int, **kwargs):
        super().__init__(*args, **kwargs)
        self.found_calls: list[tuple[ailment.Block, int, ailment.statement.Call]] = []
        self.target = target

    def _handle_Call(self, stmt_idx: int, stmt: ailment.statement.Call, block: ailment.Block | None):
        # if I try to make this more readable, pre-commit changes it back to this nonsense...
        # pylint: disable=too-many-boolean-expressions
        if (
            (isinstance(self.target, str) and stmt.target == self.target)
            or (
                isinstance(self.target, int)
                and isinstance(stmt.target, ailment.expression.Const)
                and stmt.target.value == self.target
            )
            or (
                isinstance(self.target, sim_type.SimType)
                and stmt.prototype is not None
                and stmt.prototype.returnty == self.target
            )
        ):
            assert block is not None
            self.found_calls.append((block, stmt_idx, stmt))

        return super()._handle_Call(stmt_idx, stmt, block)

    def _handle_CallExpr(
        self,
        expr_idx: int,
        expr: ailment.statement.Call,
        stmt_idx: int,
        stmt: ailment.Statement | None,
        block: ailment.Block | None,
    ):
        if (isinstance(self.target, str) and expr.target == self.target) or (
            isinstance(self.target, int)
            and isinstance(expr.target, ailment.expression.Const)
            and expr.target.value == self.target
        ):
            assert block is not None
            self.found_calls.append((block, stmt_idx, expr))
        return super()._handle_CallExpr(expr_idx, expr, stmt_idx, stmt, block)
