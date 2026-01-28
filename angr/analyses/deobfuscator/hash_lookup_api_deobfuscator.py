from __future__ import annotations
from collections.abc import Callable, Sequence
from collections.abc import Iterator

import claripy

import angr
from angr import sim_type
from angr.analyses import Analysis
from angr import ailment
from angr.ailment.block_walker import AILBlockViewer
from angr.errors import AngrCallableError
from angr.knowledge_plugins.functions.function import Function


class HashLookupAPIDeobfuscator(Analysis):
    """
    An analysis that finds functions accessing loader metadata which take concrete arguments and executes them to
    see if they resolve symbols.
    """

    def __init__(
        self, lifter: Callable[[Function], angr.analyses.decompiler.Clinic], func_addrs: Sequence[int] | None = None
    ):
        self.lifter = lifter
        self.results: dict[int, tuple[str, str]] = {}

        candidates_l0 = set()
        func_addrs = list(func_addrs or sorted(self.kb.functions))
        for idx, func_addr in enumerate(func_addrs):
            self._update_progress(0.0 + 20.0 * idx / len(func_addrs), "Finding l0 candidates")
            func = self.kb.functions.get_by_addr(func_addr)
            if self._is_metadata_accessor_candidate(func):
                candidates_l0.add(func_addr)

        # Consider predecessors to handle metadata loader wrappers
        # TODO: Constrain this more efficiently
        candidates_l1 = {p for c in candidates_l0 for p in self.kb.functions.callgraph.predecessors(c)}
        candidates_exec = []
        working = sorted(candidates_l0 | candidates_l1)
        for idx, func_addr in enumerate(working):
            self._update_progress(
                20.0 + 20.0 * idx / len(working), f"Finding execution candidates [{idx + 1}/{len(working)}]"
            )
            candidates_exec.extend(self._analyze1(self.kb.functions.get_by_addr(func_addr)))

        for idx, (a, b, c) in enumerate(candidates_exec):
            self._update_progress(
                40.0 + 60.0 * idx / len(candidates_exec), f"Executing candidates [{idx + 1}/{len(candidates_exec)}]"
            )
            self._analyze2(a, b, c)

        self._finish_progress()
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

    def _analyze1(self, function: Function) -> Iterator[tuple[int, Callable[..., claripy.ast.BV], list[int]]]:
        clinic = self.lifter(function)
        assert clinic.graph is not None

        callgraph = self.kb.functions.callgraph
        if function.addr not in callgraph:
            return
        walker1 = FindCallsTo(target=function.addr)
        seen = set()
        callers = sorted(set(callgraph.predecessors(function.addr)))
        for caller_addr in callers:
            if caller_addr in seen:
                continue
            seen.add(caller_addr)
            pred_func = self.kb.functions[caller_addr]
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
                yield call_expr.tags["ins_addr"], callme, conc_args  # type: ignore

    def _analyze2(self, ins_addr: int, callme: Callable[..., claripy.ast.BV], conc_args: list[int]):
        try:
            result_bv: claripy.ast.BV = callme(*conc_args)  # type: ignore
        except AngrCallableError:
            return
        if result_bv.concrete and (result_sym := self.project.loader.find_symbol(result_bv.concrete_value)) is not None:
            self.results[ins_addr] = (result_sym.owner.provides or "", result_sym.name)


class FindCallsTo(AILBlockViewer):
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
