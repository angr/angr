# pylint:disable=too-many-boolean-expressions,unused-argument
from __future__ import annotations
import logging


from angr.ailment import Statement, Block
from angr.ailment.block_walker import AILBlockRewriter
from angr.ailment.statement import WeakAssignment, Call
from angr.ailment.expression import VirtualVariable, Const, Load, UnaryOp
from angr.sim_type import SimType, SimTypePointer, SimTypeChar

from .optimization_pass import OptimizationPass, OptimizationPassStage


_l = logging.getLogger(name=__name__)


class RewriteStdStringCallWalker(AILBlockRewriter):
    def __init__(self, str_defs: dict[int, bytes], kb, **kwargs):
        super().__init__(update_block=False, **kwargs)
        self._str_defs = str_defs
        self.kb = kb
        self.functions = kb.functions

    def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
        if isinstance(expr.target, Const) and self.functions.contains_addr(expr.target.value_int):
            func = self.functions.get_by_addr(expr.target.value_int)
            if "std::basic_string" in func.demangled_name:
                if (
                    func.short_name == "size"
                    and len(expr.args) == 1
                    and isinstance(expr.args[0], UnaryOp)
                    and expr.args[0].op == "Reference"
                    and isinstance(expr.args[0].operand, VirtualVariable)
                ):
                    varid = expr.args[0].operand.varid
                    if varid in self._str_defs:
                        s = self._str_defs[varid]
                        if s is not None:
                            return Const(None, None, len(s), expr.bits, **expr.tags)
                if (
                    func.short_name == "c_str"
                    and len(expr.args) == 1
                    and isinstance(expr.args[0], UnaryOp)
                    and expr.args[0].op == "Reference"
                    and isinstance(expr.args[0].operand, VirtualVariable)
                ):
                    varid = expr.args[0].operand.varid
                    if varid in self._str_defs:
                        s = self._str_defs[varid]
                        if s is not None:
                            idx = self.kb.custom_strings.allocate(s)
                            return Const(None, None, idx, expr.bits, custom_string=True, **expr.tags)

        return super()._handle_CallExpr(expr_idx, expr, stmt_idx, stmt, block)


class EagerStdStringEvalPass(OptimizationPass):
    """
    Eagerly evaluate std::string methods for constant std::string instances.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Eagerly evaluate std::string methods for constant std::string instances"
    DESCRIPTION = __doc__.strip()  # type: ignore

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def _check(self):
        callgraph = self.kb.functions.callgraph
        if self._func.addr not in callgraph:
            # this function is probably manually created - already run this optimization pass
            return True, {}
        callees = set(callgraph.successors(self._func.addr))
        string_construction_calls_found = False
        for callee_addr in callees:
            if not self.kb.functions.contains_addr(callee_addr):
                continue
            callee_func = self.kb.functions.get_by_addr(callee_addr)
            demangled_name = callee_func.demangled_name
            if "std::basic_string" in demangled_name:
                string_construction_calls_found = True
                break

        return string_construction_calls_found, {}

    def _analyze(self, cache=None):
        cfg = self.kb.cfgs.get_most_accurate()
        assert cfg is not None

        # iterate over all blocks and look for constant std::string assignments.
        # Pattern 1:
        # 00 | LABEL_4025fd:
        # 01 | vvar_21619{s-128|1b} =W Load(addr=0x4511f0<32>, size=222, endness=Iend_BE)
        #
        # Pattern 2:
        # 00 | LABEL_40265d:
        # 01 | vvar_21619{s-128|1b} =W Const(1, custom_string=True)

        entry_block = self._get_block(self.entry_node_addr[0], idx=self.entry_node_addr[1])
        assert entry_block is not None

        # find constant std::string assignments
        traversed = set()
        queue = [entry_block]
        str_defs: dict[int, bytes | None] = {}
        while queue:
            block = queue.pop(0)
            key = block.addr, block.idx
            if key in traversed:
                continue
            traversed.add(key)

            # find both patterns
            for stmt in block.statements:
                if isinstance(stmt, WeakAssignment):
                    is_std_string_assign, assigned_str = self._match_std_string_assignment(stmt, cfg)
                    if is_std_string_assign:
                        # found a std::string assignment
                        if assigned_str is None:
                            str_defs[stmt.dst.varid] = None
                        elif stmt.dst.varid not in str_defs:
                            str_defs[stmt.dst.varid] = assigned_str

            succs = list(self._graph.successors(block))
            for succ in succs:
                succ_key = succ.addr, succ.idx
                if succ_key in traversed:
                    continue
                queue.append(succ)

        # remove non-constant std::string definitions
        str_defs = {k: v for k, v in str_defs.items() if v is not None}
        if not str_defs:
            return

        # rewrite std::string-related calls
        rewriter = RewriteStdStringCallWalker(str_defs, self.kb)
        for block in list(self._graph):
            new_block = rewriter.walk(block)
            if new_block is not None:
                self._update_block(block, new_block)

    def _match_std_string_assignment(self, stmt: WeakAssignment, cfg) -> tuple[bool, bytes | None]:
        if (
            "type" in stmt.tags
            and "dst" in stmt.tags["type"]
            and "src" in stmt.tags["type"]
            and isinstance(stmt.dst, VirtualVariable)
        ):
            dst_ty = stmt.tags["type"]["dst"]
            if not self._is_std_string_type(dst_ty):
                return False, None
            if isinstance(stmt.src, Load) and isinstance(stmt.src.addr, Const):
                src_ty = stmt.tags["type"]["src"]
                if self._is_std_string_type_or_charptr(src_ty):
                    if isinstance(stmt.src.addr, Const) and stmt.src.addr.tags.get("custom_string", False):
                        try:
                            s = self.kb.custom_strings[stmt.src.addr.value_int]
                        except KeyError:
                            return True, None
                        return True, s
                    if (
                        isinstance(stmt.src.addr.value, int)
                        and stmt.src.addr.value in cfg.memory_data
                        and cfg.memory_data[stmt.src.addr.value_int].sort == "string"
                    ):
                        s = cfg.memory_data[stmt.src.addr.value_int].content
                        return True, s
            return True, None
        return False, None

    @staticmethod
    def _is_std_string_type(t: SimType) -> bool:
        type_str = t.c_repr().removeprefix("const ").removesuffix("&").strip(" ")
        return type_str == "class std::basic_string<char, struct std::char_traits<char>, class std::allocator<char>>"

    @staticmethod
    def _is_std_string_type_or_charptr(t: SimType) -> bool:
        if isinstance(t, SimTypePointer) and isinstance(t.pts_to, SimTypeChar):
            return True
        return EagerStdStringEvalPass._is_std_string_type(t)
