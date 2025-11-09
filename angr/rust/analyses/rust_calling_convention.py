import logging
import traceback
from typing import Tuple, Optional, List
from collections import OrderedDict

from networkx import DiGraph

from angr.analyses.decompiler.optimization_passes import CallStatementRewriter
from angr.calling_conventions import SimCC
from angr.ailment import BinaryOp, Const, AILBlockWalker, Block
from angr.ailment.expression import BasePointerOffset, VirtualVariable, Tmp, Load, Phi, VirtualVariableCategory
from angr.ailment.statement import Store, Call, Statement, ConditionalJump, Return, Assignment, Jump, Label
from angr.rust.mixins import SRDAMixin, DFAMixin, CFAMixin
from angr.rust.optimization_passes.cleanup_code_remover import CleanupCodeRemover
from angr.rust.optimization_passes.unreachable_branch_fixer import UnreachableBranchFixer
from angr.rust.optimization_passes.utils import CallReplacer, expand_argloc, extract_str_from_addr
from angr.rust.sim_type import (
    RustSimEnum,
    RustSimTypeOption,
    RustSimTypeResult,
    RustSimType,
    RustSimTypeUnit,
    EnumVariant,
)
from angr.rust.knowledge_plugins.rust_calling_conventions import RustCallingConventionModel
from angr.rust.sim_type import (
    RustSimTypeInt,
    RustSimTypeReference,
    RustSimStruct,
    RustSimTypeFunction,
    RustSimTypeStrRef,
)
from angr.rust.typehoon.translator import RustTypeTranslator
from angr.rust.utils.ail import unwrap_stack_vvar_reference, has_call, extract_vvar_and_offset
from angr.rust.utils.library import normalize, demangle
from angr.utils.graph import GraphUtils
from angr.analyses import Analysis, AnalysesHub
from angr.knowledge_plugins import Function

l = logging.getLogger(name=__name__)


CONST_STR_ERRORS = {
    "stream did not contain valid UTF-8": "INVALID_UTF8",
    "failed to fill whole buffer": "READ_EXACT_EOF",
    "The number of hardware threads is not known for the target platform": "UNKNOWN_THREAD_COUNT",
    "operation not supported on this platform": "UNSUPPORTED_PLATFORM",
    "failed to write whole buffer": "WRITE_ALL_EOF",
    "cannot set a 0 duration timeout": "ZERO_TIMEOUT",
}


class Pathfinder:

    def __init__(self, graph, srda_mixin: SRDAMixin = None):
        self.graph = graph
        self._srda_mixin = srda_mixin

    @staticmethod
    def _is_safe_block(block):
        return all(
            isinstance(stmt, (Return, Jump, ConditionalJump, Label, Assignment)) for stmt in block.statements
        ) and not has_call(block)

    @staticmethod
    def _remove_phi(path):
        new_path = [block.copy() for block in path]

        class PhiWalker(AILBlockWalker):

            def __init__(self):
                super().__init__()
                self.pred_block = None

            def _handle_Phi(
                self, expr_id: int, expr: Phi, stmt_idx: int, stmt: Statement, block: Block | None
            ) -> Phi | None:
                if self.pred_block:
                    pred = (self.pred_block.addr, self.pred_block.idx)
                    for src, vvar in expr.src_and_vvars:
                        if src == pred:
                            return vvar
                return None

        walker = PhiWalker()
        for block in new_path:
            walker.walk(block)
            walker.pred_block = block
        return tuple(new_path)

    def _is_ret2arg0_block(self, block):
        for stmt in reversed(block.statements):
            if isinstance(stmt, Store):
                vvar, _ = extract_vvar_and_offset(stmt.addr)
                if isinstance(vvar, VirtualVariable) and self._srda_mixin:
                    vvar = self._srda_mixin.get_terminal_vvar(vvar)
                if isinstance(vvar, VirtualVariable) and vvar.was_parameter and vvar.varid == 0:
                    return True
        return False

    def _find_ret2arg0_path(self, head_block, visited):
        visited.add(head_block)
        paths = [[head_block]]
        changed = True
        while changed:
            changed = False
            new_paths = []
            for path in paths:
                last_block = path[-1]
                path_changed = False
                for succ in self.graph.successors(last_block):
                    if succ not in path and (self._is_ret2arg0_block(succ) or self._is_safe_block(succ)):
                        new_path = list(path) + [succ]
                        new_paths.append(new_path)
                        changed = True
                        path_changed = True
                    visited.add(succ)
                if not path_changed:
                    new_paths.append(path)
            paths = new_paths
        paths = set(tuple(path) for path in paths if isinstance(path[-1].statements[-1], Return))
        return paths

    def find_ret2arg0_paths(self, remove_phi=False):
        visited = set()
        paths = set()
        for block in GraphUtils.quasi_topological_sort_nodes(self.graph):
            if self._is_ret2arg0_block(block) and block not in visited:
                paths = paths.union(self._find_ret2arg0_path(block, visited))
            else:
                visited.add(block)
        paths = set(self._remove_phi(path) if remove_phi else path for path in paths)
        return paths

    @staticmethod
    def path_to_graph(path):
        graph = DiGraph()
        graph.add_node(path[0])
        for i in range(len(path) - 1):
            u = path[i]
            v = path[i + 1]
            graph.add_edge(u, v)
        return graph

    def find_backward_path(self, block, max_length=None):
        visited = {block}
        path = [block]
        while len(preds := list(self.graph.predecessors(block))) == 1 and (
            max_length is None or len(path) < max_length
        ):
            block = preds[0]
            if block in visited:
                break
            visited.add(block)
            path.insert(0, block)
        return path

    def find_forward_path(self, block, max_length=None):
        visited = {block}
        path = [block]
        while len(succs := list(self.graph.successors(block))) == 1 and (max_length is None or len(path) < max_length):
            block = succs[0]
            if block in visited:
                break
            visited.add(block)
            path.append(block)
        return path


class FunctionBodyFactCollector(AILBlockWalker):
    def __init__(self, context: "RustCallingConventionAnalysis"):
        super().__init__()
        self.context = context
        self.project = context.project
        self.model = context.model
        self.graph = context.graph
        self.has_write_to_arg0 = False
        self.const_ret_values = set()

        self._path = None

    def collect(self):
        """
        Calculate paths that write return values to the first argument
        Collect facts from every path and every callsite in this function
        """
        paths = Pathfinder(self.graph, self.context).find_ret2arg0_paths(remove_phi=True)
        callsites = set()
        for block in self.context.graph.nodes:
            if has_call(block):
                callsites.add((block,))
        retsites = set()
        for block in self.context.graph.nodes:
            if block.statements and isinstance(block.statements[-1], Return):
                retsites.add((block,))

        for path in paths | callsites | retsites:
            self._path = path
            for block in path:
                self.walk(block)

        self.has_write_to_arg0 |= len(paths) != 0

        # Collect constant return values
        for block in self.context.graph.nodes:
            if isinstance(block.statements[-1], Return):
                stmt = block.statements[-1]
                ret_expr = stmt.ret_exprs[0] if stmt.ret_exprs else None
                if isinstance(ret_expr, VirtualVariable):
                    self.const_ret_values |= set(
                        value.value
                        for value in self.context.get_terminal_vvar_values(ret_expr)
                        if isinstance(value, Const)
                    )
                elif isinstance(ret_expr, Const):
                    self.const_ret_values.add(ret_expr.value)

    def _srda_on_path(self, path: Tuple[Block]):
        return SRDAMixin(self.context.func, Pathfinder.path_to_graph(path), self.project)

    def add_memory_write(self, arg_idx, block_or_path, offset, expr):
        if block_or_path not in self.model.memory_writes[arg_idx]:
            self.model.memory_writes[arg_idx][block_or_path] = {}
        if isinstance(block_or_path, tuple) and isinstance(expr, VirtualVariable):
            srda = self._srda_on_path(block_or_path)
            expr = srda.get_terminal_vvar_value(expr) or expr
        self.model.memory_writes[arg_idx][block_or_path][offset] = (expr, self.context.func.addr)

    def add_memory_read(self, arg_idx, block, offset, expr):
        if block not in self.model.memory_reads[arg_idx]:
            self.model.memory_reads[arg_idx][block] = {}
        self.model.memory_reads[arg_idx][block][offset] = (expr, self.context.func.addr)

    def _handle_Store(self, stmt_idx: int, stmt: Store, block: Block | None):
        addr = stmt.addr
        offset = 0
        if (
            isinstance(stmt.addr, BinaryOp)
            and addr.op == "Add"
            and isinstance(addr.operands[0], VirtualVariable)
            and isinstance(addr.operands[1], Const)
        ):
            offset = addr.operands[1].value
            addr = addr.operands[0]
        if isinstance(addr, VirtualVariable):
            addr = self.context.get_terminal_vvar(addr)
        if isinstance(addr, VirtualVariable) and addr.was_parameter:
            self.add_memory_write(addr.varid, self._path, offset, stmt.data)

    def _should_handle_call(self, call: Call, stmt: Statement):
        return (
            call.args
            and isinstance(call.args[0], VirtualVariable)
            and ((arg0 := self.context.get_terminal_vvar(call.args[0])) and arg0.was_parameter and arg0.varid == 0)
        ) or (isinstance(stmt, Return) and stmt.ret_exprs and stmt.ret_exprs[0] is call)

    def _extract_arg0_offset(self, call: Call) -> Optional[int]:
        if (
            call.args
            and isinstance(call.args[0], VirtualVariable)
            and ((arg0 := self.context.get_terminal_vvar(call.args[0])) and arg0.was_parameter and arg0.varid == 0)
        ):
            return 0
        if call.args:
            arg0 = call.args[0]
            if isinstance(arg0, BinaryOp) and arg0.op == "Add":
                vvar, offset = extract_vvar_and_offset(arg0)
                if (
                    isinstance(vvar, VirtualVariable)
                    and self.context.get_terminal_vvar(vvar).was_parameter
                    and vvar.varid == 0
                ):
                    return offset
        return None

    def _handle_Call_Stmt_or_Expr(self, call: Call, stmt: Statement, block: Block):
        if (
            isinstance(call.target, Const)
            and call.target.value in self.project.kb.functions
            and self._should_handle_call(call, stmt)
        ):
            func = self.project.kb.functions[call.target.value]
            if func.name == "memcpy" and len(call.args) == 3 and isinstance(call.args[2], Const):
                tmp = Tmp(None, None, 0, call.args[2].value * self.context.project.arch.byte_width)
                self.has_write_to_arg0 = True
                self.add_memory_write(0, self._path, 0, tmp)
            elif func.normalized and func.size and self.context.depth < self.context.max_depth:
                result = self.project.analyses.RustCallingConvention(
                    func,
                    callsite_path=Pathfinder(self.graph).find_backward_path(block),
                    depth=self.context.depth + 1,
                    max_depth=self.context.max_depth,
                )
                self.model.memory_writes[0] |= result.model.memory_writes[0]
                self.model.const_ret_values |= result.model.const_ret_values
                if result.model.has_write_to_arg0:
                    self.has_write_to_arg0 = True

    def _handle_Return(self, stmt_idx: int, stmt: Return, block: Block | None):
        if stmt.ret_exprs:
            ret_expr = stmt.ret_exprs[0]
            ret_exprs = [ret_expr]
            if isinstance(ret_expr, VirtualVariable):
                ret_exprs = self.context.get_terminal_vvar_values(ret_expr)
            for call in ret_exprs:
                if (
                    isinstance(call, Call)
                    and isinstance(call.target, Const)
                    and call.target.value in self.project.kb.functions
                ):
                    func = self.project.kb.functions[call.target.value]
                    if func.normalized and func.size and self.context.depth < self.context.max_depth:
                        result = self.project.analyses.RustCallingConvention(
                            func,
                            callsite_path=Pathfinder(self.graph).find_backward_path(block),
                            depth=self.context.depth + 1,
                            max_depth=self.context.max_depth,
                        )
                        self.model.const_ret_values |= result.model.const_ret_values
        super()._handle_Return(stmt_idx, stmt, block)

    def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None):
        self._handle_Call_Stmt_or_Expr(stmt, stmt, block)
        super()._handle_Call(stmt_idx, stmt, block)

    def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
        self._handle_Call_Stmt_or_Expr(expr, stmt, block)
        super()._handle_CallExpr(expr_idx, expr, stmt_idx, stmt, block)


class RustCallingConventionAnalysis(Analysis, CFAMixin, SRDAMixin, DFAMixin):
    """
    This analysis infer function prototype including struct return type and struct argument types
    Function prototype is inferred based on collected facts from the callee function body and the caller function body

    Facts collected from callee:
    1. Memory writes to the first argument
    2. Memory reads to all arguments

    Facts collected from caller:
    1. Initialization of function arguments at callsite (memory writes at callsite)
    2. Uses of return value after callee is called
    """

    def __init__(
        self,
        func,
        graph=None,
        callsite_path=None,
        post_callsite_path=None,
        is_call_expr=None,
        depth=0,
        max_depth=8,
        rewrite=False,
    ):
        self.func: Function = func
        self.graph = graph
        self.callsite_path = callsite_path
        self.post_callsite_path = post_callsite_path
        self.is_call_expr = is_call_expr
        self.depth = depth
        self.max_depth = max_depth
        self.rewrite = rewrite

        self._fact_collector = None

        if self.func.addr in self.kb.rust_calling_conventions.cache:
            self.model = self.kb.rust_calling_conventions.cache[self.func.addr]
        else:
            self.model = RustCallingConventionModel()

            if self.depth > self.max_depth:
                return

            if self.graph is None and self.func.normalized and self.func.size:
                try:
                    cfg = self.kb.cfgs.get_most_accurate()
                    l.info(f"Clinic for {self.func.demangled_name}")
                    self.graph = self.project.analyses.Clinic(
                        self.func,
                        cfg=cfg,
                        optimization_passes=[UnreachableBranchFixer, CleanupCodeRemover, CallStatementRewriter],
                    ).graph
                    l.info(f"Clinic end for {self.func.demangled_name}")
                except Exception as e:
                    l.error(f"Failed to recover AIL graph for {normalize(self.func.name)}")
                    l.error("".join(traceback.format_exception(e)))

            if self.graph:
                CFAMixin.__init__(self, self.graph, self.project)
                SRDAMixin.__init__(self, self.func, self.graph, self.project)
                DFAMixin.__init__(self, self.graph)
                self._fact_collector = FunctionBodyFactCollector(self)

                try:
                    self._analyze()
                except Exception as e:
                    l.error(f"Rust calling convention analysis failed for {normalize(self.func.name)}")
                    l.error("".join(traceback.format_exception(e)))

    def _remove_discriminant_from_struct(self, struct_type: RustSimStruct):
        field_types = list(struct_type.fields.values())[1:]
        fields = OrderedDict()
        offset = 0
        for field_type in field_types:
            fields[f"field_{offset}"] = field_type
            offset += field_type.size // self.project.arch.byte_width
        return RustSimStruct(
            fields,
            name=f"struct{sum(field.size if field.size else 0 for field in fields.values()) // 8}",
            pack=True,
        ).with_arch(self.project.arch)

    def _infer_potential_enum_type(
        self, candidates_and_paths: List[Tuple[Tuple[RustSimStruct, Const | None], Tuple[Block]]]
    ) -> RustSimEnum | None:
        # Simplest case: if there is only one candidate, it's not an Enum type
        if len(candidates_and_paths) <= 1:
            return None

        # There are different struct types. It may be an enum!
        # Calculate discriminant for each path and deduplicate
        candidates_and_discriminants = []
        visited = set()
        for (candidate, discriminant), path in candidates_and_paths:
            key = (candidate.size, discriminant.value if discriminant else None)
            if key not in visited:
                visited.add(key)
                candidates_and_discriminants.append((candidate, discriminant))
        candidates_and_discriminants = tuple(sorted(candidates_and_discriminants, key=lambda item: item[0].size))

        # If there are two different struct types, it could be Option<T> or Result<T, E>
        # If the size of one of the struct types is equal to discriminant size, it is an Option<T>
        # Otherwise it's a Result<T, E>
        if len(candidates_and_discriminants) == 2:
            discriminants = list(discriminant for _, discriminant in candidates_and_discriminants)
            discriminant_sizes = set(discriminant.bits for discriminant in discriminants if discriminant is not None)
            # There should be only one discriminant size
            if len(discriminant_sizes) == 1:
                discriminant_size = next(iter(discriminant_sizes))
                candidate_sizes = sorted(set(candidate.size for candidate, _ in candidates_and_discriminants))
                overlapping_discriminant = None in discriminants
                if candidate_sizes[0] == discriminant_size:
                    # If there is a candidate of discriminant size, it should be an Option<T> or Result<(), E>
                    # Get the discriminant for None and Some variants
                    # Notice that if overlapping_discriminant is True, some_discriminant maybe None
                    (_, none_discriminant), (some_type, some_discriminant) = candidates_and_discriminants
                    if none_discriminant is not None:
                        none_discriminant = none_discriminant.value
                    elif some_discriminant is not None:
                        none_discriminant = some_discriminant.value - 1
                    if some_discriminant:
                        some_discriminant = some_discriminant.value
                    if not overlapping_discriminant:
                        some_type = self._remove_discriminant_from_struct(some_type)
                    none_discriminant_size = discriminant_size // 8
                    some_discriminant_size = discriminant_size // 8 if not overlapping_discriminant else 0
                    if some_type.size // 8 == self.project.arch.bytes * 2:
                        # Heuristics: Maybe it's a Result<(), E> if some_type's size is the same with &str's size
                        some_type.name = "Error"
                        return RustSimTypeResult(
                            RustSimTypeUnit(),
                            none_discriminant,
                            none_discriminant_size,
                            some_type,
                            some_discriminant,
                            some_discriminant_size,
                        )
                    return RustSimTypeOption(
                        none_discriminant,
                        none_discriminant_size,
                        some_type,
                        some_discriminant,
                        some_discriminant_size,
                    )
                elif None not in discriminants:
                    # If all discriminants are found and no candidate is of discriminant size, it should be a
                    # Result<T, E> type
                    struct_type_and_discriminant = tuple(
                        sorted(
                            candidates_and_discriminants,
                            key=lambda item: item[1].value,
                        )
                    )
                    (ok_type, ok_discriminant), (err_type, err_discriminant) = struct_type_and_discriminant
                    ok_type = self._remove_discriminant_from_struct(ok_type)
                    err_type = self._remove_discriminant_from_struct(err_type)
                    discriminant_size = discriminant_size // 8
                    return RustSimTypeResult(
                        ok_type,
                        ok_discriminant.value,
                        discriminant_size,
                        err_type,
                        err_discriminant.value,
                        discriminant_size,
                    )
                elif candidates_and_discriminants[1][1] is None:
                    # Heuristics:
                    # If one discriminant is missing and no candidate is of discriminant size, it should still be a
                    # Result<T, E> type
                    # Assume the size of T is greater than the size of E
                    # Intuitively, T's discriminant should be omitted to optimize memory space
                    (err_type, err_discriminant), (ok_type, _) = candidates_and_discriminants
                    discriminant_size = discriminant_size // 8
                    return RustSimTypeResult(
                        ok_type,
                        None,
                        0,
                        err_type,
                        err_discriminant.value,
                        discriminant_size,
                    )
        if len(candidates_and_discriminants) >= 2:
            structs_by_size = {}
            for candidate, discriminant in candidates_and_discriminants:
                if candidate.size not in structs_by_size:
                    structs_by_size[candidate.size] = candidate
            if len(structs_by_size) >= 2:
                # More than two variants, it should be an Enum type
                variants = []
                for candidate, discriminant in candidates_and_discriminants:
                    variant_name = f"variant{candidate.size // self.project.arch.bytes}"
                    variant_type = candidate
                    variants.append(
                        EnumVariant(
                            name=variant_name, fields=[(variant_type, None)], discriminant=None, discriminant_size=0
                        )
                    )
                return RustSimEnum(f"enum{max(structs_by_size) // self.project.arch.bytes}", variants).with_arch(
                    self.project.arch
                )
        return None

    def _infer_return_type(self) -> Tuple[RustSimType | None, bool]:
        # The first argument is not used as return buffer
        if (
            len(self.model.callsite_memory_writes[0]) != 0
            or not self._fact_collector.has_write_to_arg0
            or self.is_call_expr is True
        ):
            # Heuristics: check if the return type could be Result<(), &str> (std::io::Result<()>)
            if len(self.model.const_ret_values) == 2 and 0 in self.model.const_ret_values:
                _, another_const = sorted(self.model.const_ret_values)
                error_msg = extract_str_from_addr(self.project, another_const)
                if error_msg is not None:
                    ok_type = RustSimStruct(OrderedDict(), "()", True).with_arch(self.project.arch)
                    err_type = RustSimTypeReference(RustSimTypeStrRef()).with_arch(self.project.arch)
                    result_ty = RustSimTypeResult(ok_type, 0, self.project.arch.bytes, err_type, None, 0).with_arch(
                        self.project.arch
                    )
                    return result_ty, False
            return self.func.prototype.returnty, False

        memory_writes = self.model.memory_writes[0]
        candidates_and_paths = []

        for path in memory_writes:
            fields = {}
            path_memory_writes = memory_writes[path]
            discriminant = None
            for offset in sorted(path_memory_writes.keys()):
                expr, func_addr = path_memory_writes[offset]
                arg_ty = RustSimTypeInt(expr.bits, signed=False)
                fields[f"field_{offset}"] = arg_ty
                if offset == 0 and isinstance(expr, Const):
                    discriminant = expr
            struct_ty = RustSimStruct(
                fields,
                name=f"struct{sum(field.size if field.size else 0 for field in fields.values()) // 8}",
                pack=True,
            ).with_arch(self.project.arch)
            candidates_and_paths.append(((struct_ty, discriminant), path))

        # Return inferred enum type if we found one, otherwise return the struct type with the largest size
        returnty = self._infer_potential_enum_type(candidates_and_paths)
        if not returnty and candidates_and_paths:
            returnty = next(iter(sorted(candidates_and_paths, key=lambda item: item[0][0].size, reverse=True)))[0][0]
        return returnty, True

    def _infer_arg_type(self, arg_idx):
        memory_writes = self.model.memory_writes[arg_idx] | self.model.callsite_memory_writes[arg_idx]
        candidates = []

        for block_or_path in memory_writes:
            fields = OrderedDict()
            field_exprs = {offset: expr for offset, (expr, _) in memory_writes[block_or_path].items()}
            struct_ty = self.project.kb.known_structs.match_with_known_structs(field_exprs)
            if not struct_ty:
                for offset in sorted(field_exprs):
                    expr = field_exprs[offset]
                    arg_ty = RustSimTypeInt(expr.bits, signed=False)
                    fields[f"field_{offset}"] = arg_ty
                struct_ty = RustSimStruct(
                    fields,
                    name=f"struct{sum(field.size if field.size else 0 for field in fields.values()) // 8}",
                    pack=True,
                ).with_arch(self.project.arch)
            if struct_ty.size == 32 * 8:
                import ipdb

                ipdb.set_trace()
            candidates.append(struct_ty)

        final_ty = sorted(candidates, key=lambda candidate: candidate.size, reverse=True)[0] if candidates else None

        # Filter out register-size structs
        if final_ty and final_ty.size <= self.project.arch.bits:
            return None

        if final_ty:
            final_ty = RustSimTypeReference(final_ty).with_arch(self.project.arch)

        return final_ty

    def _arg_idx_to_arg_type(self, arg_idx, prototype: RustSimTypeFunction, cc: SimCC):
        if prototype and cc:
            arg_types = prototype.args
            arg_locs = cc.arg_locs(prototype)
            for arg_ty, arg_loc in zip(arg_types, arg_locs):
                if arg_idx == 0:
                    return arg_ty
                locs = expand_argloc(arg_loc)
                arg_idx -= len(locs)
        return None

    def _infer_combo_arg_types(self, arg_types):
        combo_arg_types = {}

        def callback(call: Call, block, stmt, is_expr):
            i = 0
            while i + 1 < len(call.args):
                arg = call.args[i]
                next_arg = call.args[i + 1]
                if isinstance(arg, VirtualVariable) and isinstance(next_arg, VirtualVariable):
                    arg = self.get_terminal_vvar(arg) or arg
                    next_arg = self.get_terminal_vvar(next_arg) or arg
                    if (
                        arg.was_parameter
                        and arg.parameter_category == VirtualVariableCategory.REGISTER
                        and next_arg.was_parameter
                        and next_arg.parameter_category == VirtualVariableCategory.REGISTER
                        and next_arg.varid - arg.varid == 1
                    ):
                        arg_ty = self._arg_idx_to_arg_type(i, call.prototype, call.calling_convention)
                        if isinstance(arg_ty, RustSimType) and arg_ty.size == self.project.arch.bits * 2:
                            combo_arg_types[arg.varid] = arg_ty
                            i += 1
                i += 1
            return None

        replacer = CallReplacer(callback)
        for block in self._graph.nodes:
            replacer.walk(block)

        new_arg_types = []
        i = 0
        while i < len(arg_types):
            if i in combo_arg_types:
                new_arg_types.append(combo_arg_types[i])
                i += 2
            else:
                new_arg_types.append(arg_types[i])
                i += 1

        return new_arg_types

    def infer_prototype(self):
        returnty, is_arg0_ret_buf = self._infer_return_type()
        args = []
        for arg_idx, old_arg_type in enumerate(self.func.prototype.args):
            if is_arg0_ret_buf and arg_idx == 0:
                args.append(RustSimTypeReference(returnty).with_arch(self.project.arch))
                returnty = None
                continue
            arg_type = self._infer_arg_type(arg_idx)
            if not arg_type:
                arg_type = old_arg_type
            args.append(arg_type)
        args = self._infer_combo_arg_types(args)
        prototype = self.func.prototype
        if returnty:
            returnty = RustTypeTranslator(self.project, self.project.arch).ctype2rust(returnty)
        return RustSimTypeFunction(
            args=args,
            returnty=returnty,
            label=prototype.label,
            arg_names=prototype.arg_names,
            variadic=prototype.variadic,
            is_arg0_retbuf=is_arg0_ret_buf,
        )

    def collect_function_body_facts(self):
        self._fact_collector.collect()

    def add_callsite_memory_write(self, arg_idx, block, offset, expr):
        if block not in self.model.callsite_memory_writes[arg_idx]:
            self.model.callsite_memory_writes[arg_idx][block] = {}
        self.model.callsite_memory_writes[arg_idx][block][offset] = (expr, self.func.addr)

    def collect_callsite_facts(self):
        """
        Collect memory writes to stack regions that are probably used by callee function
        """
        if not self.callsite_path:
            return
        call = self.terminal_call(self.callsite_path[-1])
        if call and call.args:
            # Calculate arguments' stack offsets
            stack_offsets = set()
            for arg in call.args:
                if vvar := unwrap_stack_vvar_reference(arg):
                    stack_offsets.add(vvar.stack_offset)
            stack_offsets = sorted(stack_offsets)
            if len(stack_offsets) == 0:
                return
            # Calculate the next argument stack offset that is larger than current stack offset
            next_offsets = {}
            for i in range(len(stack_offsets) - 1):
                next_offsets[stack_offsets[i]] = stack_offsets[i + 1]
            next_offsets[stack_offsets[-1]] = None
            # Collect memory writes to stack variables in callsite block
            stack_defs = DFAMixin(Pathfinder.path_to_graph(self.callsite_path)).collect_callsite_stack_defs(
                self.callsite_path[-1]
            )
            for idx, arg in enumerate(call.args):
                if vvar := unwrap_stack_vvar_reference(arg):
                    # Collect memory writes to stack region used by this argument
                    # Avoid include overlapping stack writes for arguments that share stack regions
                    referenced_offsets = set()
                    cur_offset = vvar.stack_offset
                    next_offset = next_offsets[cur_offset]
                    while (
                        (next_offset is None or cur_offset < next_offset)
                        and cur_offset not in referenced_offsets
                        and cur_offset in stack_defs
                    ):
                        stack_def = stack_defs[cur_offset]
                        self.add_callsite_memory_write(
                            idx, stack_def.block, cur_offset - vvar.stack_offset, stack_def.data
                        )
                        if referenced_vvar := unwrap_stack_vvar_reference(stack_def.data):
                            referenced_offsets.add(referenced_vvar.stack_offset)
                        cur_offset += stack_def.data.size

    def collect_post_callsite_facts(self):
        callsite_block = self.callsite_block
        if not callsite_block:
            return
        call = self.terminal_call(callsite_block)
        post_callsite_block = self.post_callsite_block
        if post_callsite_block and call.args and len(call.args):
            arg0 = call.args[0]
            if isinstance(arg0, BasePointerOffset) and isinstance(
                jump := self.last_stmt(post_callsite_block), ConditionalJump
            ):
                cond = jump.condition
                if (
                    isinstance(cond, BinaryOp)
                    and cond.op == "CmpEQ"
                    and isinstance(cond.operands[0], Load)
                    and isinstance(cond.operands[0].addr, BasePointerOffset)
                    and cond.operands[0].addr.likes(arg0)
                    and isinstance(cond.operands[1], Const)
                ):
                    self.model.none_discriminant = cond.operands[1].value

    def _rewrite_return_sites(self):
        ret_blocks = set()
        for block in self._graph.nodes:
            if block.statements and isinstance(block.statements[-1], Return):
                ret_blocks.add(block)
        paths = Pathfinder(self._graph, self).find_ret2arg0_paths()

        blocks_to_remove = set()

    def _analyze(self):
        self.collect_function_body_facts()
        self.collect_callsite_facts()
        # self.collect_post_callsite_facts()
        self.model.has_write_to_arg0 = self.model.has_write_to_arg0 or self._fact_collector.has_write_to_arg0
        self.model.const_ret_values.update(self._fact_collector.const_ret_values)

        prototype = self.infer_prototype()

        # if self.rewrite and prototype.is_arg0_retbuf:
        #     self._rewrite_return_sites()

        self.model.inferred_prototype = prototype
        self.kb.rust_calling_conventions.cache[self.func.addr] = self.model
        # l.debug(f"Memory writes:\n{pformat(dict(self.model.memory_writes))}")
        # l.debug(f"Callsite memory writes:\n{pformat(dict(self.model.callsite_memory_writes))}")
        l.debug(f"Analysis result for {demangle(self.func.name)} (addr: {hex(self.func.addr)}): {str(self.model)}")


AnalysesHub.register_default("RustCallingConvention", RustCallingConventionAnalysis)
