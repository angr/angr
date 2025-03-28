import logging
import traceback
from typing import Tuple, Optional, List
from collections import OrderedDict

from ailment import BinaryOp, Const, AILBlockWalker, Block
from ailment.expression import BasePointerOffset, VirtualVariable, Tmp, Load, Phi, StackBaseOffset
from ailment.statement import Store, Call, Statement, ConditionalJump, Return, Assignment, Jump, Label
from networkx import DiGraph

from ..mixins.cfa_mixin import CFAMixin
from ..mixins.dfa_mixin import DFAMixin
from ..mixins.srda_mixin import SRDAMixin
from ..optimization_passes.cleanup_code_remover import CleanupCodeRemover
from ..optimization_passes.unreachable_branch_fixer import UnreachableBranchFixer
from ..sim_type import RustSimEnum, RustSimTypeOption, RustSimTypeResult
from ..knowledge_plugins.rust_calling_conventions import RustCallingConventionModel
from ..sim_type import RustSimTypeInt, RustSimTypeReference, RustSimStruct, RustSimTypeFunction
from ..utils.library import normalize
from ..knowledge_plugins.known_structs import KnownStructs
from ..analyses.struct_memory_layout import SimpleMessageLayoutInference
from ...analyses import Analysis, AnalysesHub
from ...knowledge_plugins import Function

l = logging.getLogger(name=__name__)


CONST_STR_ERRORS = {
    "stream did not contain valid UTF-8": "INVALID_UTF8",
    "failed to fill whole buffer": "READ_EXACT_EOF",
    "The number of hardware threads is not known for the target platform": "UNKNOWN_THREAD_COUNT",
    "operation not supported on this platform": "UNSUPPORTED_PLATFORM",
    "failed to write whole buffer": "WRITE_ALL_EOF",
    "cannot set a 0 duration timeout": "ZERO_TIMEOUT",
}


class FunctionBodyFactCollector(AILBlockWalker):
    def __init__(self, context: "RustCallingConventionAnalysis"):
        super().__init__()
        self.context = context
        self.project = context.model.clinic.project
        self.model = context.model
        self.graph = context.model.clinic.graph
        self.has_write_to_arg0 = False
        self.const_ret_values = set()

        self._path = None

    def _get_dst_vvar_and_offset(self, stmt: Store) -> Tuple[VirtualVariable | None, int | None]:
        expr = stmt.addr
        offset = 0
        if (
            isinstance(expr, BinaryOp)
            and expr.op == "Add"
            and isinstance(expr.operands[0], VirtualVariable)
            and isinstance(expr.operands[1], Const)
        ):
            offset = expr.operands[1].value
            expr = expr.operands[0]
        if isinstance(expr, VirtualVariable):
            return self.context.get_terminal_vvar(expr), offset
        return None, None

    def _has_call(self, block_or_stmt):
        class CallWalker(AILBlockWalker):
            def __init__(self):
                super().__init__()
                self.has_call = False

            def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
                self.has_call = True
                return None

        walker = CallWalker()
        if isinstance(block_or_stmt, Block):
            walker.walk(block_or_stmt)
        elif isinstance(block_or_stmt, Statement):
            walker.walk_statement(block_or_stmt)
        return walker.has_call

    def _has_write(self, block):
        for stmt in reversed(block.statements):
            if isinstance(stmt, Store):
                vvar, _ = self._get_dst_vvar_and_offset(stmt)
                if isinstance(vvar, VirtualVariable) and vvar.was_parameter and vvar.varid == 0:
                    return True
        return False

    def _is_return_path_block(self, block):
        if self._has_call(block):
            return False

        return (
            all(
                isinstance(stmt, (Return, Jump, ConditionalJump, Label, Store, Assignment)) for stmt in block.statements
            )
            and self._has_write(block)
        ) or all(isinstance(stmt, (Return, Jump, ConditionalJump, Label)) for stmt in block.statements)

    def calculate_paths(self, block, max_paths):
        paths = [[block]]
        changed = True
        while len(paths) <= max_paths and changed:
            changed = False
            new_paths = []
            for path in paths:
                last_block = path[-1]
                path_changed = False
                for pred in self.graph.predecessors(last_block):
                    if self._is_return_path_block(pred):
                        new_path = list(path) + [pred]
                        new_paths.append(new_path)
                        changed = True
                        path_changed = True
                if not path_changed:
                    new_paths.append(path)
            paths = new_paths
        deduplicated_paths = set()
        for path in paths:
            path = list(path)
            while path and (
                all(isinstance(stmt, Label) for stmt in path[-1].statements)
                or isinstance(path[-1].statements[-1], ConditionalJump)
                or not self._has_write(path[-1])
            ):
                path.pop()
            if path:
                deduplicated_paths.add(tuple(path))
        return list(deduplicated_paths)

    def _is_ret_block(self, block):
        return block.statements and isinstance(block.statements[-1], Return)

    def collect(self):
        """
        Calculate paths that write return values to the first argument
        Collect facts from every path and every callsite in this function
        """
        paths = set()
        callsites = set()
        for block in self.model.clinic.graph.nodes:
            if self._is_ret_block(block):
                paths |= set(self.calculate_paths(block, max_paths=4))
            if self._has_call(block):
                callsites.add((block,))
        for path in paths | callsites:
            self._path = path
            for block in path:
                self.walk(block)

        if len(paths) == 0:
            for block in self.model.clinic.graph.nodes:
                if self._is_ret_block(block):
                    stmt = block.statements[-1]
                    ret_expr = stmt.ret_exprs[0] if stmt.ret_exprs else None
                    if isinstance(ret_expr, VirtualVariable):
                        self.const_ret_values |= set(
                            value.value
                            for value in self.context.get_terminal_vvar_values(ret_expr)
                            if isinstance(value, Const)
                        )
                    elif isinstance(ret_expr, Const):
                        self.const_ret_values.add(stmt.ret_expr.value)
        else:
            self.has_write_to_arg0 = True

    def add_memory_write(self, arg_idx, block_or_path, offset, expr):
        if block_or_path not in self.model.memory_writes[arg_idx]:
            self.model.memory_writes[arg_idx][block_or_path] = {}
        self.model.memory_writes[arg_idx][block_or_path][offset] = (expr, self.model.clinic.function.addr)

    def add_memory_read(self, arg_idx, block, offset, expr):
        if block not in self.model.memory_reads[arg_idx]:
            self.model.memory_reads[arg_idx][block] = {}
        self.model.memory_reads[arg_idx][block][offset] = (expr, self.model.clinic.function.addr)

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
        addr = self.context.get_terminal_vvar(addr)
        if isinstance(addr, VirtualVariable) and addr.was_parameter:
            self.add_memory_write(addr.varid, self._path, offset, stmt.data)

    def _handle_Call_Stmt_or_Expr(self, call: Call, block: Block):
        if (
            isinstance(call.target, Const)
            and call.target.value in self.project.kb.functions
            and call.args
            and isinstance(call.args[0], VirtualVariable)
            and call.args[0].was_parameter
            and call.args[0].varid == 0
        ):
            func = self.project.kb.functions[call.target.value]
            if func.normalized and func.size:
                result = self.project.analyses.RustCallingConvention(
                    func, callsite_block=block, depth=self.context.depth + 1, max_depth=self.context.max_depth
                )
                self.model.memory_writes[0] |= result.model.memory_writes[0]
                if result.fact_collector.has_write_to_arg0:
                    self.has_write_to_arg0 = True
            elif func.name == "memcpy" and len(call.args) == 3 and isinstance(call.args[2], Const):
                tmp = Tmp(None, None, 0, call.args[2].value * self.context.project.arch.byte_width)
                self.add_memory_write(0, self._path, 0, tmp)

    def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None):
        self._handle_Call_Stmt_or_Expr(stmt, block)
        super()._handle_Call(stmt_idx, stmt, block)

    def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
        self._handle_Call_Stmt_or_Expr(expr, block)
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

    def __init__(self, func, callsite_block=None, post_callsite_block=None, depth=0, max_depth=2):
        self.func: Function = func

        if self.func.addr in self.kb.rust_calling_conventions.cache:
            self.model = self.kb.rust_calling_conventions.cache[self.func.addr]
        else:
            self.model = RustCallingConventionModel()
            self.model.callsite_block = callsite_block
            self.model.post_callsite_block = post_callsite_block
            if self.func.normalized and self.func.size:
                try:
                    cfg = self.kb.cfgs.get_most_accurate()
                    self.model.clinic = self.project.analyses.Clinic(
                        self.func, cfg=cfg, optimization_passes=[UnreachableBranchFixer, CleanupCodeRemover]
                    )
                except Exception as e:
                    l.debug(f"Failed to recover AIL graph for {normalize(self.func.name)}")
                    l.debug("".join(traceback.format_exception(e)))

        self.fact_collector = FunctionBodyFactCollector(self)

        if self.model.clinic:
            CFAMixin.__init__(self, self.model.clinic, self.project)
            SRDAMixin.__init__(self, self.func, self.model.clinic.graph, self.project)
            DFAMixin.__init__(self)
            self.depth = depth
            self.max_depth = max_depth

            if self.depth <= self.max_depth:
                try:
                    self._analyze()
                except Exception as e:
                    l.debug(f"Rust calling convention analysis failed for {normalize(self.func.name)}")
                    l.debug("".join(traceback.format_exception(e)))

    def _srda_on_path(self, path: Tuple[Block]):
        graph = DiGraph()
        for i in range(len(path) - 1):
            u = path[i + 1]
            v = path[i]
            graph.add_edge(u, v)
        return SRDAMixin(self.func, graph, self.project)

    def _calculate_discriminant(self, path: Tuple[Block]) -> Optional[Const]:
        srda = self._srda_on_path(path)
        discriminant = None
        for i in range(len(path)):
            block = path[i]
            next_block = path[i + 1] if i + 1 < len(path) else None
            for stmt in reversed(block.statements):
                if discriminant is None:
                    if isinstance(stmt, Store) and isinstance(stmt.addr, VirtualVariable):
                        real_var = srda.get_terminal_vvar(stmt.addr)
                        if real_var.varid == 0 and real_var.was_parameter:
                            discriminant = stmt.data
                else:
                    if isinstance(stmt, Assignment) and stmt.dst.likes(discriminant):
                        discriminant = stmt.src
                if isinstance(discriminant, Phi) and next_block:
                    for src, vvar in discriminant.src_and_vvars:
                        if src == (next_block.addr, next_block.idx):
                            discriminant = vvar
                            break
                if discriminant and not isinstance(discriminant, VirtualVariable):
                    return discriminant if isinstance(discriminant, Const) else None
        return None

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
        self, candidates_and_paths: List[Tuple[RustSimStruct, Tuple[Block]]]
    ) -> RustSimEnum | None:
        # Simplest case: if there is only one candidate, it's not an Enum type
        if len(candidates_and_paths) <= 1:
            return None

        # There are different struct types. It may be an enum!
        # Calculate discriminant for each path and deduplicate
        candidates_and_discriminants = []
        visited = set()
        for candidate, path in candidates_and_paths:
            discriminant = self._calculate_discriminant(path)
            key = (candidate.size, discriminant.value if discriminant else None)
            if key not in visited:
                visited.add(key)
                candidates_and_discriminants.append((candidate, discriminant))

        # If there are two different struct types, it could be Option<T> or Result<T, E>
        # If the size of one of the struct types is equal to discriminant size, it is an Option<T>
        # Otherwise it's a Result<T, E>
        if len(candidates_and_discriminants) == 2:
            discriminants = list(discriminant for _, discriminant in candidates_and_discriminants)
            discriminant_sizes = set(discriminant.bits for discriminant in discriminants if discriminant is not None)
            # There should be only one discriminant size
            if len(discriminant_sizes) == 1:
                discriminant_size = next(iter(discriminant_sizes))
                sizes = set(candidate.size for candidate, _ in candidates_and_discriminants)
                overlapping_discriminant = None in discriminants
                if len(sizes) == 2:
                    if discriminant_size in sizes:
                        # This is probably an Option<T> or Result<(), E>
                        # Let's check if it's std::io::Result<()>
                        # Get the discriminant for None and Some variants
                        # Notice that if overlapping_discriminant is True, some_discriminant maybe None
                        some_type, some_discriminant = None, None
                        none_discriminant = None
                        for candidate, discriminant in candidates_and_discriminants:
                            if candidate.size == discriminant_size:
                                none_discriminant = discriminant
                            else:
                                some_type = candidate
                                some_discriminant = discriminant
                        if none_discriminant is not None:
                            none_discriminant = none_discriminant.value
                        elif some_discriminant is not None:
                            none_discriminant = some_discriminant.value - 1
                        if some_discriminant:
                            some_discriminant = some_discriminant.value
                        if not overlapping_discriminant:
                            some_type = self._remove_discriminant_from_struct(some_type)
                        return RustSimTypeOption(
                            some_type,
                            none_discriminant,
                            some_discriminant,
                            discriminant_size // self.project.arch.byte_width if not overlapping_discriminant else 0,
                        )
                    elif None not in discriminants:
                        # If all discriminants are found, it should be a Result<T, E> type
                        struct_type_and_discriminant = sorted(
                            candidates_and_discriminants,
                            key=lambda item: item[1].value,
                        )
                        ok_type, ok_discriminant = struct_type_and_discriminant[0]
                        err_type, err_discriminant = struct_type_and_discriminant[1]
                        ok_type = self._remove_discriminant_from_struct(ok_type)
                        err_type = self._remove_discriminant_from_struct(err_type)
                        return RustSimTypeResult(
                            ok_type,
                            err_type,
                            ok_discriminant.value,
                            err_discriminant.value,
                            discriminant_size // self.project.arch.byte_width,
                        )
                    else:
                        ok_type = None
                        err_type, err_discriminant = None, None
                        for struct_ty, discriminant in candidates_and_discriminants:
                            if discriminant is None:
                                ok_type = struct_ty
                            else:
                                err_type = self._remove_discriminant_from_struct(struct_ty)
                                err_discriminant = discriminant
                        return RustSimTypeResult(
                            ok_type,
                            err_type,
                            None,
                            err_discriminant.value,
                            discriminant_size // self.project.arch.byte_width,
                        )
        return None

    def _infer_return_type(self):
        # The first argument is not used as return buffer
        if len(self.model.callsite_memory_writes[0]) != 0 or not self.fact_collector.has_write_to_arg0:
            # Heuristics: check if the return type could be Result<(), &str> (std::io::Result<()>)
            if len(self.fact_collector.const_ret_values) == 2 and 0 in self.fact_collector.const_ret_values:
                addr = max(self.fact_collector.const_ret_values)
                if SimpleMessageLayoutInference(self.project).is_const_simple_message(addr):
                    ok_type = RustSimStruct(OrderedDict(), "()", True).with_arch(self.project.arch)
                    err_type = self.kb.known_structs[KnownStructs.SIMPLE_MESSAGE]
                    return RustSimTypeResult(ok_type, err_type, 0, None, 0)
            return None

        memory_writes = self.model.memory_writes[0]
        candidates_and_paths = []

        for path in memory_writes:
            fields = {}
            path_memory_writes = memory_writes[path]
            for offset in sorted(path_memory_writes.keys()):
                expr, func_addr = path_memory_writes[offset]
                arg_ty = RustSimTypeInt(expr.bits, signed=False)
                fields[f"field_{offset}"] = arg_ty
            struct_ty = RustSimStruct(
                fields,
                name=f"struct{sum(field.size if field.size else 0 for field in fields.values()) // 8}",
                pack=True,
            ).with_arch(self.project.arch)
            candidates_and_paths.append((struct_ty, path))

        # Return inferred enum type if we found one, otherwise return the struct type with the largest size
        returnty = self._infer_potential_enum_type(candidates_and_paths)
        if not returnty and candidates_and_paths:
            returnty = next(iter(sorted(candidates_and_paths, key=lambda item: item[0].size, reverse=True)))[0]
        return returnty

    def _infer_arg_type(self, arg_idx):
        memory_writes = self.model.memory_writes[arg_idx] | self.model.callsite_memory_writes[arg_idx]
        candidates = []

        for block_or_path in memory_writes:
            fields = {}
            block_memory_writes = memory_writes[block_or_path]
            for offset in sorted(block_memory_writes.keys()):
                expr, func_addr = block_memory_writes[offset]
                arg_ty = RustSimTypeInt(expr.bits, signed=False)
                fields[f"field_{offset}"] = arg_ty
            struct_ty = RustSimStruct(
                fields,
                name=f"struct{sum(field.size if field.size else 0 for field in fields.values()) // 8}",
                pack=True,
            ).with_arch(self.project.arch)
            candidates.append(struct_ty)

        final_ty = sorted(candidates, key=lambda candidate: candidate.size, reverse=True)[0] if candidates else None
        if final_ty:
            final_ty = RustSimTypeReference(final_ty).with_arch(self.project.arch)

        return final_ty

    def infer_prototype(self):
        returnty = self._infer_return_type()
        is_arg0_ret_buf = self.fact_collector.has_write_to_arg0 and returnty is not None
        args = []
        for arg_idx, old_arg_type in zip(range(len(self.model.clinic.arg_list)), self.func.prototype.args):
            if is_arg0_ret_buf and arg_idx == 0:
                args.append(RustSimTypeReference(returnty).with_arch(self.project.arch))
                continue
            arg_type = self._infer_arg_type(arg_idx)
            if not arg_type:
                arg_type = old_arg_type
            args.append(arg_type)
        prototype = self.func.prototype
        return RustSimTypeFunction(
            args=args,
            returnty=prototype.returnty if is_arg0_ret_buf or returnty is None else returnty,
            label=prototype.label,
            arg_names=prototype.arg_names,
            variadic=prototype.variadic,
            is_arg0_retbuf=is_arg0_ret_buf,
        )

    def collect_function_body_facts(self):
        self.fact_collector.collect()

    def add_callsite_memory_write(self, arg_idx, block, offset, expr):
        if block not in self.model.callsite_memory_writes[arg_idx]:
            self.model.callsite_memory_writes[arg_idx][block] = {}
        self.model.callsite_memory_writes[arg_idx][block][offset] = (expr, self.model.clinic.function.addr)

    def collect_callsite_facts(self):
        callsite_block = self.model.callsite_block
        if callsite_block is None:
            return
        call = self.terminal_call(callsite_block)
        if call and call.args:
            stack_offsets = []
            for arg in call.args:
                if isinstance(arg, BasePointerOffset):
                    stack_offsets.append(arg.offset)
            for idx, arg in enumerate(call.args):
                if isinstance(arg, BasePointerOffset):
                    cur_offset = arg.offset
                    while len(list(filter(lambda offset: cur_offset >= offset, stack_offsets))) == len(
                        list(filter(lambda offset: arg.offset >= offset, stack_offsets))
                    ):
                        data = None
                        for stmt in reversed(callsite_block.statements):
                            dst_offset, src_data = self.extract_stack_dest_data_flow(stmt)
                            if dst_offset == cur_offset and src_data:
                                data = src_data
                                break
                        if data is None:
                            break
                        self.add_callsite_memory_write(idx, callsite_block, cur_offset - arg.offset, data)
                        cur_offset += data.size

    def collect_post_callsite_facts(self):
        callsite_block = self.model.callsite_block
        if not callsite_block:
            return
        call = self.terminal_call(callsite_block)
        post_callsite_block = self.model.post_callsite_block
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

    def _analyze(self):
        self.collect_function_body_facts()
        self.collect_callsite_facts()
        self.collect_post_callsite_facts()

        prototype = self.infer_prototype()

        self.model.inferred_prototype = prototype
        self.kb.rust_calling_conventions.cache[self.func.addr] = self.model
        # l.debug(f"Memory writes:\n{pformat(dict(self.model.memory_writes))}")
        # l.debug(f"Callsite memory writes:\n{pformat(dict(self.model.callsite_memory_writes))}")
        l.debug(f"Analysis result for {normalize(self.func.name)} (addr: {hex(self.func.addr)}): {str(self.model)}")


AnalysesHub.register_default("RustCallingConvention", RustCallingConventionAnalysis)
