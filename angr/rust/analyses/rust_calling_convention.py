import logging
import traceback
from pprint import pformat
from typing import Tuple

from ailment import BinaryOp, Const, AILBlockWalker, Block
from ailment.expression import BasePointerOffset, VirtualVariable, Tmp, Load
from ailment.statement import Store, Call, Statement, ConditionalJump, Return
import networkx as nx

from ..mixins.cfa_mixin import CFAMixin
from ..mixins.srda_mixin import SRDAMixin
from ..sim_type import RustSimEnum, RustSimTypeOption
from ..knowledge_plugins.rust_calling_conventions import RustCallingConventionModel
from ..sim_type import RustSimTypeInt, RustSimTypeReference, RustSimStruct, RustSimTypeFunction
from ..utils.library import normalize
from ...analyses import Analysis, AnalysesHub
from ...knowledge_plugins import Function

l = logging.getLogger(name=__name__)


class PathFactsCollector(AILBlockWalker):
    def __init__(self, context: "RustCallingConventionAnalysis", path: Tuple[Block]):
        super().__init__()
        self.context = context
        self.project = context.model.clinic.project
        self.model = context.model
        self.path = path

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
            self.context.add_memory_write(addr.varid, self.path, offset, stmt.data)

    def handle_Call(self, call: Call, block: Block):
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
            elif func.name == "memcpy" and len(call.args) == 3 and isinstance(call.args[2], Const):
                tmp = Tmp(None, None, 0, call.args[2].value * self.context.project.arch.byte_width)
                self.context.add_memory_write(0, self.path, 0, tmp)

    def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None):
        self.handle_Call(stmt, block)
        super()._handle_Call(stmt_idx, stmt, block)

    def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
        self.handle_Call(expr, block)
        super()._handle_CallExpr(expr_idx, expr, stmt_idx, stmt, block)


class RustCallingConventionAnalysis(Analysis, CFAMixin, SRDAMixin):
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

    def __init__(self, func, callsite_block=None, post_callsite_block=None, depth=0, max_depth=1):
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
                    self.model.clinic = self.project.analyses.Clinic(self.func, cfg=cfg, optimization_passes=[])
                except Exception as e:
                    l.debug(f"Failed to recover AIL graph for {normalize(self.func.name)}")
                    l.debug("".join(traceback.format_exception(e)))

        if self.model.clinic:
            CFAMixin.__init__(self, self.model.clinic, self.project)
            SRDAMixin.__init__(self, self.func, self.clinic.graph, self.project)
            self.depth = depth
            self.max_depth = max_depth

            if self.depth <= self.max_depth:
                try:
                    self._analyze()
                except Exception as e:
                    l.debug(f"Rust calling convention analysis failed for {normalize(self.func.name)}")
                    l.debug("".join(traceback.format_exception(e)))

    def _decide_final_type(self, struct_types) -> RustSimStruct | RustSimEnum | None:
        if len(struct_types) == 0:
            return None

        sizes = {ty.size for ty in struct_types}

        # Check if it's a struct
        if len(sizes) == 1:
            return next(iter(struct_types))

        # Check if it's an Option<T>
        if self.model.none_discriminant is not None and len(sizes) == 2 and self.project.arch.bits in sizes:
            struct_type = next(filter(lambda ty: ty.size != self.project.arch.bits, struct_types))
            return RustSimTypeOption(struct_type, self.model.none_discriminant)

        return RustSimEnum(struct_types, False)

    def _infer_arg_type(self, arg_idx):
        memory_writes = self.model.memory_writes[arg_idx] | self.model.callsite_memory_writes[arg_idx]
        struct_types = []

        for block in memory_writes:
            fields = {}
            block_memory_writes = memory_writes[block]
            for offset in sorted(block_memory_writes.keys()):
                expr, func_addr = block_memory_writes[offset]
                arg_ty = RustSimTypeInt(expr.bits, signed=False)
                fields[f"field_{offset}"] = arg_ty
            struct_types.append(
                RustSimStruct(
                    fields,
                    name=f"struct{sum(field.size if field.size else 0 for field in fields.values()) // 8}",
                    pack=True,
                ).with_arch(self.project.arch)
            )

        final_ty = self._decide_final_type(struct_types)
        if final_ty:
            final_ty = RustSimTypeReference(final_ty).with_arch(self.project.arch)

        return final_ty

    def _infer_prototype(self):
        args = []
        is_arg0_ret_buf = False
        for arg_idx, old_arg_type in zip(range(len(self.clinic.arg_list)), self.func.prototype.args):
            arg_type = self._infer_arg_type(arg_idx)
            if not arg_type:
                arg_type = old_arg_type
            if (
                arg_idx == 0
                and isinstance(arg_type, RustSimTypeReference)
                and (isinstance(arg_type.pts_to, RustSimStruct) or isinstance(arg_type.pts_to, RustSimEnum))
                and len(self.model.callsite_memory_writes[arg_idx]) == 0
            ):
                is_arg0_ret_buf = True
            args.append(arg_type)
        prototype = self.func.prototype
        return RustSimTypeFunction(
            args=args,
            returnty=prototype.returnty,
            label=prototype.label,
            arg_names=prototype.arg_names,
            variadic=prototype.variadic,
            is_returnty_struct=is_arg0_ret_buf,
        )

    @property
    def clinic(self):
        return self.model.clinic

    def add_memory_write(self, arg_idx, block_or_path, offset, expr):
        if block_or_path not in self.model.memory_writes[arg_idx]:
            self.model.memory_writes[arg_idx][block_or_path] = {}
        self.model.memory_writes[arg_idx][block_or_path][offset] = (expr, self.model.clinic.function.addr)

    def add_callsite_memory_write(self, arg_idx, block, offset, expr):
        if block not in self.model.callsite_memory_writes[arg_idx]:
            self.model.callsite_memory_writes[arg_idx][block] = {}
        self.model.callsite_memory_writes[arg_idx][block][offset] = (expr, self.model.clinic.function.addr)

    def add_memory_read(self, arg_idx, block, offset, expr):
        if block not in self.model.memory_reads[arg_idx]:
            self.model.memory_reads[arg_idx][block] = {}
        self.model.memory_reads[arg_idx][block][offset] = (expr, self.model.clinic.function.addr)

    def _derive_paths(self, block, max_paths):
        paths = [[block]]
        changed = True
        while len(paths) <= max_paths and changed:
            changed = False
            new_paths = []
            for path in paths:
                last_block = path[-1]
                path_changed = False
                for pred in self.clinic.graph.predecessors(last_block):
                    new_path = list(path) + [pred]
                    new_paths.append(new_path)
                    changed = True
                    path_changed = True
                if not path_changed:
                    new_paths.append(path)
            paths = new_paths
        return [tuple(path) for path in paths]

    def collect_function_body_facts(self):
        ret_blocks = set()
        for block in self.model.clinic.graph.nodes:
            if block.statements and isinstance(block.statements[-1], Return):
                ret_blocks.add(block)
        for ret_block in ret_blocks:
            paths = self._derive_paths(ret_block, max_paths=4)
            for path in paths:
                walker = PathFactsCollector(self, path)
                for block in path:
                    walker.walk(block)

    def collect_callsite_facts(self):
        callsite_block = self.model.callsite_block
        call = self.terminal_call(callsite_block)
        if call and call.args:
            func_graph = nx.DiGraph()
            func_graph.add_node(callsite_block)
            srda = SRDAMixin(callsite_block, func_graph, self.project)
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
                        vvar = srda.get_stack_vvar_by_insn(cur_offset, call.ins_addr, callsite_block.idx)
                        if vvar is None:
                            break
                        self.add_callsite_memory_write(idx, callsite_block, cur_offset - arg.offset, vvar)
                        cur_offset += vvar.size

    def collect_post_callsite_facts(self):
        callsite_block = self.model.callsite_block
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

        prototype = self._infer_prototype()

        self.model.inferred_prototype = prototype
        self.kb.rust_calling_conventions.cache[self.func.addr] = self.model
        l.debug(f"Memory writes:\n{pformat(dict(self.model.memory_writes))}")
        l.debug(f"Callsite memory writes:\n{pformat(dict(self.model.callsite_memory_writes))}")
        l.debug(f"Analysis result for {normalize(self.func.name)} (addr: {hex(self.func.addr)}): {str(self.model)}")


AnalysesHub.register_default("RustCallingConvention", RustCallingConventionAnalysis)
