import logging
import traceback

from ailment import BinaryOp, Const, AILBlockWalker, Block
from ailment.expression import BasePointerOffset, VirtualVariable, Phi, Tmp, Load
from ailment.statement import Store, Call, Statement, ConditionalJump
import networkx as nx

from ..sim_type import RustSimEnum, RustSimTypeOption
from ..knowledge_plugins.rust_calling_conventions import RustCallingConventionModel
from ..sim_type import RustSimTypeInt, RustSimTypeReference, RustSimStruct, RustSimTypeFunction
from ..utils.ail_util import get_terminal_call
from ..utils.library import normalize
from ..utils.srda_util import SRDAUtil
from ...analyses import Analysis, AnalysesHub
from ...analyses.s_reaching_definitions import SRDAView
from ...knowledge_plugins import Function

l = logging.getLogger(name=__name__)


class FactsCollector(AILBlockWalker):
    def __init__(self, context: "RustCallingConventionAnalysis", srda_view: SRDAView):
        super().__init__()
        self.context = context
        self.project = context.model.clinic.project
        self.model = context.model
        self.srda_view = srda_view

    def add_memory_write(self, arg_idx, block, offset, expr):
        if block not in self.model.memory_writes[arg_idx]:
            self.model.memory_writes[arg_idx][block] = {}
        self.model.memory_writes[arg_idx][block][offset] = (expr, self.model.clinic.function.addr)

    def add_callsite_memory_write(self, arg_idx, block, offset, expr):
        if block not in self.model.callsite_memory_writes[arg_idx]:
            self.model.callsite_memory_writes[arg_idx][block] = {}
        self.model.callsite_memory_writes[arg_idx][block][offset] = (expr, self.model.clinic.function.addr)

    def add_memory_read(self, arg_idx, block, offset, expr):
        if block not in self.model.memory_reads[arg_idx]:
            self.model.memory_reads[arg_idx][block] = {}
        self.model.memory_reads[arg_idx][block][offset] = (expr, self.model.clinic.function.addr)

    def get_vvar_value(self, vvar):
        value = vvar
        for i in range(100):  # Avoid unexpected infinite loop
            value = self.srda_view.get_vvar_value(vvar)
            if isinstance(value, VirtualVariable):
                vvar = value
            elif isinstance(value, Phi):
                result = set()
                for _, phi_vvar in value.src_and_vvars:
                    result.add(self.get_vvar_value(phi_vvar))
                if len(result) == 1:
                    return next(iter(result))
                else:
                    return vvar
            else:
                return vvar
        return value

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
        addr = self.get_vvar_value(addr)
        if isinstance(addr, VirtualVariable) and addr.was_parameter:
            self.add_memory_write(addr.varid, block, offset, stmt.data)

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
                    func, block, depth=self.context.depth + 1, max_depth=self.context.max_depth
                )
                self.model.memory_writes[0] |= result.model.memory_writes[0]
            elif func.name == "memcpy" and len(call.args) == 3 and isinstance(call.args[2], Const):
                self.add_memory_write(
                    0, block, 0, Tmp(None, None, 0, call.args[2].value * self.context.project.arch.byte_width)
                )

    def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None):
        self.handle_Call(stmt, block)
        super()._handle_Call(stmt_idx, stmt, block)

    def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
        self.handle_Call(expr, block)
        super()._handle_CallExpr(expr_idx, expr, stmt_idx, stmt, block)

    def collect_callsite_facts(self):
        callsite_block = self.model.callsite_block
        call = get_terminal_call(callsite_block)
        if call and call.args:
            func_graph = nx.DiGraph()
            func_graph.add_node(callsite_block)
            srda = self.project.analyses.SReachingDefinitions(subject=callsite_block, func_graph=func_graph)
            srda_util = SRDAUtil(srda)
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
                        vvar = srda_util.get_stack_vvar_by_insn(cur_offset, call.ins_addr, callsite_block.idx)
                        if vvar is None:
                            break
                        self.add_callsite_memory_write(idx, callsite_block, cur_offset - arg.offset, vvar)
                        cur_offset += vvar.size

    def collect_post_callsite_facts(self):
        callsite_block = self.model.callsite_block
        call = get_terminal_call(callsite_block)
        post_callsite_block = self.model.post_callsite_block
        if call.args and len(call.args):
            arg0 = call.args[0]
            if (
                isinstance(arg0, BasePointerOffset)
                and post_callsite_block.statements
                and isinstance(post_callsite_block.statements[-1], ConditionalJump)
            ):
                jump = post_callsite_block.statements[-1]
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


class RustCallingConventionAnalysis(Analysis):
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
        self.model = RustCallingConventionModel()
        self.model.callsite_block = callsite_block
        self.model.post_callsite_block = post_callsite_block

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

    @clinic.setter
    def clinic(self, value):
        self.model.clinic = value

    def add_memory_write(self, var, offset, data):
        self.model.memory_writes[var][offset] = (data, self.func.addr)

    def add_callsite_memory_write(self, var, offset, data):
        self.model.callsite_memory_writes[var][offset] = (data, self.func.addr)

    def _analyze(self):
        if self.func.addr in self.kb.rust_calling_conventions.cache:
            self.model = self.kb.rust_calling_conventions.cache[self.func.addr]
            return

        if not self.func.normalized or not self.func.size:
            return

        if not self.clinic:
            cfg = self.kb.cfgs.get_most_accurate()
            self.clinic = self.project.analyses.Clinic(self.func, cfg=cfg, optimization_passes=[])

        srda = self.project.analyses.SReachingDefinitions(subject=self.func, func_graph=self.clinic.graph)
        srda_view = SRDAView(srda.model)
        walker = FactsCollector(self, srda_view)
        for block in self.clinic.graph.nodes:
            walker.walk(block)
        walker.collect_callsite_facts()
        walker.collect_post_callsite_facts()

        prototype = self._infer_prototype()

        self.model.inferred_prototype = prototype
        self.kb.rust_calling_conventions.cache[self.func.addr] = self.model
        l.debug(f"Analysis result for {normalize(self.func.name)} (addr: {hex(self.func.addr)}): {str(self.model)}")


AnalysesHub.register_default("RustCallingConvention", RustCallingConventionAnalysis)
