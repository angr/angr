import logging
import traceback

from ailment import BinaryOp, Const, AILBlockWalker, Block
from ailment.expression import BasePointerOffset, VirtualVariable, Phi
from ailment.statement import Store, Call, Statement

from ..knowledge_plugins.rust_calling_conventions import RustCallingConventionModel
from ..sim_type import RustSimTypeInt, RustSimTypeReference, RustSimStruct, RustSimTypeFunction
from ..utils.library import normalize
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

    def handle_Call(self, call: Call):
        if (
            isinstance(call.target, Const)
            and call.target.value in self.project.kb.functions
            and call.args
            and isinstance(call.args[0], VirtualVariable)
            and call.args[0].was_parameter
            and call.args[0].varid == 0
        ):
            func = self.project.kb.functions[call.target.value]
            result = self.project.analyses.RustCallingConvention(
                func, self.context.clinic.graph, depth=self.context.depth + 1, max_depth=self.context.max_depth
            )
            self.model.memory_writes[0] |= result.model.memory_writes[0]

    def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None):
        self.handle_Call(stmt)
        super()._handle_Call(stmt_idx, stmt, block)

    def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
        self.handle_Call(expr)
        super()._handle_CallExpr(expr_idx, expr, stmt_idx, stmt, block)


class RustCallingConventionAnalysis(Analysis):
    def __init__(self, func, caller_graph=None, depth=0, max_depth=1):
        self.func: Function = func
        self.model = RustCallingConventionModel()
        self.model.caller_graph = caller_graph

        self.depth = depth
        self.max_depth = max_depth

        if self.depth <= self.max_depth:
            try:
                self._analyze()
            except Exception as e:
                l.debug(f"Rust calling convention analysis failed for {normalize(self.func.name)}")
                l.debug("".join(traceback.format_exception(e)))

    def _merge_struct_types(self, struct_types) -> RustSimStruct | None:
        """
        Merge a list of struct types
        If the types have different sizes, merge them into one enum type
        """
        if len(struct_types) == 0:
            return None
        sizes = {ty.size for ty in struct_types}
        if len(sizes) == 1:
            return next(iter(struct_types))
        # Return an enum type
        return next(iter(struct_types))

    def _infer_arg_type(self, arg_idx):
        fields = {}
        memory_writes = self.model.memory_writes[arg_idx]
        struct_types = []

        for block in memory_writes:
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

        final_ty = self._merge_struct_types(struct_types)
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
                and isinstance(arg_type.pts_to, RustSimStruct)
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

    def _collect_callsite_facts(self, block, call):
        args = call.args
        stack = {}

        def collect_stack_writes(cur_block):
            for stmt in cur_block.statements:
                if isinstance(stmt, Store) and isinstance(stmt.addr, BasePointerOffset):
                    stack[stmt.addr.offset] = stmt.data

        collect_stack_writes(block)
        if not stack:
            for pred in self.caller_graph.predecessors(block):
                collect_stack_writes(pred)

        stack_offsets = sorted(stack.keys())
        args = [arg.offset if isinstance(arg, BasePointerOffset) else None for arg in args]
        for arg_idx, arg in enumerate(args):
            if arg in stack_offsets:
                idx = stack_offsets.index(arg)
                for i in range(idx, len(stack_offsets)):
                    offset = stack_offsets[i]
                    if offset != arg and offset in args:
                        break
                    mapped_var = self.clinic.arg_list[arg_idx]
                    self.add_callsite_memory_write(mapped_var, offset - arg, stack[offset])

    @property
    def clinic(self):
        return self.model.clinic

    @clinic.setter
    def clinic(self, value):
        self.model.clinic = value

    @property
    def caller_graph(self):
        return self.model.caller_graph

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

        prototype = self._infer_prototype()

        self.model.inferred_prototype = prototype
        self.kb.rust_calling_conventions.cache[self.func.addr] = self.model
        l.debug(f"Analysis result for {normalize(self.func.name)} (addr: {hex(self.func.addr)}): {str(self.model)}")


AnalysesHub.register_default("RustCallingConvention", RustCallingConventionAnalysis)
