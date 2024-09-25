import logging
import traceback

from ailment import BinaryOp, Const, AILBlockWalker, Block
from ailment.expression import BasePointerOffset, VirtualVariable
from ailment.statement import Store

from ..definitions.structs import Option
from ..knowledge_plugins.rust_calling_conventions import RustCallingConventionModel
from ..sim_type import RustSimTypeInt, RustSimTypeReference, RustSimStruct, RustSimTypeFunction
from ..utils.library import normalize
from ...analyses import Analysis, AnalysesHub
from ...knowledge_plugins import Function

l = logging.getLogger(name=__name__)


class FactsCollector(AILBlockWalker):
    def __init__(self, model: RustCallingConventionModel):
        super().__init__()
        self.model = model

    def add_memory_write(self, arg_idx, block, offset, expr):
        if block not in self.model.memory_writes[arg_idx]:
            self.model.memory_writes[arg_idx][block] = {}
        self.model.memory_writes[arg_idx][block][offset] = (expr, self.model.clinic.function.addr)

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
        addr: VirtualVariable
        if addr.was_parameter:
            self.add_memory_write(addr.varid, block, offset, stmt.data)


class RustCallingConventionAnalysis(Analysis):
    def __init__(self, func, caller_graph=None, depth=0, max_depth=1):
        self.func: Function = func
        self.model = RustCallingConventionModel()
        self.model.caller_graph = caller_graph

        self._depth = depth
        self._max_depth = max_depth

        if self._depth <= self._max_depth:
            try:
                self._analyze()
            except Exception as e:
                l.debug(f"Rust calling convention analysis failed for {normalize(self.func.name)}")
                l.debug("".join(traceback.format_exception(e)))

    def _infer_arg_type(self, arg_idx):
        fields = {}
        memory_writes = self.model.memory_writes[arg_idx]
        # If we find potential discriminant in collected facts, the type maybe Result or Option
        discriminant = None
        overlapping_discriminant = False
        struct_types = []

        def _maybe_discriminant(block_memory_writes):
            return (
                len(block_memory_writes) == 1
                and 0 in block_memory_writes
                and isinstance(block_memory_writes[0][0], Const)
            )

        for block in memory_writes:
            block_memory_writes = memory_writes[block]
            if _maybe_discriminant(block_memory_writes):
                discriminant = block_memory_writes[0][0].value

        for block in memory_writes:
            block_memory_writes = memory_writes[block]
            if _maybe_discriminant(block_memory_writes):
                continue
            for offset in sorted(block_memory_writes.keys()):
                expr, func_addr = block_memory_writes[offset]
                arg_ty = RustSimTypeInt(expr.bits, signed=False)
                fields[f"field_{offset}"] = arg_ty
            ty = RustSimTypeReference(
                RustSimStruct(
                    fields,
                    name=f"struct{sum(field.size if field.size else 0 for field in fields.values()) // 8}",
                    pack=True,
                )
            ).with_arch(self.project.arch)
            struct_types.append(ty)

        if discriminant is not None and discriminant != 0 and len(struct_types):
            struct_ty = Option(struct_types[0].pts_to, overlapping_discriminant=overlapping_discriminant)
            return RustSimTypeReference(struct_ty).with_arch(self.project.arch)
        return struct_types[0] if len(struct_types) else None

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

        walker = FactsCollector(self.model)
        for block in self.clinic.graph.nodes:
            walker.walk(block)

        prototype = self._infer_prototype()
        self.model.inferred_prototype = prototype
        self.kb.rust_calling_conventions.cache[self.func.addr] = self.model
        l.debug(f"Analysis result for {normalize(self.func.name)} (addr: {hex(self.func.addr)}): {str(self.model)}")


AnalysesHub.register_default("RustCallingConvention", RustCallingConventionAnalysis)
