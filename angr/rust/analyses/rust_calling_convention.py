from collections import defaultdict
from typing import Optional
import logging
import traceback

from ailment import BinaryOp, Const, AILBlockWalker, Block
from ailment.expression import BasePointerOffset
from ailment.statement import Store, Call, Statement

from ..knowledge_plugins.rust_calling_conventions import RustCallingConventionModel
from ..sim_type import RustSimType, RustSimTypeInt, RustSimTypeReference, RustSimStruct, RustSimTypeFunction
from ..utils.ail_util import get_terminal_call
from ..utils.library import normalize
from ...analyses import Analysis, AnalysesHub
from ...knowledge_plugins import Function


l = logging.getLogger(name=__name__)


class RustCallingConventionAILBlockWalker(AILBlockWalker):
    def __init__(self, analysis: "RustCallingConventionAnalysis"):
        super().__init__()
        self.analysis = analysis

    def _handle_Store(self, stmt_idx: int, stmt: Store, block: Block | None):
        var, offset = None, 0
        addr = stmt.addr
        if isinstance(addr, BinaryOp) and addr.op == "Add" and isinstance(addr.operands[1], Const):
            offset = addr.operands[1].value
            addr = addr.operands[0]
        if hasattr(addr, "variable") and addr.variable:
            var = addr.variable
        if var and var in self.analysis.clinic.arg_list:
            self.analysis.add_memory_write(var, offset, stmt.data)

    def _handle_CallStmtOrExpr(self, call: Call):
        if (
            call.args
            and any(arg.variable in self.analysis.clinic.arg_list for arg in call.args)
            and isinstance(call.target, Const)
        ):
            func = self.analysis.kb.functions[call.target.value]
            if func.normalized and func.size:
                rcc: RustCallingConventionAnalysis = self.analysis.project.analyses.RustCallingConvention(
                    func=self.analysis.kb.functions[call.target.value],
                    depth=self.analysis._depth + 1,
                    max_depth=self.analysis._max_depth,
                )
                for var in rcc.model.memory_writes:
                    var_idx = rcc.clinic.arg_list.index(var)
                    mapped_var = call.args[var_idx].variable
                    if mapped_var in self.analysis.clinic.arg_list:
                        self.analysis.model.memory_writes[mapped_var] = rcc.model.memory_writes[var]

    def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None):
        super()._handle_Call(stmt_idx, stmt, block)
        self._handle_CallStmtOrExpr(stmt)

    def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
        super()._handle_CallExpr(expr_idx, expr, stmt_idx, stmt, block)
        self._handle_CallStmtOrExpr(expr)


class RustCallingConventionAnalysis(Analysis):
    def __init__(self, func, caller_graph=None, depth=0, max_depth=1, clinic=None):
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

    def _infer_arg_type(self, var) -> Optional[RustSimType]:
        fields = {}
        memory_writes = self.model.memory_writes[var]
        memory_writes.update(self.model.callsite_memory_writes[var])
        for offset in sorted(memory_writes.keys()):
            data, func_addr = memory_writes[offset]
            arg_ty = self.clinic.variable_kb.variables[func_addr].get_variable_type(data.variable)
            if not arg_ty:
                arg_ty = RustSimTypeInt(data.bits, signed=False)
            fields[f"field_{offset}"] = arg_ty
        if fields:
            ty = RustSimTypeReference(
                RustSimStruct(
                    fields,
                    name=f"struct{sum(field.size if field.size else 0 for field in fields.values()) // 8}",
                    pack=True,
                )
            ).with_arch(self.project.arch)
            return ty
        return None

    def _infer_prototype(self):
        args = []
        is_first_arg_ret_buffer = False
        for idx, old_arg_type, arg in zip(
            range(len(self.clinic.arg_list)), self.func.prototype.args, self.clinic.arg_list
        ):
            arg_type = self._infer_arg_type(arg)
            if not arg_type:
                arg_type = old_arg_type
            if (
                idx == 0
                and isinstance(arg_type, RustSimTypeReference)
                and isinstance(arg_type.pts_to, RustSimStruct)
                and len(self.model.callsite_memory_writes[arg]) == 0
            ):
                is_first_arg_ret_buffer = True
            args.append(arg_type)
        prototype = self.func.prototype
        return RustSimTypeFunction(
            args=args,
            returnty=prototype.returnty,
            label=prototype.label,
            arg_names=prototype.arg_names,
            variadic=prototype.variadic,
            is_returnty_struct=is_first_arg_ret_buffer,
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

        if not self.clinic:
            cfg = self.kb.cfgs.get_most_accurate()
            self.clinic = self.project.analyses.Clinic(self.func, cfg=cfg, optimization_passes=[])

        # Collect facts for inferring return type
        walker = RustCallingConventionAILBlockWalker(self)
        for block in self.clinic.graph.nodes:
            walker.walk(block)

        if self.caller_graph:
            # Collect callsite facts for inferring argument types
            for block in self.caller_graph.nodes:
                call = get_terminal_call(block)
                if call and isinstance(call.target, Const) and call.target.value == self.func.addr:
                    self._collect_callsite_facts(block, call)

        prototype = self._infer_prototype()
        self.model.inferred_prototype = prototype
        self.kb.rust_calling_conventions.cache[self.func.addr] = self.model
        l.debug(f"Analysis result for {normalize(self.func.name)} (addr: {hex(self.func.addr)}): {str(self.model)}")


AnalysesHub.register_default("RustCallingConvention", RustCallingConventionAnalysis)
