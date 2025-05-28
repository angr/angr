import logging
from collections import OrderedDict, defaultdict
from typing import Optional

from ailment import Const, AILBlockWalkerBase, Block, Statement
from ailment.expression import Load, VirtualVariable
from ailment.statement import Store, ConditionalJump, Call

from ..definitions.prototypes import generate_known_rust_prototypes
from ..optimization_passes.utils import extract_str_from_addr
from ..utils.ail import (
    unwrap_stack_vvar_reference,
    extract_vvar_and_offset,
)
from ...analyses import Analysis, AnalysesHub
from ..mixins import CFAMixin, DFAMixin
from ..sim_type import RustSimTypeOption, RustSimStruct, RustSimTypeReference, RustSimTypeArrayRef, RustSimTypeStrRef

l = logging.getLogger(name=__name__)


class ReferenceCounter(AILBlockWalkerBase):

    def __init__(self, arg_idx, project, depth=0):
        super().__init__()
        self.arg_idx = arg_idx
        self.project = project
        self.depth = depth
        self.read_counter = defaultdict(int)
        self.write_counter = defaultdict(int)
        self.condition_counter = defaultdict(int)

    def _handle_Store(self, stmt_idx: int, stmt: Store, block: Block | None):
        vvar, offset = extract_vvar_and_offset(stmt.addr)
        if vvar and vvar.was_parameter and vvar.varid == self.arg_idx:
            self.write_counter[offset] += 1
        super()._handle_Store(stmt_idx, stmt, block)

    def _handle_Load(self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement, block: Block | None):
        vvar, offset = extract_vvar_and_offset(expr.addr)
        if vvar and vvar.was_parameter and vvar.varid == self.arg_idx:
            self.read_counter[offset] += 1
            if isinstance(stmt, ConditionalJump):
                self.condition_counter[offset] += 1
        super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_call(self, call):
        if self.depth >= 5:
            return
        if isinstance(call.target, Const) and call.target.value in self.project.kb.functions:
            func = self.project.kb.functions[call.target.value]
            for arg_idx, arg in enumerate(call.args or []):
                if isinstance(arg, VirtualVariable) and arg.was_parameter and arg.varid == self.arg_idx:
                    clinic = self.project.analyses.Clinic(
                        func, cfg=self.project.kb.cfgs.get_most_accurate(), optimization_passes=[]
                    )
                    walker = ReferenceCounter(arg_idx, self.project, self.depth + 1)
                    for block in clinic.graph.nodes:
                        walker.walk(block)
                    for offset, value in walker.read_counter.items():
                        self.read_counter[offset] += value
                    for offset, value in walker.write_counter.items():
                        self.write_counter[offset] += value
                    for offset, value in walker.condition_counter.items():
                        self.condition_counter[offset] += value

    def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None):
        self._handle_call(stmt)
        super()._handle_Call(stmt_idx, stmt, block)

    def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
        self._handle_call(expr)
        super()._handle_CallExpr(expr_idx, expr, stmt_idx, stmt, block)

    @property
    def scores(self):
        scores = defaultdict(int)
        for offset, value in self.read_counter.items():
            scores[offset] += value
        for offset, value in self.write_counter.items():
            scores[offset] += value
        for offset, value in self.condition_counter.items():
            scores[offset] += value * 2
        return scores

    @property
    def rankings(self):
        scores = self.scores
        return sorted(scores.keys(), key=lambda ele: scores[ele], reverse=True)


class StructFieldsMatcher:

    def __init__(self, project):
        self.project = project
        self._handlers = {RustSimTypeArrayRef: self._match_ArrayReference, RustSimTypeOption: self._match_Option}

    def _get_field_exprs_between(self, field_exprs, start_offset, end_offset):
        result = {}
        for offset in field_exprs:
            if start_offset <= offset < end_offset:
                result[offset - start_offset] = field_exprs[offset]
        return result

    def _match_Option(self, single_field_exprs, field_ty):
        if 0 in single_field_exprs:
            expr = single_field_exprs[0]
            if isinstance(expr, Const) and expr.value == 0:
                return True
        return False

    def _match_ArrayReference(self, single_field_exprs, field_ty: RustSimTypeArrayRef):
        if len(single_field_exprs) == 2 and 0 in single_field_exprs and self.project.arch.bytes in single_field_exprs:
            ptr_expr = single_field_exprs[0]
            len_expr = single_field_exprs[self.project.arch.bytes]
            if isinstance(field_ty.ele_ty, RustSimTypeStrRef):
                if (
                    isinstance(ptr_expr, Const)
                    and isinstance(len_expr, Const)
                    and extract_str_from_addr(self.project, ptr_expr.value) is not None
                ):
                    return True
                return False
            else:
                return True
        return False

    def _match_field(self, single_field_exprs, field_ty):
        handler = self._handlers.get(field_ty.__class__, None)
        if handler:
            return handler(single_field_exprs, field_ty)
        return False

    def match_fields(self, field_exprs, struct_ty: RustSimStruct) -> Optional[RustSimStruct]:
        """
        Match field expressions with the field types in a struct type
        Return the new struct type with recovered memory layout
        """
        cur_offset = 0
        pending_fields = list(struct_ty.fields.items())
        failed_fields = []
        final_fields = OrderedDict()
        while pending_fields:
            field_name, field_ty = pending_fields.pop(0)
            field_size = field_ty.size // self.project.arch.bytes
            single_field_exprs = self._get_field_exprs_between(field_exprs, cur_offset, cur_offset + field_size)
            if self._match_field(single_field_exprs, field_ty):
                final_fields[field_name] = field_ty
                pending_fields = failed_fields + pending_fields
                failed_fields = []
                cur_offset += field_size
            else:
                failed_fields.append((field_name, field_ty))
        if failed_fields:
            return None
        new_struct_ty = struct_ty.copy()
        new_struct_ty.fields = final_fields
        return new_struct_ty


# Structs targeted by StructMemoryLayoutAnalysis and the default RustSimStructs
TARGET_STRUCT_TYPES = {"Arguments"}


class StructMemoryLayoutAnalysis(Analysis, CFAMixin, DFAMixin):
    """
    Unlike C/C++, the order of Rust struct fields is not guaranteed to be the same as the order in source code.
    According to our observation, struct field reordering is very common.
    This analysis aims to recover the memory layouts (field orders) of Rust standard library structs.
    """

    def __init__(self, max_attempts_per_struct=5):
        CFAMixin.__init__(self, None, self.project)
        DFAMixin.__init__(self, None)
        self.max_attempts_per_struct = max_attempts_per_struct
        self.cfg = self.kb.cfgs.get_most_accurate()
        self._analyze()

    def _recover_layout_from_callsites(self, caller_func, callee_func, struct_ty, arg_idx):
        clinic = self.project.analyses.Clinic(caller_func, cfg=self.cfg)
        struct_ty = struct_ty.with_arch(self.project.arch)
        self.graph = clinic.graph
        for block in clinic.graph.nodes:
            call = self.terminal_call(block)
            if (
                call
                and isinstance(call.target, Const)
                and call.target.value == callee_func.addr
                and call.args
                and len(call.args) > arg_idx
            ):
                arg_vvar = unwrap_stack_vvar_reference(call.args[arg_idx])
                stack_defs = self.collect_callsite_stack_defs(block)
                field_exprs = {}
                for offset, stack_def in stack_defs.items():
                    if offset - arg_vvar.stack_offset < struct_ty.size // 8:
                        field_exprs[offset - arg_vvar.stack_offset] = stack_def.data
                result = StructFieldsMatcher(self.project).match_fields(field_exprs, struct_ty)
                if result:
                    return result
        return None

    def _get_callers_and_callees(self, callee_name):
        result = set()
        for addr in self.kb.functions:
            func = self.kb.functions[addr]
            if func.demangled_name == callee_name:
                for pred in list(self.cfg.graph.predecessors(self.cfg.get_node(func.addr))):
                    if pred.function_address in self.kb.functions:
                        caller = self.kb.functions[pred.function_address]
                        result.add((caller, func))
        return result

    def _analyze(self):
        """
        Methodology:
        1) Traverse the pre-defined Rust standard library function prototypes;
        2) If this prototype has a struct argument type that is targeted by this analysis, go to 3);
        3) Find the caller functions of this function, find the callsites to the target function;
        4) Analyze how the struct is constructed in callsite and infer the correct order of struct fields
        """
        attempts = defaultdict(int)
        for func_name, prototype in generate_known_rust_prototypes(self.project).items():
            for arg_idx, arg_ty in enumerate(prototype.args):
                if isinstance(arg_ty, RustSimTypeReference) and isinstance(arg_ty.pts_to, RustSimStruct):
                    struct_ty = arg_ty.pts_to
                    struct_name = struct_ty.name
                    if (
                        struct_name in TARGET_STRUCT_TYPES
                        and attempts[struct_name] < self.max_attempts_per_struct
                        and not self.project.kb.known_structs.is_calibrated(struct_name)
                    ):
                        callers_and_callees = self._get_callers_and_callees(func_name)
                        while (
                            callers_and_callees
                            and attempts[struct_name] < self.max_attempts_per_struct
                            and not self.project.kb.known_structs.is_calibrated(struct_name)
                        ):
                            caller, callee = callers_and_callees.pop()
                            recovered_struct_ty = self._recover_layout_from_callsites(
                                caller, callee, struct_ty, arg_idx
                            )
                            if recovered_struct_ty:
                                self.kb.known_structs[struct_name] = recovered_struct_ty.with_arch(self.project.arch)
                                l.debug(
                                    f"Recovered struct memory layout for {struct_name}: {recovered_struct_ty.fields}"
                                )
                            attempts[struct_name] += 1
        for struct_name in TARGET_STRUCT_TYPES:
            # Fall back to default memory layout if analysis failed for this struct
            if not self.project.kb.known_structs.is_calibrated(struct_name):
                l.debug(f"Failed to recover struct memory layout for {struct_name}. Use default layout")

        # Regenerate Rust standard library function prototypes with recovered struct types
        self.kb.librust.regenerate()
        #
        # functions = defaultdict(list)
        # for addr in self.kb.functions:
        #     func = self.kb.functions[addr]
        #     functions[normalize(func.demangled_name, monopolize=True, use_trait_name=True)].append(func)
        # targets = []
        # for name, prototype in generate_known_rust_prototypes(self.project).items():
        #     for func in functions[name]:
        #         for arg_idx, arg_ty in enumerate(prototype.args):
        #             # if (
        #             #     isinstance(arg_ty, RustSimTypeReference)
        #             #     and isinstance(arg_ty.pts_to, RustSimStruct)
        #             #     and arg_ty.pts_to.name == "Arguments"
        #             # ):
        #             if isinstance(arg_ty, RustSimTypeReference) and isinstance(arg_ty.pts_to, RustSimTypeString):
        #                 targets.append((func, arg_idx))
        #
        # # addr_list = [(0x451AF0, 0), (0x451CC0, 0), (0x451D20, 0), (0x451A30, 0), (0x431ED0, 1)]
        # walker = ReferenceCounter(0, self.project)
        # for func, arg_idx in targets:
        #     # func = self.kb.functions[addr]
        #     clinic = self.project.analyses.Clinic(func, cfg=self.cfg, optimization_passes=[])
        #     walker.arg_idx = arg_idx
        #     # sta = self.project.analyses.SimpleTaintAnalysis(
        #     #     clinic.graph, SimpleTaintAnalysis.get_clinic_arg_vvars(clinic), ["free"]
        #     # )
        #     for block in clinic.graph.nodes:
        #         walker.walk(block)
        # import ipdb
        #
        # ipdb.set_trace()


AnalysesHub.register_default("StructMemoryLayout", StructMemoryLayoutAnalysis)
