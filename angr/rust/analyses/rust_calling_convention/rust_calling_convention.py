import logging
import traceback
from typing import Tuple, List
from collections import OrderedDict

from angr.analyses.decompiler.clinic import ClinicStage
from angr.calling_conventions import default_cc
from angr.ailment import Const
from angr.ailment.block import Block
from angr.ailment.expression import VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Call
from angr.analyses import Analysis, AnalysesHub
from angr.knowledge_plugins.functions import Function
from angr.rust.optimization_passes.cleanup_code_remover import CleanupCodeRemover
from angr.rust.optimization_passes.utils import extract_str_from_addr
from angr.rust.sim_type import (
    RustSimEnum,
    RustSimTypeOption,
    RustSimTypeResult,
    RustSimType,
    RustSimTypeUnit,
    RustSimTypeInt,
    RustSimTypeReference,
    RustSimStruct,
    RustSimTypeFunction,
    RustSimTypeStrRef,
    EnumVariant,
)
from angr.rust.typehoon.translator import RustTypeTranslator
from angr.rust.utils.ail import CallVisitor
from angr.rust.utils.demangler import normalize, demangle

from .fact_collector import FactCollector
from .rust_calling_convention_model import RustCallingConventionModel

l = logging.getLogger(name=__name__)


class RustCallingConventionAnalysis(Analysis):
    """
    Infer function prototype including struct return type and struct argument types.

    Function prototype is inferred based on collected facts from the callee
    function body and the caller function body.

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
        callsite_path=None,
        post_callsite_path=None,
        is_call_expr=None,
        depth=0,
        max_depth=8,
    ):
        self.func: Function = func
        self.callsite_path = callsite_path
        self.post_callsite_path = post_callsite_path
        self.is_call_expr = is_call_expr
        self.depth = depth
        self.max_depth = max_depth
        self.graph = None

        self.calling_convention = func.calling_convention or default_cc(self.project.arch.name)(self.project.arch)

        self._fact_collector: FactCollector | None = None

        if self.func.addr in self.kb.rust_calling_conventions:
            self.model = self.kb.rust_calling_conventions[self.func.addr]
            return

        self.model = RustCallingConventionModel()

        if self.depth > self.max_depth:
            return

        if self.func.normalized and self.func.size:
            try:
                # cfg = self.kb.cfgs.get_most_accurate()
                # clinic = self.project.analyses.Clinic(
                #     self.func,
                #     cfg=cfg,
                #     optimization_passes=[CleanupCodeRemover],
                # )
                clinic = self.project.kb.clinic_factory.get(
                    self.func, optimization_passes=[CleanupCodeRemover], end_stage=ClinicStage.POST_CALLSITES
                )
                self.graph = clinic.graph
            except Exception as e:
                l.error(f"Failed to recover AIL graph for {normalize(self.func.name)}")
                l.error("".join(traceback.format_exception(e)))

        if self.graph:
            self._fact_collector = FactCollector(self)
            try:
                self._analyze()
            except Exception as e:
                l.error(f"Rust calling convention analysis failed for {normalize(self.func.name)}")
                l.error("".join(traceback.format_exception(e)))

    # -- properties ----------------------------------------------------------

    @property
    def prototype(self):
        return self.model.inferred_prototype

    # -- core ----------------------------------------------------------------

    def _analyze(self):
        self._fact_collector.collect()
        self.model.inferred_prototype = self._infer_prototype()
        self.kb.rust_calling_conventions[self.func.addr] = self.model
        l.debug(f"Analysis result for {demangle(self.func.name)} (addr: {hex(self.func.addr)}): {self.model}")

    # -- prototype inference -------------------------------------------------

    def _infer_prototype(self):
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

    def _infer_return_type(self) -> Tuple[RustSimType | None, bool]:
        # The first argument is not used as return buffer
        if (
            len(self.model.callsite_memory_writes[0]) != 0
            or not self.model.has_write_to_arg0
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
            candidates.append(struct_ty)

        final_ty = sorted(candidates, key=lambda candidate: candidate.size, reverse=True)[0] if candidates else None

        # Filter out register-size structs
        if final_ty and final_ty.size <= self.project.arch.bits:
            return None

        if final_ty:
            final_ty = RustSimTypeReference(final_ty).with_arch(self.project.arch)

        return final_ty

    def _infer_combo_arg_types(self, arg_types):
        """
        Infer argument types for consecutive register arguments that are likely
        to be used as a combo (e.g., slice types).
        """
        fc = self._fact_collector
        combo_arg_types = {}

        def callback(call: Call, block, stmt, is_expr):
            i = 0
            while i + 1 < len(call.args):
                arg = call.args[i]
                next_arg = call.args[i + 1]
                if isinstance(arg, VirtualVariable) and isinstance(next_arg, VirtualVariable):
                    arg = fc.get_terminal_vvar(arg) or arg
                    next_arg = fc.get_terminal_vvar(next_arg) or next_arg
                    if (
                        arg.was_parameter
                        and arg.parameter_category == VirtualVariableCategory.REGISTER
                        and next_arg.was_parameter
                        and next_arg.parameter_category == VirtualVariableCategory.REGISTER
                        and next_arg.varid - arg.varid == 1
                    ):
                        arg_ty = self._arg_idx_to_arg_ty(i, call)
                        if isinstance(arg_ty, RustSimType) and arg_ty.size == self.project.arch.bits * 2:
                            combo_arg_types[arg.varid] = arg_ty
                            i += 1
                i += 1

        visitor = CallVisitor(callback)
        visitor.visit(self.graph)

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

    @staticmethod
    def _arg_idx_to_arg_ty(arg_idx, call: Call):
        if call.prototype and call.calling_convention and call.args:
            arg_offset = 0
            for i in range(arg_idx):
                arg = call.args[i]
                arg_offset += arg.bits
            cur_offset = 0
            for arg_ty in call.prototype.args:
                if cur_offset == arg_offset:
                    return arg_ty
                cur_offset += arg_ty.size
                if cur_offset > arg_offset:
                    break
        return None

    # -- enum inference ------------------------------------------------------

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
        if len(candidates_and_paths) <= 1:
            return None

        # Deduplicate candidates by (size, discriminant value)
        candidates_and_discriminants = []
        visited = set()
        for (candidate, discriminant), path in candidates_and_paths:
            key = (candidate.size, discriminant.value if discriminant else None)
            if key not in visited:
                visited.add(key)
                candidates_and_discriminants.append((candidate, discriminant))
        candidates_and_discriminants = tuple(sorted(candidates_and_discriminants, key=lambda item: item[0].size))

        if len(candidates_and_discriminants) == 2:
            discriminants = list(discriminant for _, discriminant in candidates_and_discriminants)
            discriminant_sizes = set(discriminant.bits for discriminant in discriminants if discriminant is not None)
            if len(discriminant_sizes) == 1:
                discriminant_size = next(iter(discriminant_sizes))
                candidate_sizes = sorted(set(candidate.size for candidate, _ in candidates_and_discriminants))
                overlapping_discriminant = None in discriminants
                if candidate_sizes[0] == discriminant_size:
                    # Option<T> or Result<(), E>
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
                        # Heuristics: Maybe it's a Result<(), E>
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
                    # Result<T, E> with both discriminants known
                    struct_type_and_discriminant = tuple(
                        sorted(candidates_and_discriminants, key=lambda item: item[1].value)
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
                    # Result<T, E> with one discriminant missing (T is larger, discriminant omitted)
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
            if len(structs_by_size) == 2:
                small_type, large_type = sorted(structs_by_size.values(), key=lambda ty: ty.size)
                return RustSimTypeResult(
                    ok_type=large_type,
                    ok_discriminant=None,
                    ok_discriminant_size=0,
                    err_type=small_type,
                    err_discriminant=None,
                    err_discriminant_size=0,
                )
            elif (
                len(structs_by_size) > 2
                and min(structs_by_size) > 16 * self.project.arch.byte_width
                and not all(discriminant is None for _, discriminant in candidates_and_discriminants)
            ):
                variants = []
                for candidate, discriminant in candidates_and_discriminants:
                    variant_name = f"variant{candidate.size // self.project.arch.byte_width}"
                    variants.append(
                        EnumVariant(
                            name=variant_name, fields=[(candidate, None)], discriminant=None, discriminant_size=0
                        )
                    )
                return RustSimEnum(f"enum{max(structs_by_size) // self.project.arch.byte_width}", variants).with_arch(
                    self.project.arch
                )

        return None


AnalysesHub.register_default("RustCallingConvention", RustCallingConventionAnalysis)
