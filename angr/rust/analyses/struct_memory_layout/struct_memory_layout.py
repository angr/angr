import itertools
import logging
from collections import defaultdict, OrderedDict
from typing import List, Generator, Tuple

from angr.rust.analyses.struct_memory_layout.constraint_collector import ConstraintCollector
from angr.rust.definitions.prototypes import generate_known_rust_prototypes
from angr.rust.mixins import CFAMixin, DFAMixin
from angr.rust.sim_type import RustSimStruct, RustSimTypeReference, RustSimType
from angr.analyses import Analysis, AnalysesHub


l = logging.getLogger(__name__)


class StructMemoryLayoutAnalysis(Analysis, CFAMixin, DFAMixin):
    """
    Unlike C/C++, the order of Rust struct fields is not guaranteed to be the same as the order in source code.
    According to our observation, struct field reordering is very common.
    This analysis aims to recover the memory layouts (field orders) of Rust standard library structs.
    """

    def __init__(self, max_analyzing_functions=10, max_struct_size=48, struct_prefixes=("std::", "alloc::", "core::")):
        CFAMixin.__init__(self, None, self.project)
        DFAMixin.__init__(self, None)
        self.max_analyzing_functions = max_analyzing_functions
        self.max_struct_size = max_struct_size
        self.struct_prefixes = struct_prefixes
        self.cfg = self.kb.cfgs.get_most_accurate()

        self._demangled_name_to_func = {}
        for func_addr in self.kb.functions:
            func = self.kb.functions[func_addr]
            self._demangled_name_to_func[func.demangled_name] = func

        self._struct_ty_uses = defaultdict(list)
        for func_name, prototype in generate_known_rust_prototypes(self.project).items():
            if func_name in self._demangled_name_to_func:
                func = self._demangled_name_to_func[func_name]
                for arg_idx, arg_ty in enumerate(prototype.args):
                    if isinstance(arg_ty, RustSimTypeReference) and isinstance(arg_ty.pts_to, RustSimStruct):
                        struct_ty = arg_ty.pts_to
                        struct_name = struct_ty.name
                        self._struct_ty_uses[struct_name].append((func, arg_idx, prototype))

        self._permutation_memo = {}

        self._analyze()

    @staticmethod
    def _calibrate_arg_idx(prototype, arg_idx, clinic):
        size = 0
        for arg_ty in prototype.args[:arg_idx]:
            size += arg_ty.size
        cur_size = 0
        for i, (vvar, _) in enumerate(clinic.arg_vvars.values()):
            if cur_size == size:
                return i
            cur_size += vvar.bits
        return arg_idx

    def _permutate_fields(self, fields) -> Generator[List[Tuple[str, RustSimType]]]:
        # Keep the original order of zero-sized fields
        zero_sized_fields = []
        sized_fields = []
        for field_idx, (field_name, field_ty) in enumerate(fields):
            if field_ty.size == 0:
                zero_sized_fields.append((field_idx, field_name, field_ty))
            else:
                sized_fields.append((field_name, field_ty))

        if len(sized_fields) == 0:
            yield []
            return

        fields = sized_fields

        def insert_zsts(no_zsts_fields):
            new_fields = list(no_zsts_fields)
            for field_idx, field_name, field_ty in zero_sized_fields:
                new_fields.insert(field_idx, (field_name, field_ty))
            return new_fields

        for i, (field_name, field_ty) in enumerate(fields):
            other_fields = fields[:i] + fields[i + 1 :]
            if isinstance(field_ty, RustSimStruct):
                for new_field_ty in self._permutate_struct_types(field_ty):
                    for permutation in self._permutate_fields(other_fields):
                        yield insert_zsts([(field_name, new_field_ty)] + permutation)
            else:
                for permutation in self._permutate_fields(other_fields):
                    yield insert_zsts([(field_name, field_ty)] + permutation)

    def _permutate_struct_types(self, struct_ty: RustSimStruct) -> Generator[RustSimStruct]:
        for fields in self._permutate_fields(list(struct_ty.fields.items())):
            new_struct_ty = struct_ty.copy()
            new_struct_ty.fields = OrderedDict(fields)
            yield new_struct_ty

    def _find_compatible_struct_ty(self, struct_ty: RustSimStruct, constraints):
        candidates = self._permutate_struct_types(struct_ty)
        for candidate in candidates:
            if all(constraint.satisfy(candidate) for constraint in constraints):
                return candidate
        return None

    def _analyze(self):
        for target_struct_name in self._struct_ty_uses.keys():
            if not any(target_struct_name.startswith(prefix) for prefix in self.struct_prefixes):
                continue
            struct_ty = self.project.kb.known_structs[target_struct_name].with_arch(self.project.arch)
            if struct_ty.size > self.max_struct_size * 8:
                continue
            l.debug(f"Try recovering memory layout for {struct_ty.repr(full=10)}")
            collector = ConstraintCollector()
            for func, arg_idx, prototype in self._struct_ty_uses[target_struct_name][: self.max_analyzing_functions]:
                prototype = prototype.with_arch(self.project.arch)
                clinic = self.project.kb.clinic_factory.get(func)
                if clinic:
                    # Calibrate arg_idx
                    # TODO: This is just a workaround
                    arg_idx = self._calibrate_arg_idx(prototype, arg_idx, clinic)
                    if arg_idx in clinic.arg_vvars:
                        arg_vvar = clinic.arg_vvars[arg_idx][0]
                        collector.collect(clinic, arg_vvar)
            constraints = collector.constraints
            l.debug(f"Collected {constraints}")
            compatible_struct_ty = self._find_compatible_struct_ty(struct_ty, constraints)
            if compatible_struct_ty is None:
                l.error(f"Failed to recover struct memory layout for {struct_ty}")
                compatible_struct_ty = struct_ty
            l.debug(f"Recovered struct memory layout for {struct_ty}")
            l.debug(compatible_struct_ty.repr(full=10))
            self.project.kb.known_structs[target_struct_name] = compatible_struct_ty

        self.project.kb.librust.regenerate()


AnalysesHub.register_default("StructMemoryLayout", StructMemoryLayoutAnalysis)
