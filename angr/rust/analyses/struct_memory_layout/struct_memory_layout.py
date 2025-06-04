import logging
from collections import defaultdict
from pprint import pformat

from angr.rust.analyses.struct_memory_layout.constraint_collector import ConstraintCollector
from angr.rust.analyses.struct_memory_layout.constraint_solver import ConstraintSolver
from angr.rust.definitions.prototypes import generate_known_rust_prototypes
from angr.rust.knowledge_plugins import KnownStructs
from angr.rust.mixins import CFAMixin, DFAMixin
from angr.rust.sim_type import RustSimStruct, RustSimTypeReference
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
        self.known_structs: KnownStructs = self.project.kb.known_structs

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
                        self._struct_ty_uses[struct_ty].append((func, arg_idx, prototype))

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

    def _skip(self, struct_ty: RustSimStruct):
        return (
            not any(struct_ty.name.startswith(prefix) for prefix in self.struct_prefixes)
            or struct_ty.size > self.max_struct_size * 8
        )

    def _analyze(self):
        constraints = defaultdict(list)
        for struct_ty in self._struct_ty_uses.keys():
            if self._skip(struct_ty):
                continue
            collector = ConstraintCollector()
            for func, arg_idx, prototype in self._struct_ty_uses[struct_ty][: self.max_analyzing_functions]:
                prototype = prototype.with_arch(self.project.arch)
                clinic = self.project.kb.clinic_factory.get(func)
                if clinic:
                    # Calibrate arg_idx
                    # TODO: This is just a workaround
                    arg_idx = self._calibrate_arg_idx(prototype, arg_idx, clinic)
                    if arg_idx in clinic.arg_vvars:
                        arg_vvar = clinic.arg_vvars[arg_idx][0]
                        collector.collect(clinic, arg_vvar)
            if collector.constraints:
                constraints[struct_ty.name] = collector.constraints
            l.debug(f"Collected {pformat(collector.constraints)} for {struct_ty}")

        solution = ConstraintSolver().solve(list(self.known_structs.known_struct_types.values()), constraints)

        self.known_structs.known_struct_types.update(solution)

        self.project.kb.librust.regenerate()


AnalysesHub.register_default("StructMemoryLayout", StructMemoryLayoutAnalysis)
