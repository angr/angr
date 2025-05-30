import itertools
import logging
from collections import OrderedDict, defaultdict
from typing import List
import sys

from angr.ailment import Const, AILBlockWalkerBase, Block, Statement
from angr.ailment.expression import Load, VirtualVariable
from angr.ailment.statement import Store, ConditionalJump, Call
from angr.rust.definitions.features import struct_features
from angr.rust.definitions.prototypes import generate_known_rust_prototypes
from angr.rust.utils.ail import extract_vvar_and_offset
from angr.rust.mixins import CFAMixin, DFAMixin
from angr.rust.sim_type import RustSimStruct, RustSimTypeReference
from angr.analyses import Analysis, AnalysesHub

l = logging.getLogger(name=__name__)


class FeatureCollector(AILBlockWalkerBase):

    def __init__(self, project, depth=0):
        super().__init__()
        self.project = project
        self.depth = depth

        self.arg_idx = None
        self.feature = {
            "reads": defaultdict(int),
            "writes": defaultdict(int),
            "cond_uses": defaultdict(int),
        }

    @staticmethod
    def _resolve_struct_field(struct_ty: RustSimStruct, offset, path=None):
        if path is None:
            path = [struct_ty.name]
        offsets = struct_ty.offsets
        for field_name, field_ty in struct_ty.fields.items():
            field_offset = offsets[field_name]
            if offset >= field_offset and offset < field_offset + field_ty.size // 8:
                if offset == field_offset and not isinstance(field_ty, RustSimStruct):
                    return ".".join(path + [field_name])
                elif isinstance(field_ty, RustSimStruct):
                    return FeatureCollector._resolve_struct_field(field_ty, offset - field_offset, path + [field_name])
                return None
        return None

    def _handle_Store(self, stmt_idx: int, stmt: Store, block: Block | None):
        vvar, offset = extract_vvar_and_offset(stmt.addr)
        if vvar and vvar.was_parameter and vvar.varid == self.arg_idx:
            self.feature["writes"][offset] += 1
        super()._handle_Store(stmt_idx, stmt, block)

    def _handle_Load(self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement, block: Block | None):
        vvar, offset = extract_vvar_and_offset(expr.addr)
        if vvar and vvar.was_parameter and vvar.varid == self.arg_idx:
            self.feature["reads"][offset] += 1
            if isinstance(stmt, ConditionalJump):
                self.feature["cond_uses"][offset] += 1
        super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_call(self, call):
        if self.depth >= 5:
            return
        if isinstance(call.target, Const) and call.target.value in self.project.kb.functions:
            func = self.project.kb.functions[call.target.value]
            for arg_idx, arg in enumerate(call.args or []):
                if isinstance(arg, VirtualVariable) and arg.was_parameter and arg.varid == self.arg_idx:
                    clinic = self.project.kb.clinic_factory.get(func)
                    walker = FeatureCollector(self.project, self.depth + 1)
                    walker.process(arg_idx, clinic.graph)
                    for tag in walker.feature:
                        sub_feature = walker.feature[tag]
                        for offset, value in sub_feature.items():
                            self.feature[tag][offset] += value

    def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None):
        self._handle_call(stmt)
        super()._handle_Call(stmt_idx, stmt, block)

    def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement, block: Block | None):
        self._handle_call(expr)
        super()._handle_CallExpr(expr_idx, expr, stmt_idx, stmt, block)

    def get_feature(self, struct_ty):
        _offset_path_mappings = {}

        def _offset_to_path(offset):
            if offset in _offset_path_mappings:
                return _offset_path_mappings[offset]
            path = self._resolve_struct_field(struct_ty, offset)
            _offset_path_mappings[offset] = path
            return path

        new_feature = {}
        for tag, sub_feature in self.feature.items():
            new_sub_feature = {}
            for offset, value in sub_feature.items():
                path = _offset_to_path(offset)
                if path:
                    new_sub_feature[path] = value
            new_feature[tag] = new_sub_feature
        return new_feature

    def process(self, arg_idx, graph):
        self.arg_idx = arg_idx
        for block in graph.nodes:
            self.walk(block)


TARGET_STRUCT_TYPES = {"alloc::string::String"}


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

        self._demangled_name_to_func = {}
        for func_addr in self.kb.functions:
            func = self.kb.functions[func_addr]
            self._demangled_name_to_func[func.demangled_name] = func

        self._related_prototypes = defaultdict(list)
        for func_name, prototype in generate_known_rust_prototypes(self.project).items():
            if func_name in self._demangled_name_to_func:
                func = self._demangled_name_to_func[func_name]
                for arg_idx, arg_ty in enumerate(prototype.args):
                    if isinstance(arg_ty, RustSimTypeReference) and isinstance(arg_ty.pts_to, RustSimStruct):
                        struct_ty = arg_ty.pts_to
                        struct_name = struct_ty.name
                        if struct_name in TARGET_STRUCT_TYPES:
                            self._related_prototypes[struct_name].append((func, arg_idx, prototype))

        self._permutation_memo = {}

        self._analyze()

    def _permutate_fields(self, struct_ty: RustSimStruct) -> List[RustSimStruct]:
        if struct_ty.name in self._permutation_memo:
            return self._permutation_memo[struct_ty.name]

        candidates = []

        # Keep the original order of zero-sized fields
        zero_sized_fields = []
        fields = []
        for field_idx, (field_name, field_ty) in enumerate(struct_ty.fields.items()):
            if field_ty.size == 0:
                zero_sized_fields.append((field_idx, field_name, field_ty))
            else:
                fields.append((field_name, field_ty))
        for permuted_fields in itertools.permutations(fields):
            # Recursively permutate field types
            derived_permutations = [[]]
            for field_name, field_ty in permuted_fields:
                if isinstance(field_ty, RustSimStruct):
                    variant_field_types = self._permutate_fields(field_ty)
                    tmp = []
                    for permutation in derived_permutations:
                        for variant_field_ty in variant_field_types:
                            tmp.append(permutation + [(field_name, variant_field_ty)])
                    derived_permutations = tmp
                else:
                    for permutation in derived_permutations:
                        permutation.append((field_name, field_ty))

            for permutation in derived_permutations:
                # Insert ZSTs back
                for field_idx, field_name, field_ty in zero_sized_fields:
                    permutation.insert(field_idx, (field_name, field_ty))
                new_struct_ty = struct_ty.copy()
                new_struct_ty.fields = OrderedDict(permutation)
                candidates.append(new_struct_ty)

        self._permutation_memo[struct_ty.name] = candidates
        return candidates

    def _edit_distance(self, feature, another_feature):
        edit_distance = 0
        for tag in feature.keys():
            sub_feature = feature[tag]
            another_sub_feature = another_feature[tag]
            combined_keys = set(sub_feature.keys()) | set(another_sub_feature.keys())
            for key in combined_keys:
                edit_distance += abs(sub_feature.get(key, 0) - another_sub_feature.get(key, 0))
        return edit_distance

    def _analyze(self):
        for target_struct_name in TARGET_STRUCT_TYPES:
            struct_ty = self.project.kb.known_structs[target_struct_name].with_arch(self.project.arch)
            feature_collector = FeatureCollector(self.project)
            for func, arg_idx, prototype in self._related_prototypes[target_struct_name][
                : self.max_attempts_per_struct
            ]:
                clinic = self.project.kb.clinic_factory.get(func)
                feature_collector.process(arg_idx, clinic.graph)
            candidates = self._permutate_fields(struct_ty)
            best_candidate, min_edit_distance = struct_ty, sys.maxsize
            ground_truth = struct_features[target_struct_name]
            for candidate in candidates:
                feature = feature_collector.get_feature(candidate)
                edit_distance = self._edit_distance(feature, ground_truth)
                if edit_distance < min_edit_distance:
                    min_edit_distance = edit_distance
                    # TODO: Update best_candidate
            self.project.kb.known_structs[struct_ty.name] = best_candidate

        self.kb.librust.regenerate()


AnalysesHub.register_default("StructMemoryLayout", StructMemoryLayoutAnalysis)
