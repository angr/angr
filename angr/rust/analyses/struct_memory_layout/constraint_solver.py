import itertools
import logging
from collections import OrderedDict, Counter
from typing import List, Dict

from z3 import *

from angr.rust.analyses.struct_memory_layout.constraints import Constraint, IsNotConstraint, IsConstraint
from angr.rust.sim_type import RustSimStruct, RustSimEnum, RustSimTypeOption, RustSimTypeResult
from angr.rust.knowledge_plugins.known_structs import TypeWalker

l = logging.getLogger(__name__)


class ConstraintSolver:

    def __init__(self, max_permutations=120):
        self.max_permutations = max_permutations

        self.context = Context()
        self._solver = Optimize(ctx=self.context)

        self._struct_vars = {}
        self._struct_candidates: Dict[str, List[RustSimStruct]] = {}
        self._struct_perm_vals: Dict[str, List[DatatypeRef]] = {}

        self._constrained_structs = set()

    def _generate_z3_constraints(self, struct_ty, constraint: Constraint):
        var = self._struct_vars[struct_ty.name]
        candidates = self._struct_candidates[struct_ty.name]
        perm_vals = self._struct_perm_vals[struct_ty.name]
        z3_constraints_and_weights = []
        for candidate, perm_val in zip(candidates, perm_vals):
            for field_name, field_offset in candidate.offsets.items():
                field_ty = candidate.fields[field_name]
                field_size = field_ty.size
                # Skip ZSTs
                if field_size == 0:
                    continue
                if field_offset <= constraint.offset < field_offset + field_size / 8:
                    if isinstance(constraint, IsNotConstraint):
                        if constraint.offset == field_offset and type(field_ty) is constraint.ty_cls:
                            z3_constraints_and_weights.append((Not(var == perm_val, ctx=self.context), 1))
                        elif isinstance(field_ty, RustSimStruct):
                            new_constraint = IsNotConstraint(
                                constraint.offset - field_offset, constraint.size, constraint.ty_cls
                            )
                            for z3_constraint, weight in self._generate_z3_constraints(field_ty, new_constraint):
                                z3_constraint = Implies(var == perm_val, z3_constraint, ctx=self.context)
                                z3_constraints_and_weights.append((z3_constraint, weight))
                    elif isinstance(constraint, IsConstraint):
                        if not isinstance(field_ty, (RustSimStruct, RustSimEnum)):
                            if type(field_ty) is not constraint.ty_cls:
                                z3_constraints_and_weights.append((Not(var == perm_val), 20))
                        elif isinstance(field_ty, RustSimStruct):
                            new_constraint = IsConstraint(
                                constraint.offset - field_offset, constraint.size, constraint.ty_cls
                            )
                            for z3_constraint, weight in self._generate_z3_constraints(field_ty, new_constraint):
                                z3_constraint = Implies(var == perm_val, z3_constraint)
                                z3_constraints_and_weights.append((z3_constraint, weight))
        return z3_constraints_and_weights

    def _add_offset_cost_objective(self):
        total_cost_terms = []

        for struct_name, var in self._struct_vars.items():
            if struct_name not in self._constrained_structs:
                continue
            candidates = self._struct_candidates[struct_name]
            perm_vals = self._struct_perm_vals[struct_name]
            original = candidates[0]

            original_offsets = original.offsets  # field_name → offset

            for i, candidate in enumerate(candidates):
                candidate_offsets = candidate.offsets
                cost = 0
                for field_name, new_offset in candidate_offsets.items():
                    if field_name not in original_offsets:
                        continue  # unlikely
                    original_offset = original_offsets[field_name]
                    field_ty = candidate.fields[field_name]
                    field_size = field_ty.size
                    # offset diff in bytes, field size also in bytes
                    cost += field_size * abs(new_offset - original_offset)
                term = If(var == perm_vals[i], cost, 0, ctx=self.context)
                total_cost_terms.append(term)

        self._solver.minimize(Sum(total_cost_terms))

    def _permute_fields(self, fields):
        zero_sized_fields = []
        sized_fields = []
        for field_idx, (field_name, field_ty) in enumerate(fields):
            if field_ty.size == 0:
                zero_sized_fields.append((field_idx, field_name, field_ty))
            else:
                sized_fields.append((field_name, field_ty))
        fields = sized_fields
        for perm in itertools.permutations(fields):
            new_fields = list(perm)
            for field_idx, field_name, field_ty in zero_sized_fields:
                new_fields.insert(field_idx, (field_name, field_ty))
            yield new_fields

    def _constrain_struct_ty(self, struct_ty: RustSimStruct, constraints: List[Constraint]):
        name = struct_ty.name
        if len(constraints):
            self._constrained_structs.add(name)
        candidates = []
        for fields in self._permute_fields(list(struct_ty.fields.items())):
            candidate = struct_ty.copy()
            candidate.fields = OrderedDict(fields)
            candidates.append(candidate)
            if len(candidates) >= self.max_permutations:
                break
        sort, perm_vals = EnumSort(f"{name}_perm", [f"{name}_p{i}" for i in range(len(candidates))], ctx=self.context)
        var = Const(name, sort)
        self._struct_vars[name] = var
        self._struct_candidates[name] = candidates
        self._struct_perm_vals[name] = perm_vals
        for constraint, weight in Counter(constraints).items():
            z3_constraints_and_weights = self._generate_z3_constraints(struct_ty, constraint)
            for z3_constraint, z3_weight in z3_constraints_and_weights:
                self._solver.add_soft(z3_constraint, weight=weight * z3_weight)

    def _populate_solution(self, struct_types: List[RustSimStruct | RustSimEnum]):
        assert self._solver.check() == sat
        model = self._solver.model()
        solution = OrderedDict()

        def _update(ty):
            return solution[ty.name]

        updater = TypeWalker(
            handlers={
                RustSimStruct: _update,
                RustSimEnum: _update,
                RustSimTypeOption: _update,
                RustSimTypeResult: _update,
            }
        )

        for struct_ty in struct_types:
            struct_var = self._struct_vars.get(struct_ty.name, None)
            if struct_var is not None:
                struct_perm_val = model[struct_var]
                if struct_perm_val is not None:
                    candidate_idx = self._struct_perm_vals[struct_ty.name].index(struct_perm_val)
                    struct_ty = self._struct_candidates[struct_ty.name][candidate_idx]
            struct_ty = updater.walk_fields(struct_ty)
            solution[struct_ty.name] = struct_ty

        return solution

    def solve(self, struct_types: List[RustSimStruct | RustSimEnum], constraints: Dict[str, List[Constraint]]):
        for idx, struct_ty in enumerate(struct_types):
            if isinstance(struct_ty, RustSimStruct):
                self._constrain_struct_ty(struct_ty, constraints[struct_ty.name])
        # Observation: Field order after compilation is usually close to its original order
        # Thus we want to minimize the difference
        self._add_offset_cost_objective()
        return self._populate_solution(struct_types)
