from collections import defaultdict
from typing import Set, Optional, Dict, Union, TYPE_CHECKING

from ...analyses.typehoon.typehoon import Typehoon
from ...analyses.analysis import AnalysesHub
from ..typehoon.translator import RustTypeTranslator
from ..sim_type import RustSimTypeInt
from ...sim_type import SimTypePointer, SimTypeArray, SimStruct, SimTypeBottom
from ...analyses.typehoon.typevars import TypeVariable
from ...sim_variable import SimVariable, SimStackVariable

if TYPE_CHECKING:
    from angr.sim_type import SimType
    from angr.analyses.typehoon.typevars import TypeConstraint


class RustTypehoon(Typehoon):
    def __init__(
        self,
        constraints,
        func_var,
        ground_truth=None,
        var_mapping: Optional[Dict["SimVariable", Set["TypeVariable"]]] = None,
        must_struct: Optional[Set["TypeVariable"]] = None,
        stackvar_max_sizes: dict[TypeVariable, int] | None = None,
        stack_offset_tvs: dict[int, TypeVariable] | None = None,
        constraint_set_degradation_threshold: int = 150,
    ):
        super().__init__(
            constraints,
            func_var,
            ground_truth,
            var_mapping,
            must_struct,
            stackvar_max_sizes,
            stack_offset_tvs,
            constraint_set_degradation_threshold,
        )

    def update_variable_types(
        self,
        func_addr: int | str,
        var_to_typevars: dict[SimVariable, set[TypeVariable]],
        stack_offset_tvs: dict[int, TypeVariable] | None = None,
    ) -> None:

        if not self.simtypes_solution:
            return

        for var, typevars in var_to_typevars.items():
            # if the variable is a stack variable, does the stack offset have any corresponding type variable?
            typevars_list = sorted(typevars, key=lambda tv: tv.idx)
            if stack_offset_tvs and isinstance(var, SimStackVariable) and var.offset in stack_offset_tvs:
                typevars_list.append(stack_offset_tvs[var.offset])

            type_candidates: list[SimType] = []
            for typevar in typevars_list:
                type_ = self.simtypes_solution.get(typevar, None)
                # print("{} -> {}: {}".format(var, typevar, type_))
                # Hack: if a global address is of a pointer type and it is not an array, we unpack the type
                if (
                    func_addr == "global"
                    and isinstance(type_, SimTypePointer)
                    and not isinstance(type_.pts_to, SimTypeArray)
                ):
                    type_ = type_.pts_to
                # FIXME: Why type_ is None?
                if type_:
                    type_candidates.append(type_)

            # determine the best type - this logic can be made better!
            if not type_candidates:
                continue
            if len(type_candidates) > 1:
                types_by_size: dict[int, list[SimType]] = defaultdict(list)
                for t in type_candidates:
                    t = t.with_arch(self.project.arch)
                    if t.size is not None:
                        types_by_size[t.size].append(t)
                if not types_by_size:
                    # we only have BOT and TOP? damn
                    the_type = type_candidates[0]
                else:
                    max_size = max(types_by_size.keys())
                    the_type = types_by_size[max_size][0]  # TODO: Sort it
            else:
                the_type = type_candidates[0]

            if isinstance(the_type, SimTypeBottom) and var.size is not None:
                the_type = RustSimTypeInt(signed=False, size=var.size * self.project.arch.byte_width)

            self.kb.variables[func_addr].set_variable_type(
                var, the_type, name=the_type.name if isinstance(the_type, SimStruct) else None
            )

    def _translate_to_simtypes(self):
        """
        Translate solutions in type variables to solutions in SimTypes.
        """

        simtypes_solution = {}
        translator = RustTypeTranslator(project=self.project, arch=self.project.arch)
        needs_backpatch = set()

        for tv, sol in self.solution.items():
            simtypes_solution[tv], has_nonexistent_ref = translator.tc2simtype(sol)
            if has_nonexistent_ref:
                needs_backpatch.add(tv)

        # back patch
        for tv in needs_backpatch:
            translator.backpatch(simtypes_solution[tv], simtypes_solution)

        self.simtypes_solution = simtypes_solution
        self.structs = translator.structs

    def _specialize_struct(self, tc, memo: set | None = None):
        return None


AnalysesHub.register_default("RustTypehoon", RustTypehoon)
