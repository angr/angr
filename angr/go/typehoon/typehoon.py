from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

from angr.analyses.analysis import AnalysesHub
from angr.analyses.typehoon.typehoon import Typehoon
from angr.analyses.typehoon.typevars import TypeVariable, TypeVariableManager
from angr.go.sim_type import GoSimStruct, GoSimTypeInt
from angr.go.typehoon.translator import GoTypeTranslator
from angr.sim_type import SimStruct, SimTypeArray, SimTypeBottom, SimTypePointer
from angr.sim_variable import SimStackVariable, SimVariable

if TYPE_CHECKING:
    from angr.sim_type import SimType


class GoTypehoon(Typehoon):
    """Go-aware type inference engine: solutions come back as Go SimTypes."""

    def __init__(
        self,
        constraints,
        func_var,
        ground_truth=None,
        var_mapping: dict[SimVariable, set[TypeVariable]] | None = None,
        must_struct: set[TypeVariable] | None = None,
        stackvar_max_sizes: dict[TypeVariable, int] | None = None,
        stack_offset_tvs: dict[int, TypeVariable] | None = None,
        constraint_set_degradation_threshold: int = 150,
        type_translator: GoTypeTranslator | None = None,
        tv_manager: TypeVariableManager | None = None,
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
            type_translator=(type_translator if type_translator is not None else GoTypeTranslator(self.project.arch)),
            tv_manager=tv_manager,
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
            typevars_list = sorted(typevars, key=lambda tv: tv.idx)
            if stack_offset_tvs and isinstance(var, SimStackVariable) and var.offset in stack_offset_tvs:
                typevars_list.append(stack_offset_tvs[var.offset])

            type_candidates: list[SimType] = []
            for typevar in typevars_list:
                type_ = self.simtypes_solution.get(typevar, None)
                if (
                    func_addr == "global"
                    and isinstance(type_, SimTypePointer)
                    and not isinstance(type_.pts_to, SimTypeArray)
                ):
                    type_ = type_.pts_to
                if type_ is not None:
                    type_candidates.append(type_)
            if not type_candidates:
                continue

            type_candidates = [t.with_arch(self.project.arch) for t in type_candidates]
            if len(type_candidates) > 1:
                types_by_size: dict[int, list[SimType]] = defaultdict(list)
                for t in type_candidates:
                    if t.size is not None:
                        types_by_size[t.size].append(t)
                the_type = type_candidates[0] if not types_by_size else types_by_size[max(types_by_size)][0]
            else:
                the_type = type_candidates[0]

            if isinstance(the_type, SimTypeBottom) and var.size is not None:
                the_type = GoSimTypeInt(var.size * self.project.arch.byte_width, signed=False).with_arch(
                    self.project.arch
                )

            if func_addr != "global":
                the_type = self._flatten_pointer_to_array(the_type, self.project.arch)

            name = the_type.name if isinstance(the_type, SimStruct) and not isinstance(the_type, GoSimStruct) else None
            self.kb.variables[func_addr].set_variable_type(var, the_type, name=name)


AnalysesHub.register_default("GoTypehoon", GoTypehoon)
