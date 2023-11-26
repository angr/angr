from typing import Set, Optional, Dict, Union, TYPE_CHECKING

from ..typehoon import Typehoon
from ...analysis import AnalysesHub
from ..rust.translator import RustTypeTranslator
from ..rust.sim_type import RustSimTypeInt
from angr.sim_type import SimTypePointer, SimTypeArray, SimStruct, SimTypeBottom

if TYPE_CHECKING:
    from angr.sim_variable import SimVariable
    from angr.sim_type import SimType
    from ..typevars import TypeVariable, TypeConstraint


class RustTypehoon(Typehoon):
    def __init__(
        self,
        constraints,
        ground_truth=None,
        var_mapping: Optional[Dict["SimVariable", Set["TypeVariable"]]] = None,
        must_struct: Optional[Set["TypeVariable"]] = None,
    ):
        super().__init__(constraints, ground_truth, var_mapping, must_struct)

    def update_variable_types(self, func_addr: Union[int, str], var_to_typevars):
        for var, typevars in var_to_typevars.items():
            for typevar in typevars:
                type_ = self.simtypes_solution.get(typevar, None)
                if type_ is not None:
                    # print("{} -> {}: {}".format(var, typevar, type_))
                    # Hack: if a global address is of a pointer type and it is not an array, we unpack the type
                    if (
                        func_addr == "global"
                        and isinstance(type_, SimTypePointer)
                        and not isinstance(type_.pts_to, SimTypeArray)
                    ):
                        type_ = type_.pts_to

                    name = None
                    if isinstance(type_, SimStruct):
                        name = type_.name

                    if isinstance(type_, SimTypeBottom) and var.size is not None:
                        type_ = RustSimTypeInt(signed=False, size=var.size * self.project.arch.byte_width)

                    self.kb.variables[func_addr].set_variable_type(var, type_, name=name)

    def _translate_to_simtypes(self):
        """
        Translate solutions in type variables to solutions in SimTypes.
        """

        simtypes_solution = {}
        translator = RustTypeTranslator(arch=self.project.arch)
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


AnalysesHub.register_default("RustTypehoon", RustTypehoon)
