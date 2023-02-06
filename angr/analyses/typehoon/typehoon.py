from typing import List, Set, Optional, Dict, Union, TYPE_CHECKING

from ...sim_type import SimStruct, SimTypePointer, SimTypeArray
from ..analysis import Analysis, AnalysesHub
from .simple_solver import SimpleSolver
from .translator import TypeTranslator
from .typeconsts import Struct, Pointer, TypeConstant, Array
from .typevars import Equivalence

if TYPE_CHECKING:
    from angr.sim_variable import SimVariable
    from angr.sim_type import SimType
    from .typevars import TypeVariable, TypeConstraint


class Typehoon(Analysis):
    """
    A spiritual tribute to the long-standing typehoon project that @jmg (John Grosen) worked on during his days in the
    angr team. Now I feel really bad of asking the poor guy to work directly on VEX IR without any fancy static analysis
    support as we have right now...

    Typehoon analysis implements a pushdown system that simplifies and solves type constraints. Our type constraints are
    largely an implementation of the paper Polymorphic Type Inference for Machine Code by Noonan, Loginov, and Cok from
    GrammaTech (with missing functionality support and bugs, of course). Type constraints are collected by running
    VariableRecoveryFast (maybe VariableRecovery later as well) on a function, and then solved using this analysis.

    User may specify ground truth, which will override all types at certain program points during constraint solving.
    """

    def __init__(
        self,
        constraints,
        ground_truth=None,
        var_mapping: Optional[Dict["SimVariable", Set["TypeVariable"]]] = None,
        must_struct: Optional[Set["TypeVariable"]] = None,
    ):
        """

        :param constraints:
        :param ground_truth:        A set of SimType-style solutions for some or all type variables. They will be
                                    respected during type solving.
        :param var_mapping:
        :param must_struct:
        """

        self._constraints: Set["TypeConstraint"] = constraints
        self._ground_truth: Optional[Dict["TypeVariable", "SimType"]] = ground_truth
        self._var_mapping = var_mapping  # variable mapping is only used for debugging purposes
        self._must_struct = must_struct

        self.bits = self.project.arch.bits
        self.solution = None
        self.structs = None
        self.simtypes_solution = None

        # import pprint
        # pprint.pprint(self._var_mapping)
        # pprint.pprint(self._constraints)
        self._analyze()
        # pprint.pprint(self.solution)

    #
    # Public methods
    #

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

                    self.kb.variables[func_addr].set_variable_type(var, type_, name=name)

    def pp_constraints(self) -> None:
        """
        Pretty-print constraints between *variables* using the variable mapping.
        """
        if self._var_mapping is None:
            raise ValueError("Variable mapping does not exist.")

        typevar_to_var = {}
        for k, typevars in self._var_mapping.items():
            for tv in typevars:
                typevar_to_var[tv] = k

        print(f"### {len(self._constraints)} constraints")
        for constraint in self._constraints:
            print("    " + constraint.pp_str(typevar_to_var))
        print("### end of constraints ###")

    def pp_solution(self) -> None:
        """
        Pretty-print solutions using the variable mapping.
        """
        if self._var_mapping is None:
            raise ValueError("Variable mapping does not exist.")
        if self.solution is None:
            raise RuntimeError("Please run type solver before calling pp_solution().")

        typevar_to_var = {}
        for k, typevars in self._var_mapping.items():
            for tv in typevars:
                typevar_to_var[tv] = k

        print(f"### {len(self.solution)} solutions")
        for typevar in sorted(self.solution.keys(), key=str):
            sol = self.solution[typevar]
            print(f"    {typevar_to_var.get(typevar, typevar)} -> {sol}")
        print("### end of solutions ###")

    #
    # Private methods
    #

    def _analyze(self):
        # convert ground truth into constraints
        if self._ground_truth:
            translator = TypeTranslator(arch=self.project.arch)
            for tv, sim_type in self._ground_truth.items():
                self._constraints.add(Equivalence(tv, translator.simtype2tc(sim_type)))

        self._solve()
        self._specialize()
        self._translate_to_simtypes()

        # apply ground truth
        if self._ground_truth and self.simtypes_solution is not None:
            self.simtypes_solution.update(self._ground_truth)

    def _solve(self):
        solver = SimpleSolver(self.bits, self._constraints)
        self.solution = solver.solution

    def _specialize(self):
        """
        Heuristics to make types more natural and more readable.

        - structs where every element is of the same type will be converted to an array of that element type.
        """

        for tv in list(self.solution.keys()):
            if self._must_struct and tv in self._must_struct:
                continue
            sol = self.solution[tv]
            specialized = self._specialize_struct(sol)
            if specialized is not None:
                self.solution[tv] = specialized

    def _specialize_struct(self, tc, memo: Optional[Set] = None):
        if isinstance(tc, Pointer):
            if memo is not None and tc in memo:
                return None
            specialized = self._specialize_struct(tc.basetype, memo={tc} if memo is None else memo | {tc})
            if specialized is None:
                return None
            return tc.new(specialized)

        if isinstance(tc, Struct) and tc.fields:
            offsets: List[int] = sorted(list(tc.fields.keys()))  # get a sorted list of offsets
            offset0 = offsets[0]
            field0: TypeConstant = tc.fields[offset0]

            if len(tc.fields) == 1 and 0 in tc.fields:
                return field0

            # are all fields the same?
            if len(tc.fields) > 1 and all(tc.fields[off] == field0 for off in offsets):
                # are all fields aligned properly?
                try:
                    alignment = field0.size
                except NotImplementedError:
                    alignment = 1
                if all(off % alignment == 0 for off in offsets):
                    # yeah!
                    max_offset = offsets[-1]
                    count = (max_offset + field0.size) // alignment
                    return Array(field0, count=count)

        return None

    def _translate_to_simtypes(self):
        """
        Translate solutions in type variables to solutions in SimTypes.
        """

        simtypes_solution = {}
        translator = TypeTranslator(arch=self.project.arch)
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


AnalysesHub.register_default("Typehoon", Typehoon)
