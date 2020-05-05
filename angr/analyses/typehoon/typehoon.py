
from typing import List, Set, Optional

from ..analysis import Analysis, AnalysesHub
from .simple_solver import SimpleSolver
from .translator import TypeTranslator
from .typeconsts import Struct, Pointer, TypeConstant, Array


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
    def __init__(self, constraints, ground_truth=None):

        self._constraints = constraints
        self._ground_truth = ground_truth

        self.solution = None
        self.structs = None
        self.simtypes_solution = None

        # import pprint
        # pprint.pprint(self._constraints)
        self._analyze()
        # pprint.pprint(self.solution)

    #
    # Public methods
    #

    def update_variable_types(self, func_addr, var_to_typevar):

        for var, typevar in var_to_typevar.items():
            type_ = self.simtypes_solution.get(typevar, None)
            if type_ is not None:
                # print("{} -> {}: {}".format(var, typevar, type_))
                self.kb.variables[func_addr].types[var] = type_

    #
    # Private methods
    #

    def _analyze(self):

        self._solve()
        self._specialize()
        self._translate_to_simtypes()

    def _solve(self):
        solver = SimpleSolver(self._constraints)
        self.solution = solver.solution

    def _specialize(self):
        """
        Heuristics to make types more natural and more readable.

        - structs where every element is of the same type will be converted to an array of that element type.
        """

        for tv in list(self.solution.keys()):
            sol = self.solution[tv]
            specialized = self._specialize_struct(sol)
            if specialized is not None:
                self.solution[tv] = specialized

    def _specialize_struct(self, tc, memo: Optional[Set]=None):

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

            # are all fields the same?
            if len(tc.fields) > 1 and all(tc.fields[off] == field0 for off in offsets):
                # are all fields aligned properly?
                alignment = field0.size
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

        simtypes_solution = { }
        translator = TypeTranslator(arch=self.project.arch)
        needs_backpatch = set()

        for tv, sol in self.solution.items():
            simtypes_solution[tv], has_nonexistent_ref = translator.translate(sol)

            if has_nonexistent_ref:
                needs_backpatch.add(tv)

        # back patch
        for tv in needs_backpatch:
            translator.backpatch(simtypes_solution[tv], simtypes_solution)

        self.simtypes_solution = simtypes_solution
        self.structs = translator.structs


AnalysesHub.register_default("Typehoon", Typehoon)
