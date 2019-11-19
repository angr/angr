
from ..analysis import Analysis, AnalysesHub
from .simple_solver import SimpleSolver
from .translator import TypeTranslator


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
        self.simtypes_solution = None

        self._analyze()

    #
    # Public methods
    #

    def update_variable_types(self, func_addr, var_to_typevar):

        for var, typevar in var_to_typevar.items():
            type_ = self.simtypes_solution.get(typevar, None)
            if type_ is not None:
                self.kb.variables[func_addr].types[var] = type_

    #
    # Private methods
    #

    def _analyze(self):

        self._solve()
        self._translate_to_simtypes()

    def _solve(self):
        solver = SimpleSolver(self._constraints)
        self.solution = solver.solution

    def _translate_to_simtypes(self):

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
