
from ..analysis import Analysis, AnalysesHub
from ..forward_analysis import ForwardAnalysis, FunctionGraphVisitor


class TypeState:
    """
    The abstract state used during analysis in Typehoon.
    """
    def __init__(self, addr, arch):
        self._addr = addr
        self.arch = arch
        self.constraints = set()

    def add_constraints(self, *constraints):

        for constraint in constraints:
            self.constraints.add(constraint)


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

        self._analyze()

    def _analyze(self):

        self._simplify()

    def _simplify(self):
        print(self._constraints)


AnalysesHub.register_default("Typehoon", Typehoon)
