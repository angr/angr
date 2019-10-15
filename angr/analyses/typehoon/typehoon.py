
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


class Typehoon(ForwardAnalysis, Analysis):
    """
    A spiritual tribute to the long-standing typehoon project that @jmg (John Grosen) worked on during his days in the
    angr team. Now I feel really bad of asking the poor guy to work directly on VEX IR without any fancy static analysis
    support as we have right now...
    """
    def __init__(self, func, clinic=None, ground_truth=None):

        self._graph_visitor = FunctionGraphVisitor(func)

        ForwardAnalysis.__init__(self, order_jobs=True, allow_merging=True, graph_visitor=self._graph_visitor)

        self._func = func
        self._clinic = clinic
        self._ground_truth = ground_truth

        self._analyze()

    @property
    def _use_ail(self):
        return self._clinic is not None

    def _to_ailblock(self, node):
        return self._clinic.block(node.addr, node.size)

    def _to_block(self, node):
        return self.project.factory.block(node.addr, size=node.size)

    #
    # Handlers
    #

    def _pre_analysis(self):
        pass

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass

    def _initial_abstract_state(self, node):
        return TypeState(node.addr, self.project.arch)

    def _run_on_node(self, node, state):
        raise NotImplementedError()


AnalysesHub.register_default("Typehoon", Typehoon)
