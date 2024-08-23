from __future__ import annotations
from . import ExplorationTechnique


class TechniqueBuilder(ExplorationTechnique):
    """
    This meta technique could be used to hook a couple of simulation manager methods
    without actually creating a new exploration technique, for example:

    class SomeComplexAnalysis(Analysis):

        def do_something():
            simgr = self.project.factory.simulation_manager()
            simgr.use_tech(ProxyTechnique(step_state=self._step_state))
            simgr.run()

        def _step_state(self, state):
            # Do stuff!
            pass

    In the above example, the _step_state method can access all the necessary stuff,
    hidden in the analysis instance, without passing that instance to a one-shot-styled
    exploration technique.
    """

    def __init__(
        self, setup=None, step_state=None, step=None, successors=None, filter=None, selector=None, complete=None
    ):
        super().__init__()
        self.setup = _its_a_func(setup) or super().setup
        self.step_state = _its_a_func(step_state) or super().step_state
        self.step = _its_a_func(step) or super().step
        self.filter = _its_a_func(filter) or super().filter
        self.successors = _its_a_func(successors) or super().successors
        self.selector = _its_a_func(selector) or super().selector
        self.complete = _its_a_func(complete) or super().complete


def _its_a_func(func):
    """
    In case the target func doesn't have it's `im_func` attr set.

    :param func:
    :return:
    """
    if func is not None:
        func.im_func = True
    return func
