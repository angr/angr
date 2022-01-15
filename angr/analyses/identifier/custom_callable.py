
import logging

from ...errors import AngrCallableError, AngrCallableMultistateError
from ...calling_conventions import DEFAULT_CC


l = logging.getLogger(name=__name__)
# l.setLevel("DEBUG")


class IdentifierCallable(object):
    """
    Callable is a representation of a function in the binary that can be
    interacted with like a native python function.

    If you set perform_merge=True (the default), the result will be returned to you, and
    you can get the result state with callable.result_state.

    Otherwise, you can get the resulting path group (immutable) at callable.result_path_group.
    """

    def __init__(self, project, addr, concrete_only=False, perform_merge=False, base_state=None, toc=None, cc=None,
                 max_steps=None):
        """
        :param project:         The project to operate on
        :param addr:            The address of the function to use

        The following parameters are optional:

        :param concrete_only:   Throw an exception if the execution splits into multiple paths
        :param perform_merge:   Merge all result states into one at the end (only relevant if concrete_only=False)
        :param base_state:      The state from which to do these runs
        :param toc:             The address of the table of contents for ppc64
        :param cc:              The SimCC to use for a calling convention
        """

        self._project = project
        self._addr = addr
        self._concrete_only = concrete_only
        self._perform_merge = perform_merge
        self._base_state = base_state
        self._toc = toc
        self._caller = None
        self._cc = cc if cc is not None else DEFAULT_CC[project.arch.name](project.arch)
        self._deadend_addr = project.simos.return_deadend
        self._max_steps = max_steps

        self.result_path_group = None
        self.result_state = None

    def set_base_state(self, state):
        """
        Swap out the state you'd like to use to perform the call
        :param state: The state to use to perform the call
        """
        self._base_state = state

    def __call__(self, *args):
        prototype = self._cc.guess_prototype(args)
        self.perform_call(*args, prototype=prototype)
        if self.result_state is not None:
            loc = self._cc.return_val(prototype.returnty)
            return self.result_state.solver.simplify(loc.get_value(self.result_state, stack_base=self.result_state.regs.sp - self._cc.STACKARG_SP_DIFF))
        return None

    def get_base_state(self, *args):
        prototype = self._cc.guess_prototype(args)
        self._base_state.ip = self._addr
        state = self._project.factory.call_state(self._addr, *args,
                    prototype=prototype,
                    cc=self._cc,
                    base_state=self._base_state,
                    ret_addr=self._deadend_addr,
                    toc=self._toc)
        return state

    def perform_call(self, *args, prototype=None):
        if prototype is None:
            prototype = self._cc.guess_prototype(args)
        self._base_state.ip = self._addr
        state = self._project.factory.call_state(self._addr, *args,
                    cc=self._cc,
                    prototype=prototype,
                    base_state=self._base_state,
                    ret_addr=self._deadend_addr,
                    toc=self._toc)

        def step_func(pg):
            pg2 = pg.prune()
            if len(pg2.active) > 1:
                raise AngrCallableMultistateError("Execution split on symbolic condition!")
            return pg2

        caller = self._project.factory.simulation_manager(state)
        for _ in range(self._max_steps):
            if len(caller.active) == 0:
                break
            if caller.active[0].history.block_count > 100000:
                l.debug("super long path %s", caller.active[0])
                raise AngrCallableError("Super long path")
            caller.step(step_func=step_func if self._concrete_only else None)
        if len(caller.active) > 0:
            raise AngrCallableError("didn't make it to the end of the function")

        caller.unstash(from_stash='deadended')
        caller.prune(filter_func=lambda pt: pt.addr == self._deadend_addr)

        if len(caller.active) == 0:
            raise AngrCallableError("No paths returned from function")

        self.result_path_group = caller.copy()

        if self._perform_merge:
            caller.merge()
        self.result_state = caller.active[0]
