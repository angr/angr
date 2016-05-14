from .explorer import Explorer
import simuvex

class Callable(object):
    """
    Callable is a representation of a function in the binary that can be
    interacted with like a native python function.

    If you set perform_merge=True (the default), the result will be returned to you, and
    you can get the result state with callable.result_state.

    Otherwise, you can get the resulting path group (immutable) at callable.result_path_group.
    """

    def __init__(self, project, addr, concrete_only=False, perform_merge=True, base_state=None, toc=None, cc=None):
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
        self._cc = cc if cc is not None else simuvex.DefaultCC[project.arch.name](project.arch)
        self._deadend_addr = project._simos.return_deadend

        self.result_path_group = None
        self.result_state = None

    def set_base_state(self, state):
        """
        Swap out the state you'd like to use to perform the call
        :param state: The state to use to perform the call
        """
        self._base_state = state

    def __call__(self, *args):
        self.perform_call(*args)
        if self.result_state is not None:
            return self.result_state.se.simplify(self._cc.get_return_val(self.result_state, stack_base=self.result_state.regs.sp - self._cc.STACKARG_SP_DIFF))
        else:
            return None

    def perform_call(self, *args):
        state = self._project.factory.call_state(self._addr, *args,
                    cc=self._cc,
                    base_state=self._base_state,
                    ret_addr=self._deadend_addr,
                    toc=self._toc)

        def step_func(pg):
            pg2 = pg.prune()
            if len(pg2.active) > 1:
                raise AngrCallableMultistateError("Execution split on symbolic condition!")
            return pg2

        caller = self._project.factory.path_group(state, immutable=True)
        caller_end_unpruned = caller.step(until=lambda pg: len(pg.active) == 0, step_func=step_func if self._concrete_only else None).unstash(from_stash='deadended')
        caller_end_unmerged = caller_end_unpruned.prune(filter_func=lambda pt: pt.addr == self._deadend_addr)

        if len(caller_end_unmerged.active) == 0:
            raise AngrCallableError("No paths returned from function")

        self.result_path_group = caller_end_unmerged

        if self._perform_merge:
            caller_end = caller_end_unmerged.merge()
            self.result_state = caller_end.active[0].state

class Caller(Explorer):
    """
    Caller is a surveyor that executes functions to see what they do.
    """

    def __init__(self, project, addr, args=(), start=None, num_find=None, concrete_only=False, **kwargs):
        """
        :param project:         the project
        :param addr:            the address to start calling at
        :param args:            a tuple of arguments. Any members that are None will be replaced with symbolic expressions with a
                                length of the architecture's bitwidth.
        :param start:           a path (or set of paths) to start from
        :param num_find:        find at least this many returns from the function
        :param concrete_only:   Throw an exception if the execution splits into multiple paths
        """

        self._fake_return_addr = project.entry
        self._cc = simuvex.DefaultCC[project.arch.name](project.arch)
        self._concrete_only = concrete_only

        start_paths = [ ]
        if start is None:
            start_paths.append(project.factory.path(project.factory.blank_state(addr=addr)))
        elif isinstance(start, (tuple,list,set)):
            start_paths.extend(start)
        else:
            start_paths.append(start)

        self.symbolic_args = [ start_paths[0].state.se.Unconstrained('arg%d'%i, project.arch.bits) if arg is None else arg for i, arg in enumerate(args) ]
        self._ret_addr = start_paths[0].state.se.BVV(self._fake_return_addr, project.arch.bits)

        for p in start_paths:
            p.state.ip = addr
            self._cc.setup_callsite(p.state, self._ret_addr, self.symbolic_args)

        super(Caller, self).__init__(project, find=self._fake_return_addr, start=start_paths, num_find=num_find, **kwargs)

    def post_tick(self):
        if not self._concrete_only: return
        if len(self.active) > 1:
            toomany = self.active
            self.active = []
            for path in toomany:
                if path.state.satisfiable():
                    self.active.append(path)
                else:
                    self.errored.append(path)
            if len(self.active) > 1:
                raise AngrCallableMultistateError("Execution produced multiple successors")

    def map_se(self, func, *args, **kwargs):
        """
        Maps the state.se."func" function for all the return address states. This is a generator.

        :param func: the function name, used as getattr(p.state.se, func). Normally any_n_int or any_n_str
        :param runs: the maximum number of runs to execute
        :param solutions: check only returns with this value as a possible solution
        :param sort: sort the result before yielding it

        Other *args and **kwargs are passed to the called state.se.* function.

        yields (r, func_return) for each state.
        """

        runs = kwargs.pop('runs', None)
        solution = kwargs.pop('solution', None)
        extra_constraints = kwargs.pop('extra_constraints', ())
        sort = kwargs.pop('sort', True)
        for r,p in self.iter_returns(runs=runs, solution=solution):
            v = getattr(p.state.se, func)(*args, extra_constraints=extra_constraints + (r==solution,), **kwargs)
            yield r, sorted(v) if sort else v

    def map_func(self, func, runs=None, solution=None):
        """
        Calls func(return_value, args_tuple, path) for each function return. This is a generator.

        :param func: the function to call
        :param runs: the maximum number of runs to execute
        :param solutions: check only returns with this value as a possible solution

        yields the return values of func
        """
        for r,p in self.iter_returns(runs=runs, solution=solution):
            yield func(r, self.symbolic_args, p)

    def iter_returns(self, runs=None, solution=None):
        """
        Yields (return_value, path) for every return. This is a generator.

        :param runs: the maximum number of runs to execute
        :param solutions: check only returns with this value as a possible solution
        """
        for p in self.iter_found(runs=runs):
            r = p.state.se.simplify(self._cc.return_val.get_value(p.state))
            if solution is not None and not p.state.se.solution(r, solution):
                continue
            yield (r, p)
    __iter__ = iter_returns

from ..errors import AngrCallableError, AngrCallableMultistateError
from . import all_surveyors
all_surveyors['Caller'] = Caller
