from .explorer import Explorer
from ..calling_conventions import DEFAULT_CC


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
        self._cc = DEFAULT_CC[project.arch.name](project.arch)
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

        :param func: the function name, used as getattr(p.state.se, func). Normally eval_upto or any_n_str
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

from ..errors import AngrCallableMultistateError
from . import all_surveyors
all_surveyors['Caller'] = Caller
