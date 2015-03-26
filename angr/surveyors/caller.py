from .explorer import Explorer
import simuvex

class Caller(Explorer):
    '''
    Caller is a surveyor that executes functions to see what they do.
    '''

    def __init__(self, project, addr, args=(), start=None, num_find=None, **kwargs):
        '''
        Creates a Caller.

        @arg project: the project
        @arg addr: the address to start calling at
        @arg args: a tuple of arguments. Any members that are None will be replaced with
         arg     symbolic expressions with a length of the architecture's bitwidth
        @arg start: a path (or set of paths) to start from
        @arg num_find: find at least this many returns from the function
        '''

        self._fake_return_addr = project.entry
        self._cc = simuvex.DefaultCC[project.arch.name](project.arch)

        start_paths = [ ]
        if start is None:
            start_paths.append(project.path_generator.blank_path(address=addr))
        elif isinstance(start, (tuple,list,set)):
            start_paths.extend(start)
        else:
            start_paths.append(start)

        # this is a bit of a hack to get the arg values
        throwaway = project.state_generator.blank_state()
        self._cc.set_args(throwaway, [ throwaway.se.Unconstrained('arg%d'%i, throwaway.arch.bits) if a is None else a for i,a in enumerate(args) ])
        self.symbolic_args = [ self._cc.arg(throwaway, i) for i,_ in enumerate(args) ]
        self._ret_addr = throwaway.se.BVV(self._fake_return_addr, throwaway.arch.bits)

        for p in start_paths:
            self._cc.setup_callsite(p.state, self._ret_addr, self.symbolic_args)

        super(Caller, self).__init__(project, find=self._fake_return_addr, start=start_paths, num_find=num_find, **kwargs)

    def map_se(self, func, *args, **kwargs):
        '''
        Maps the state.se."func" function for all the return address states. This is a generator.

        @arg func: the function name, used as getattr(p.state.se, func). Normally any_n_int or any_n_str

        @kwarg runs: the maximum number of runs to execute
        @kwarg solutions: check only returns with this value as a possible solution
        @kwarg sort: sort the result before yielding it

        Other *args and **kwargs are passed to the called state.se.* function.

        @yields (r, func_return) for each state.
        '''

        runs = kwargs.pop('runs', None)
        solution = kwargs.pop('solution', None)
        extra_constraints = kwargs.pop('extra_constraints', ())
        sort = kwargs.pop('sort', True)
        for r,p in self.iter_returns(runs=runs, solution=solution):
            v = getattr(p.state.se, func)(*args, extra_constraints=extra_constraints + (r==solution,), **kwargs)
            yield r, sorted(v) if sort else v

    def map_func(self, func, runs=None, solution=None):
        '''
        Calls func(return_value, args_tuple, path) for each function return. This is a generator.

        @arg func: the function to call
        @kwarg runs: the maximum number of runs to execute
        @kwarg solutions: check only returns with this value as a possible solution

        @yields the return values of func
        '''
        for r,p in self.iter_returns(runs=runs, solution=solution):
            yield func(r, self.symbolic_args, p)

    def iter_returns(self, runs=None, solution=None):
        '''
        Yields (return_value, path) for every return. This is a generator.

        @kwarg runs: the maximum number of runs to execute
        @kwarg solutions: check only returns with this value as a possible solution
        '''
        for p in self.iter_found(runs=runs):
            r = p.state.se.simplify(self._cc.get_return_expr(p.state))
            if solution is not None and not p.state.se.solution(r, solution):
                continue
            yield (r, p)
    __iter__ = iter_returns

from . import all_surveyors
all_surveyors['Caller'] = Caller
