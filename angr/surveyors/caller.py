from .explorer import Explorer
import simuvex, claripy

class Callable(object):
    '''
    Callable is a representation of a function in the binary that can be
    interacted with like a native python function.
    '''

    def __init__(self, project, addr, prototype, base_state=None, toc=None):
        '''
        Creates a Callable.

        @arg project: the project to operate with
        @arg addr: the address of the function to use
        @arg prototype: a SimTypeFunction instance describing the functions args and return type
        @arg base_state: the state from which to do these runs
        @arg toc: the address of the table of contents for ppc64
        '''

        if not isinstance(prototype, simuvex.s_type.SimTypeFunction):
            raise ValueError("Prototype must be a function!")

        self._project = project
        self._ty = prototype
        self._addr = addr
        self.base_state = base_state
        self._toc = toc
        self._caller = None

    def call_get_return_val(self, *args):
        return self._get_call_results(*args)[0]
    __call__ = call_get_return_val

    def call_get_res_state(self, *args):
        return self._get_call_results(*args)[1].state

    def _get_call_results(self, *args):
        wantlen = len(self._ty.args)
        if len(args) != wantlen:
            raise TypeError("The function at {:#x} takes exactly {} argument{} ({} given)"\
                    .format(self._addr, wantlen, '' if wantlen == 1 else 's', len(args)))

        state = self.base_state.copy() \
                    if self.base_state is not None \
                    else self._project.factory.blank_state()

        if state.arch.name == 'PPC64' and self._toc is not None:
            state.regs.r2 = self._toc
        pointed_args = [self._standardize_value(arg, ty, state) for arg, ty in zip(args, self._ty.args)]
        self._caller = Caller(self._project, self._addr, pointed_args, concrete_only=True, start=self._project.factory.path(state))

        out = None
        for res in self._caller:
            if out is not None:
                raise AngrCallableMultistateError("Got more than one return value")
            out = res
        if out is None:
            raise AngrCallableError("No paths returned from function")
        return out

    def _standardize_value(self, arg, ty, state):
        if isinstance(arg, Callable.PointerWrapper):
            if not isinstance(ty, simuvex.s_type.SimTypePointer):
                raise TypeError("Type mismatch: expected {}, got pointer-wrapper".format(ty))
            real_value = self._standardize_value(arg.value, ty.pts_to, state)
            return self._push_value(real_value, state)
        elif isinstance(arg, str):
            if not isinstance(ty, simuvex.s_type.SimTypePointer) or \
               not isinstance(ty.pts_to, simuvex.s_type.SimTypeChar):
                raise TypeError("Type mismatch: Expected {}, got char*".format(ty))
            return self._standardize_value(map(ord, arg+'\0'), ty, state)
        elif isinstance(arg, list):
            if not isinstance(ty, simuvex.s_type.SimTypePointer):
                raise TypeError("Type mismatch: expected {}, got list".format(ty))
            types = map(type, arg)
            if types[1:] != types[:-1]:
                raise TypeError("All elements of list must be of same type")
            pointed_args = [self._standardize_value(sarg, ty.pts_to, state) for sarg in arg]
            for sarg in reversed(pointed_args):
                out = self._push_value(sarg, state)
            return out
        elif isinstance(arg, (int, long)):
            return state.BVV(arg, ty.size)
        elif isinstance(arg, claripy.A):
            return arg

    @staticmethod
    def _push_value(val, state):
        sp = state.regs.sp - val.size() / 8
        state.regs.sp = sp
        state.memory.store(sp, val, endness=state.arch.memory_endness)
        return sp

    class PointerWrapper(object):
        def __init__(self, value):
            self.value = value


class Caller(Explorer):
    '''
    Caller is a surveyor that executes functions to see what they do.
    '''

    def __init__(self, project, addr, args=(), start=None, num_find=None, concrete_only=False, **kwargs):
        '''
        Creates a Caller.

        @arg project: the project
        @arg addr: the address to start calling at
        @arg args: a tuple of arguments. Any members that are None will be replaced with
         arg     symbolic expressions with a length of the architecture's bitwidth
        @arg start: a path (or set of paths) to start from
        @arg num_find: find at least this many returns from the function
        @arg concrete_only: Throw an exception if the execution splits into multiple paths
        '''

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

from ..errors import AngrCallableError, AngrCallableMultistateError
from . import all_surveyors
all_surveyors['Caller'] = Caller
