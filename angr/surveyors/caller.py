from .explorer import Explorer
import simuvex, claripy

class Callable(object):
    '''
    Callable is a representation of a function in the binary that can be
    interacted with like a native python function.
    '''

    def __init__(self, project, addr, concrete_only=False, prototype=None, base_state=None, toc=None):
        '''
        :param project: the project to operate on
        :param addr: the address of the function to use
        :param concrete_only: Optional: Throw an exception if the execution splits into multiple paths
        :param prototype: Optional: A SimTypeFunction instance describing the functions args and return type
        :param base_state: Optional: The state from which to do these runs
        :param toc: Optional: The address of the table of contents for ppc64
        '''

        if prototype is not None and not isinstance(prototype, simuvex.s_type.SimTypeFunction):
            raise ValueError("Prototype must be a function!")

        self._project = project
        self._ty = prototype
        self._addr = addr
        self._concrete_only = concrete_only
        self._base_state = base_state
        self._toc = toc
        self._caller = None

        self._deadend_addr = project._extern_obj.get_pseudo_addr('FAKE_RETURN_ADDR')

    def set_base_state(self, state):
        '''
        Swap out the state you'd like to use to perform the call
        :param state: The state to use to perform the call
        '''
        self._base_state = state

    def call_get_return_val(self, *args):
        return self._get_call_results(*args)[0]
    __call__ = call_get_return_val

    def call_get_res_state(self, *args):
        return self._get_call_results(*args)[1]

    def _get_call_results(self, *args):
        cc = simuvex.DefaultCC[self._project.arch.name](self._project.arch)
        if self._ty is not None:
            wantlen = len(self._ty.args)
            if len(args) != wantlen:
                raise TypeError("The function at {:#x} takes exactly {} argument{} ({} given)"\
                        .format(self._addr, wantlen, '' if wantlen == 1 else 's', len(args)))

        state = self._base_state.copy() \
                    if self._base_state is not None \
                    else self._project.factory.blank_state()

        if state.arch.name == 'PPC64' and self._toc is not None:
            state.regs.r2 = self._toc

        if self._ty is not None:
            pointed_args = [self._standardize_value(arg, ty, state) for arg, ty in zip(args, self._ty.args)]
        else:
            pointed_args = [self._standardize_value(arg, None, state) for arg in args]

        def step_func(pg):
            pg2 = pg.prune()
            if len(pg2.active) > 1:
                raise AngrCallableMultistateError("Execution split on symbolic condition!")
            return pg2

        caller = PathGroup.call(self._project, self._addr, pointed_args, start=self._project.factory.path(state))
        caller_end_unpruned = caller.step(until=lambda pg: len(pg.active) == 0, step_func=step_func if self._concrete_only else None).unstash(from_stash='deadended')
        caller_end_unmerged = caller_end_unpruned.prune(filter_func=lambda pt: pt.addr == self._deadend_addr)

        if len(caller_end_unmerged.active) == 0:
            raise AngrCallableError("No paths returned from function")

        caller_end = caller_end_unmerged.merge()
        out_state = caller_end.active[0].state
        out_val = out_state.se.simplify(cc.get_return_expr(out_state))
        return out_val, out_state

    def _standardize_value(self, arg, ty, state):
        check = ty is not None
        if isinstance(arg, Callable.PointerWrapper):
            if check and not isinstance(ty, simuvex.s_type.SimTypePointer):
                raise TypeError("Type mismatch: expected {}, got pointer-wrapper".format(ty))
            real_value = self._standardize_value(arg.value, ty.pts_to if check else None, state)
            return self._push_value(real_value, state)
        elif isinstance(arg, str):
            if check and (not isinstance(ty, simuvex.s_type.SimTypePointer) or \
               not isinstance(ty.pts_to, simuvex.s_type.SimTypeChar)):
                raise TypeError("Type mismatch: Expected {}, got char*".format(ty))
            return self._standardize_value(map(ord, arg+'\0'), ty, state)
        elif isinstance(arg, list):
            if check and not isinstance(ty, simuvex.s_type.SimTypePointer):
                raise TypeError("Type mismatch: expected {}, got list".format(ty))
            types = map(type, arg)
            if types[1:] != types[:-1]:
                raise TypeError("All elements of list must be of same type")
            pointed_args = [self._standardize_value(sarg, ty.pts_to if check else None, state) for sarg in arg]
            for sarg in reversed(pointed_args):
                out = self._push_value(sarg, state)
            return out
        elif isinstance(arg, (int, long)):
            return state.BVV(arg, ty.size if check else state.arch.bits)
        elif isinstance(arg, claripy.Base):
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
        :param project: the project
        :param addr: the address to start calling at
        :param args: a tuple of arguments. Any members that are None will be replaced with
                     symbolic expressions with a length of the architecture's bitwidth
        :param start: a path (or set of paths) to start from
        :param num_find: find at least this many returns from the function
        :param concrete_only: Throw an exception if the execution splits into multiple paths
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

        :param func: the function name, used as getattr(p.state.se, func). Normally any_n_int or any_n_str

        :param runs: the maximum number of runs to execute
        :param solutions: check only returns with this value as a possible solution
        :param sort: sort the result before yielding it

        Other *args and **kwargs are passed to the called state.se.* function.

        yields (r, func_return) for each state.
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

        :param func: the function to call
        :param runs: the maximum number of runs to execute
        :param solutions: check only returns with this value as a possible solution

        yields the return values of func
        '''
        for r,p in self.iter_returns(runs=runs, solution=solution):
            yield func(r, self.symbolic_args, p)

    def iter_returns(self, runs=None, solution=None):
        '''
        Yields (return_value, path) for every return. This is a generator.

        :param runs: the maximum number of runs to execute
        :param solutions: check only returns with this value as a possible solution
        '''
        for p in self.iter_found(runs=runs):
            r = p.state.se.simplify(self._cc.get_return_expr(p.state))
            if solution is not None and not p.state.se.solution(r, solution):
                continue
            yield (r, p)
    __iter__ = iter_returns

from ..path_group import PathGroup
from ..errors import AngrCallableError, AngrCallableMultistateError
from . import all_surveyors
all_surveyors['Caller'] = Caller
