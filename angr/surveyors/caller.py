from .explorer import Explorer
import simuvex

class Caller(Explorer):
    def __init__(self, project, addr, args=(), start=None, num_find=None, **kwargs):
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

    def iter_returns(self, runs=None):
        for p in self.iter_found(runs=runs):
            r = self._cc.get_return_expr(p.state)
            yield (r, p)
    __iter__ = iter_returns

from . import all_surveyors
all_surveyors['Caller'] = Caller
