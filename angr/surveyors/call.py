from .explorer import Explorer
import simuvex

class Call(Explorer):
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

        for p in start_paths:
            ret_addr = p.state.se.BVV(self._fake_return_addr, p.state.arch.bits)
            self._cc.setup_callsite(p.state, ret_addr, args)

        super(Call, self).__init__(project, find=self._fake_return_addr, start=start_paths, num_find=num_find, **kwargs)

    def iter_returns(self, runs=None):
        for p in self.iter_found(runs=runs):
            r = self._cc.get_return_expr(p.state)
            yield (r, p)
    __iter__ = iter_returns

from . import all_surveyors
all_surveyors['Call'] = Call
