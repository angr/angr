from ..analysis import Analysis
from ..variableseekr import StackVariable

class OFlow(Analysis):
    __dependencies__ = [ 'CFGAnalysis', 'VSA' ]

    def __init__(self):
        # this is a dict of the overflow results, keyed by function address
        self.oflows = { }

        cfg = self._deps[0].cfg
        seeker = self._deps[1].seeker

        for addr in cfg.function_manager.functions:
            with self._resilience():
                var_mgr = seeker.get_variable_manager(addr)

                if var_mgr is None:
                    continue

                for v in var_mgr.variables:
                    if isinstance(v, StackVariable):
                        print v.detail_str()
                    else:
                        print "%s(%d),  referenced at %08x"%(v, v._size, v._inst_addr)
