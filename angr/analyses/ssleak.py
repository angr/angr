from ..analysis import Analysis
from ..variableseekr import StackVariable
import logging

l = logging.getLogger("StackLeak")
class StackLeak(Analysis):
    """
    Statically identify functions accessing uninitialized stack variables, and
    those variables
    """
    __name__ = "SLEAK"
    __dependencies__ = [ 'VSA' ]


    def __init__(self, entries=[]):
        """
        @entries: list of entry points of functions you want to analyze.
        """

        vsa = self._deps[0]
        #vfg = vsa.vfg
        cfg = vsa._cfg
        seeker = vsa.seeker
        fm = cfg.function_manager


        if len(entries) == 0:
            # Defaults to all functions
            l.warning("No functions entry points provided. Will scan for all functions")
            fcts = fm.functions
        else:
            fcts = {}
            # Get functions with matching entry points from functionmanager
            for i in entries:
                for k,v in fm.functions:
                    if k == i:
                        fcts[k] = v

        # Get variables
        for e in fcts.keys():
            #with self._resilience():
            seeker.construct(func_start=e)

            for func_addr, func in fm.functions.items():
                print "Function 0x%x" % func_addr
                variable_manager = seeker.get_variable_manager(func_addr)
                if variable_manager is None:
                    print "No variable manager for function @ 0x%x" % func_addr
                    continue
                # TODO: Check the result returned
                print "Variables: "
                for var in variable_manager.variables:
                    if isinstance(var, StackVariable):
                        print var.detail_str()
                    else:
                        print "%s(%d),  referenced at %08x", var, var._size, var._inst_addr
