#from ..analysis import Analysis
#from ..variableseekr import StackVariable
from sleak import SleakMeta
from ..surveyors import Explorer
from ..analysis import register_analysis
import logging
import simuvex

l = logging.getLogger("analysis.xsleak")

class SExplorer(Explorer):
    """
    Abstract class for XSleak
    This is separated from the rest of the code to avoid multiple inheritence
    issues with Analysis
    """

    def explorer_init(self, *args, **kwargs):
        super(SExplorer, self).__init__(*args, **kwargs)
        self._last=0

    def run(self, n=None):
        """
        Readjust targets
        """
        find_addrs = tuple(self.targets.values())
        self._find = find_addrs
        return super(SExplorer, self).run(n)


    @property
    def done(self):
        """
        Overrides Explorer's done method to keep going until we find a leaking
        path (or the superclass method decides to stop for another reason).
        """
        # Only recheck if we found new paths
        if len(self.found) > self._last:
            self._last = len(self.found)
            x = self._check_path(self.found[-1])
            if x is not None:
                self.leaks.append(x)

        # Stop if we have enough paths
        if len(self.leaks) >= self.num_leaks:
                return True

        # Delegate the decision to the superclass's method
        return super(SExplorer, self).done

class XSleak(SleakMeta, SExplorer):
    """
    Stack leak detection based on Explorer (i.e., full symbolic execution).
    We identify stuff that look like addresses at runtime, and start tracking
    them from there, until we reach targets.
    """

    def __init__(self, mode=None, istate=None, argc=None, num_leaks=1):

        self.prepare(istate=istate, mode=mode, argc=argc)
        self.num_leaks = num_leaks

        # Explorer wants a tuple of addresses

        self.explorer_init(self.project, find=(), start=self.ipath, num_find=100)

        # Results picked up by Orgy
        self.result = self.leaks

    @property
    def terminated_paths(self):
        return self.found

    def str_result(self):
        """
        Workaround path serialization issues
        """
        self.result=[]
        for i in self.leaks:
            rz={}
            rz['name'] = i.name
            rz['badargs'] = i.badargs
            rz['backtrace'] = i.path.backtrace
            rz['addr'] = i.path.addr
            self.result.append(rz)

register_analysis(XSleak, 'XSleak')
