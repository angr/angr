import logging

import networkx

from typing import Optional, Set, TYPE_CHECKING

from . import analysis
from ..knowledge_plugins.functions import Function

if TYPE_CHECKING:
    from angr.knowledge_plugins.cfg import CFGModel
    from angr.knowledge_plugins.xrefs import XRefManager
    from angr.analyses.decompiler.decompiler import Decompiler

_l = logging.getLogger(name=__name__)


class DataDependencyGraphAnalysis(analysis):
    """
    generates a proximity graph based off data-dependency.
    """

    def __init__(self, func: 'Function', cfg_model: 'CFGModel', xrefs: 'XRefManager',
                 decompilation: Optional['Decompiler'] = None,
                 pred_depth=1, succ_depth=1,
                 expand_funcs: Optional[Set[int]] = None):
        self._function = func
        self._cfg_model = cfg_model
        self._xrefs = xrefs
        self._decompilation = decompilation
        self._pred_depth: int = pred_depth
        self._succ_depth: int = succ_depth
        self._expand_funcs = expand_funcs.copy() if expand_funcs else None

        self.graph: Optional[networkx.DiGraph] = None

        self._work()

    def _work(self):
        pass

    def _process_variable(self):
        pass

    def _process_decompilation(self):
        pass


# register this analysis
from angr.analyses import AnalysesHub

AnalysesHub.register_default('DataDep', DataDependencyGraphAnalysis)
