from .reaching_definitions import ReachingDefinitionsAnalysis
from .live_definitions import LiveDefinitions
from .def_use import DefUseAnalysis, DefUseState
from .constants import OP_AFTER, OP_BEFORE
from .. import register_analysis

for analysis in [ DefUseAnalysis, ReachingDefinitionsAnalysis ]:
    register_analysis(analysis, analysis.__name__[:-len('Analysis')])
