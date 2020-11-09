from .reaching_definitions import ReachingDefinitionsAnalysis
from .. import register_analysis


register_analysis(ReachingDefinitionsAnalysis, 'ReachingDefinitions')
