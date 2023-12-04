# deobfuscator is a collection of analyses that automatically identifies functions where obfuscation techniques are
# in-use.

from .string_obf_finder import StringObfuscationFinder
from .string_obf_peephole_optimizer import StringObfType1PeepholeOptimizer
from .string_obf_opt_passes import StringObfType3Rewriter
