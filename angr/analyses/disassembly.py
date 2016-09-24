from ..analysis import Analysis, register_analysis

import logging
l = logging.getLogger('angr.analyses.disassembly')

class Disassembly(Analysis):
    def __init__(self, function=None, ranges=None):
        if function is not None:
            blocks = function.graph.nodes()

register_analysis(Disassembly, 'Disassembly')
