import networkx


class CFG(object):
    """An abstract representation of a CFG.

    (Abstract, as opposed to angr.analyses.CFG, which is one particular analysis)"""
    def __init__(self, code):
        self._code = code
        self.graph = networkx.DiGraph()


class Code(object):
    def __init__(self, model):
        self._model = model
        self.cfg = CFG(self)
