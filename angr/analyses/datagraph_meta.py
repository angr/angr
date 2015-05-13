from ..analysis import Analysis
from ..errors import AngrAnalysisError

class DataGraphError(AngrAnalysisError):
    pass

class DataGraphMeta(Analysis):
    def __init__(self):
        raise Exception("Not implemented - use subclasses")

    def _irsb(self, in_state):
            """
            We expect a VSA state here.
            """
            return self._p.sim_run(in_state)

    def _vfg_node(self, addr):
        """
        Gets vfg node at @addr
        Returns VFGNode or None
        """
        for n in self._vfg._nodes.values():
            if n.addr == addr:
                return n

    def get_irsb_at(self, addr):
        n = self._vfg_node(addr)
        if n is None:
            raise DataGraphError("No VFG node at this address")
        return self._irsb(n.state)

    def pp(self):
        for e in self.graph.edges():
            data = self.graph.get_edge_data(e[0], e[1])
            print "(0x%x, %d) -> (0x%x, %d) : %s" % (e[0][0], e[0][1], e[1][0], e[1][1], data)

    def _branch(self, live_defs, node):
        """
        Recursive function, it branches in every possible path in the VFG.
        @live_defs: a dict {addr:stmt} of live definitions at the start point
        @node: the starting vfg node

        Returns: the address of the block where the execution stops
        """

        irsb = self._irsb(node.state)
        block = self._make_block(irsb, live_defs)
        if block.stop == True:
            return irsb.addr
        for s in self._vfg._graph.successors(node):
            self._branch(block.live_defs, s)

    def _make_block(self):
        raise DataGraphError("Not Implemented")
