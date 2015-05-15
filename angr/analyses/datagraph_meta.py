from ..analysis import Analysis
from ..errors import AngrAnalysisError
import simuvex

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
        raise DataGraphError("No VFG node at 0x%x" % addr)

    def get_irsb_at(self, addr):
        n = self._vfg_node(addr)
        if n is None:
            raise DataGraphError("No VFG node at this address")
        return self._irsb(n.state)

    def pp(self, imarks=False):
        for e in self.graph.edges():
            data = self.graph.get_edge_data(e[0], e[1])
            data['label'] = str(data['label']) + " " +  self._simproc_info(e[0]) + self._simproc_info(e[1])
            if imarks is True:
                try:
                    i1 = self._imarks[e[0]]
                    i2 = self._imarks[e[1]]
                    print "[0x%x] -> [0x%x] : %s" % (i1, i2, data)
                except:
                    print "(0x%x, %d) -> (0x%x, %d) : %s" % (e[0][0], e[0][1], e[1][0], e[1][1], data)

            print "(0x%x, %d) -> (0x%x, %d) : %s" % (e[0][0], e[0][1], e[1][0], e[1][1], data)

    def _branch(self, live_defs, node):
        """
        Recursive function, it branches in every possible path in the VFG.
        @live_defs: a dict {addr:stmt} of live definitions at the start point
        @node: the starting vfg node

        Returns: the address of the block where the execution stops
        """

        irsb = self._irsb(node.state)

        if isinstance(irsb, simuvex.SimProcedure):
            self._simproc_map[irsb.addr] = repr(irsb)

        block = self._make_block(irsb, live_defs)
        self._imarks.update(block._imarks)
        if block.stop == True:
            return irsb.addr
        for s in self._vfg._graph.successors(node):
            self._branch(block.live_defs, s)

    def _make_block(self):
        raise DataGraphError("Not Implemented")

    def _simproc_info(self, node):
        if node[0] in self._simproc_map:
            return self._simproc_map[node[0]]
        return ""
