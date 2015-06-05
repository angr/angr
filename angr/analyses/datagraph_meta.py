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
        """
        Pretty print the graph.  @imarks determine whether the printed graph
        represents instructions (coarse grained) for easier navigation,  or
        exact statements.
        """
        for e in self.graph.edges():
            data = dict(self.graph.get_edge_data(e[0], e[1]))
            data['label'] = str(data['label']) + " ; " +  self._simproc_info(e[0]) + self._simproc_info(e[1])
            self._print_edge(e, data, imarks)

    def _print_edge(self, e, data, imarks=False):
        pp = []
        for stmt in e:
            if imarks is False or stmt[1] == -1: # SimProcedure
                s = "(0x%x, %d)" % (stmt[0], stmt[1])
            else:
                s = "[0x%x]" % self._imarks[stmt]
            pp.append(s)

        print pp[0] + " -> " + pp[1] + " : " + str(data)

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
            # We need to make a copy of the dict !
            self._branch(dict(block.live_defs), s)

    def _make_block(self):
        raise DataGraphError("Not Implemented")

    def _simproc_info(self, node):
        if node[0] in self._simproc_map:
            return self._simproc_map[node[0]]
        return ""
