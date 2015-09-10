
import logging

import simuvex

l = logging.getLogger(name="angr.analyses.vsa_ddg")

class DataGraphMeta(object):
    def __init__(self):
        self._p = None

    def _irsb(self, in_state):
        """
        We expect a VSA state here.
        """
        return self._p.factory.sim_run(in_state)

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

    def _branch(self, live_defs, node, path=""):
        """
        Recursive function, it branches in every possible path in the VFG.
        @live_defs: a dict {addr:stmt} of live definitions at the start point
        @node: the starting vfg node

        Returns: the address of the block where the execution stops
        """

        irsb = self._irsb(node.state)
        path = path + " -> " + hex(irsb.addr)

        if isinstance(irsb, simuvex.SimProcedure):
            self._simproc_map[irsb.addr] = repr(irsb)

        l.debug("--> Branch: running block 0x%x" % irsb.addr)
        block = self._make_block(irsb, live_defs)
        self._imarks.update(block._imarks)
        if block.stop == True:
            #l.debug(" ### Stopping at block 0x%x" % (irsb.addr))
            l.debug(" ### End of path %s" % path)
            return irsb.addr
        succ = self._vfg._graph.successors(node)

        defer = []
        for s in succ:
            # Consider fake returns last
            if self._vfg._graph.edge[node][s]['jumpkind'] == 'Ijk_FakeRet':
                defer.append(s)
                continue
            # We need to make a copy of the dict !
            self._branch(dict(block.live_defs), s, path)

            # We explore every other paths before taking fake rets.
            # Ideally, we want to take fake rets only when functions don't
            # return.
            for s in defer:
                self._branch(dict(block.live_defs), s, path)

    def _make_block(self, vfg_node, live_defs):
        raise DataGraphError("Not Implemented")

    def _simproc_info(self, node):
        if node[0] in self._simproc_map:
            return self._simproc_map[node[0]]
        return ""
