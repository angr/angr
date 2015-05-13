import logging
import simuvex
from ..analysis import Analysis
from .datagraph_meta import DataGraphMeta, DataGraphError


l = logging.getLogger(name="angr.analyses.dataflow")

class DataNode(object):
    """
    Data nodes as used in the DataGraph
    """
    def __init__(self, block_addr, stmt_idx, mem_addr=None):
        """
        Each node correspond to a statement defining of using data .
        Nodes are labeled with <block address - statement idx>
        @block addr is the address of the basic block
        @stmt_idx is the statement index in the basic block (IRSB)
        @mem_addr is the address of the involved memory location
        """

        self.block_addr = block_addr
        self.stmt_idx = stmt_idx
        self.mem_addr = mem_addr

        l.info("%s" % self.__str__())

        def __str__(self):
            return "<DataNode - 0x%x stmt %d>" % (self.block_addr, self.stmt_idx)

class TaintAtom(object):
    """
    This is used to keep tracks of which temps and registers are tainted by a
    memory read.
    """
    def __init__(self, kind, id, node):
        """
        Node: the networkx node associated with the memory read, that is,
        a tuple (irsb_addr, stmt_idx)
        kind: "tmp" or "reg"
        id: register offset or temp number
        """
        if kind not in ["tmp", "reg"]:
            raise DataGraphError("Unknown kind of TaintAtom")

        self.kind = kind
        self.id = id
        self.node = node

        l.debug("New %s" % self.__str__())

    def __str__(self):
        return "<TaintAtom %s%d - (0x%x, %d)>" % (self.kind, self.id,
                                                  self.node[0], self.node[1])

class Stmt(object):
    """
    Taint tracking inside SimStmt objects.
    Each Stmt object takes as input a list of TaintAtoms and returns a new list
    of TaintAtoms.
    """
    def __init__(self, irsb, idx, graph, in_taint):

        self.node = (irsb.addr, idx) # Node corresponding to this stmt in the graph
        self.taint = in_taint  # What is tainted (regs and temps)
        self.loop = False # Have we already analyzed this stmt ?
        self.graph = graph
        self._write_edge = False
        self._new = False
        self._read = False

        stmt = irsb.statements[idx]

        for a in stmt.actions:
            # We used normalized address, see simuvex.plugins.abstract_memory
            #if a.type == "mem":
                #addr = irsb.initial_state.memory.normalize_address(a.addr)

            if a.type == "mem" and a.action == "read":
                l.debug("Mem read at (0x%x, %d)" % (irsb.addr, idx))
                self._read = True

            elif a.type == "mem" and a.action == "write":
                taint = self._check_deps(a)
                if taint is not None:
                    l.debug("Mem write tainted by %s at (0x%x, %d)" % (taint, irsb.addr, idx))
                    self._write_edge = True
                    destnode = (irsb.addr, idx)

                    # We create an edge from the original node from the taint to
                    # the current node
                    if (taint.node, destnode) not in self.graph.edges():
                        l.info("Adding new edge: (0x%x, %d) -> (0x%x, %d)" %
                               (taint.node[0], taint.node[1], destnode[0], destnode[1]))
                        self.graph.add_edge(taint.node, destnode, label="tainted_write")
                        self.new = True

                """
                There is only one write per statement.
                If there previously was a memory read within the same statement,
                then we know that the subsequent write will store the data that was
                previously read.  SimActions don't track this, so we need to
                implicitely infer it here from the value of self.node
                """

            elif a.type == "tmp" and a.action == "write":
                # FIXME (hack) if we previously created a node within the same statement,
                # this temp is the content we read from memory
                if self._read is True:
                    l.debug("(Hack) TMP write following mem read: (0x%x, %d)" %
                            (self.node[0], self.node[1]))
                    self._add_taint(a, self.node)
                else:
                    dep = self._check_deps(a)
                    if dep is not None:
                        self._add_taint(a, dep.node)


            else:
                dep = self._check_deps(a)
                if dep is not None:
                    self._add_taint(a, dep.node)

    def _check_deps(self, a):
        """
        Check action @a for tainted dependencies (regs and tmp).
        If a dependency is tainted, then a's temp or reg becomes tainted.
        """

        dreg = self._check_reg_deps(a)
        if dreg is not None:
            return dreg

        dtmp = self._check_tmp_deps(a)
        if dtmp is not None:
            return dtmp

    def _check_reg_deps(self, a):
        for dep in a.reg_deps:
            taint = self._get_taint("reg", dep)
            if taint is not None:
                return taint

    def _check_tmp_deps(self, a):
        for dep in a.tmp_deps:
            taint = self._get_taint("tmp", dep)
            if taint is not None:
                return taint

    def _clear_taint(self, kind, id):
        for t in self.taint:
            if t.kind == kind and t.id == id:
                self.taint.remove(t)

    def _add_taint(self, a, node):
        kind = a.type
        if kind == "tmp":
            id = a.tmp
        elif kind == "reg":
            id = a.offset
        else:
            raise DataGraphError("Unknown action type")
        # If we taint a register or temp, we remove its previous taint first.
        t = self._get_taint(kind, id)
        if t is not None:
            self._clear_taint(kind,id)
        self.taint.append(TaintAtom(kind, id, node))

    def _get_taint(self, kind, id):
        for t in self.taint:
            if t.kind == kind and t.id == id:
                return t
        return None

    @property
    def stop(self):
        return self._write_edge and not self._new

class TaintBlock(object):
    """
    Data dependency within a single IRSB
    """
    def __init__(self, irsb, in_taint, graph):
        """
        irsb: a SimIRSB object
        in_deps: a list of BlockDeps
        """
        self.irsb = irsb
        self.live_defs = in_taint
        self.stop = False

        if isinstance(self.irsb, simuvex.SimProcedure):
            return

        # Fist instruction in the block
        imark = irsb.statements[0].imark.addr

        for s in self.irsb.statements:
            # Flush temps at new instruction
            if s.imark.addr != imark:
                self._flush_temps()

            # Update the taint state
            stmt = Stmt(self.irsb, s.stmt_idx, graph, self.live_defs)
            if stmt.stop is True:
                self.stop = True

            self.live_defs = stmt.taint

    def _flush_temps(self):
        for atom in self.live_defs:
            if atom.kind == "tmp":
                self.live_defs.remove(atom)

class DataFlowGraph(DataGraphMeta):
    """
    A Data dependency graph based on VSA states.
    That means we don't (and shouldn't) expect any symbolic expressions.
    """

    def __init__(self, ddg, start_addr=None):
        """
        start_addr: the address where to start the analysis (typically, a
        function's entry point)

        Returns: a NetworkX graph representing data dependency within the
        analyzed function's scope (including calls to subfunctions).

        The logic:
            Nodes in the graph are memory locations (stack, heap) represented by DataNodes.
            Edges represent their dependencies.

        """

        # This analysis actually completes the DDG by adding read to write
        # data dependencies
        self.graph = ddg.graph.copy()
        self._vfg = ddg._vfg

        # We explore one path at a time
        self._branch([], ddg._startnode)

    def _make_block(self, irsb, taint):
        return TaintBlock(irsb, taint, self.graph)
