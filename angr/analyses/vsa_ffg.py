from ..analysis import Analysis
from ..errors import AngrAnalysisError
import networkx
import claripy
import logging


"""
TODO: VSA Forward Flow Graph (FFG)
"""
l = logging.getLogger(name="angr.analyses.datagraph")

class DataGraphError(AngrAnalysisError):
    pass

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
        Node: the networkx node associated with the memory read.
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
        return "<TaintAtom %s%d - %s>" % (self.kind, self.id, repr(self.node))

class Stmt(object):
    """
    Taint tracking inside SimStmt objects.
    Each Stmt object takes as input a list of TaintAtoms and returns a new list
    of TaintAtoms.
    """
    def __init__(self, irsb, idx, graph, in_taint):

        self.node=None # If we created a node in this statement (i.e., read from memory)
        self.taint = in_taint  # What is tainted (regs and temps)
        self.loop = False # Have we already analyzed this stmt ?
        self.graph = graph

        stmt = irsb.statements[idx]

        for a in stmt.actions:
            # We want to make sure we always get a ValueSet for the addr

            if a.type == "mem":
                addr = irsb.initial_state.memory.normalize_address(a.addr)

            if a.type == "mem" and a.action == "read":
                l.debug("Mem read at 0x%x, stmt %d" % (irsb.addr, idx))

                #data = a.data.ast.model
                self.node = self.get_node(irsb.addr, idx)
                self.node.mem_addr = addr

            if a.type == "mem" and a.action == "write":
                l.debug("Mem write at 0x%x, stmt %d" % (irsb.addr, idx))
                taint = self._check_deps(a)
                if taint is not None:
                    # We get a node for this memory address and data
                    destnode = self.get_node(irsb.addr, idx)
                    destnode.mem_addr = addr

                    # We crate an edge from the original node from the taint to
                    # the current node
                    l.info("New edge")
                    self.graph.add_edge(taint.node, destnode)

            """
            There is only one write per statement.
            If there previously was a memory read within the same statement,
            then we know that the subsequent write will store the data that was
            previously read.  SimActions don't track this, so we need to
            implicitely infer it here from the value of self.node
            """

            if a.type == "tmp" and a.action == "write":
                # If we previously created a node within the same statement,
                # this temp is the content from memory
                if self.node is not None:
                   self._add_taint("tmp", a.tmp, self.node)
                else:
                    #FIXME: issue #103 on gilab
                    self._check_deps(a)

            if a.type == "reg" and a.action == "write":
                if self.node is not None: # We read from memory
                    self._add_taint("reg", a.offset, self.node)
                else:
                    self._check_deps(a)

            if a.type == "reg" and a.action == "read":
                self._check_deps(a)

            if a.type == "tmp" and a.action == "read":
                self._check_deps(a)

    def _check_deps(self, a):
        """
        Check action @a for tainted dependencies (regs and tmp).
        If a dependency is tainted, then a's temp or reg becomes tainted.
        """
        taint = None
        # Temporaries
        for dep in a.tmp_deps:
            taint = self._get_taint("tmp", dep)

        # Registers
        for dep in a.reg_deps:
            taint = self._get_taint("reg", dep)

        if taint is not None:
            if a.type == "reg":
                self._add_taint(a.type, a.offset, taint.node)
            elif a.type == "tmp":
                self._add_taint(a.type, a.tmp, taint.node)
            else:
                raise DataGraphError("Unexpected action type")

        return taint

    def _clear_taint(self, kind, id):
        for t in self.taint:
            if t.kind == kind and t.id == id:
                self.taint.remove(t)

    def _add_taint(self, kind, id, node):
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

    def get_node(self, block_addr, stmt_idx):
        for n in self.graph.nodes():
            if n.block_addr == block_addr and n.stmt_idx == stmt_idx:
                return n
        return DataNode(block_addr, stmt_idx)


class Block(object):
    """
    Data dependency within a single IRSB
    """
    def __init__(self, irsb, in_taint, node_cache):
        """
        irsb: a SimIRSB object
        in_deps: a list of BlockDeps
        """
        self.irsb = irsb
        self.taint = in_taint

        imark = None
        for s in self.irsb.statements:
            # Flush temps at new instruction
            if s.imark.addr != imark:
                self._flush_temps()

            # Update the taint state
            stmt = Stmt(self.irsb, s.stmt_idx, node_cache, self.taint)
            self.taint = stmt.taint

    def _flush_temps(self):
        for atom in self.taint:
            if atom.kind == "tmp":
                self.taint.remove(atom)

class DataGraph(Analysis):
    """
    A Data dependency graph based on VSA states.
    That means we don't (and shouldn't) expect any symbolic expressions.
    """

    def __init__(self, start_addr, interfunction_level=0):
        """
        start_addr: the address where to start the analysis (typically, a
        function's entry point)

        Returns: a NetworkX graph representing data dependency within the
        analyzed function's scope (including calls to subfunctions).

        The logic:
            Nodes in the graph are memory locations (stack, heap) represented by DataNodes.
            Edges represent their dependencies.

        """

        self._startnode = None # entry point of the analyzed function
        self._vfg = self._p.analyses.VFG(function_start=start_addr,
                                         interfunction_level=interfunction_level)
        self.graph = networkx.DiGraph()

        # Get the first node
        self._startnode = self._vfg_node(start_addr)

        if self._startnode is None:
            raise DataGraphError("No start node :(")

        # We explore one path at a time
        self._branch([], [], self._startnode)

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

    def _branch(self, callstack, taint, node):
        """
        This represents a branch in the analysis.
        @Callstack: the addresses of previously analyzed blocks
        @taint: the current taint at the branching point
        @state: the state at the branching point
        @vfg: a reference to the VFG
        """

        irsb = self._irsb(node.state)
        block = Block(irsb, taint, self.graph)
        taint = block.taint # is this necessary ?
        for s in self._vfg._graph.successors(node):
            #import pdb; pdb.set_trace()
            self._branch(callstack, taint, s)

class DataPath(object):
    """
    A DataPath object runs data tracking on a single path, and stops when it
    reaches a deadend in the CFG, or when it loops (everything gets analyzed
    only once).
    """
    def __init__(self):
        pass
