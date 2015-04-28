from ..analysis import Analysis
from ..errors import AngrAnalysisError
import networkx


class DataGraphError(AngrAnalysisError):
    pass

class Point(object):
    """
    This defines a program point: IRSB address and statment id.
    """
    def __init__(self, addr, stmt):
        """
        addr is the irsb address
        stmt is the statement id inside the irsb
        """
        self.addr = addr
        self.stmt = stmt


class NodeMeta(object):
    def __init__(self):
        raise DataGraphException("This class cannot be instanciated")

    def hash(self, a_loc, data_expr):
        #TODO: check whether this is safe
        h = _hash(a_loc.ast.__str__() + data_expr.ast.__str__())

class DataNode(NodeMeta):
    """
    Data nodes as used in the DataGraph
    """
    def __init__(self, a_loc, data_expr):
        """
        @a_loc is an abstract location, i.e., an address or VSA-expression of an
        address.
        @data_expr is the expression of the data being contained at that address.
        """
        # The expression of a memory address
        self.a_loc = a_loc
        self.data_expr = data_expr

        # Program points where this node is read and written to
        self._reads=[]
        self._writes=[]

    def written_at(self, point):
        """
        The abstract location represented by this node was written to by @point.
        """
        self._writes.add(point)

    def read_at(self, point):
        """
        The abstract location represented by this node was written to by @point.
        """
        self._reads.add(point)

    def hash(self):
        return self._hash(self.a_loc, self.data_expr)

class NodeCache(NodeMeta):
    """
    We keep nodes in a cache to avoid redundancy
    """
    def __init__(self):
        self.nodes={}

    def get_node(self, a_loc, data_expr):
        """
        Get the node at a_loc containing data_expr if it exists.
        Create a new one with those properties and return it otherwise.

        """
        h = self._hash(a_loc.ast, data_expr.ast)
        if h in self.nodes.keys():
            return self.nodes[h]
        else:
            node = DataNode(a_loc, data_expr)
            self.nodes[h] = node
            return node

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

class Stmt(object):
    """
    Taint tracking inside SimStmt objects.
    Each Stmt object takes as input a list of TaintAtoms and returns a new list
    of TaintAtoms.
    """
    def __init__(self, irsb, idx, node_cache, in_taint):

        self.node=None # If we created a node in this statement (i.e., read from memory)
        self.taint = in_taint  # What is tainted (regs and temps)
        self.edge = [] # If this statement creates an edge in the graph

        stmt = irsb[idx]

        for a in stmt.actions:
            if a.type == "mem" and a.action == "read":
                self.node = node_cache.get_node(a.addr, a.data)
                self.node.read_at(Point(irsb.addr, idx))

            if a.type == "mem" and a.action == "write":
                taint = self._check_deps(a)
                if taint is not None:
                    # We get a node for this memory address and data
                    destnode = node_cache.get_node(a.addr, a.data)
                    destnode.write_at(Point(irsb.addr, idx))

                    # We crate an edge from the original node from the taint to
                    # the current node
                    self.edge = ( (taint.node, destnode) )

            """
            There is only one write per statement.
            If there previously was a memory read within the same statement,
            then we know that the subsequent write will store the data that was
            previously read.  SimActions don't track this, so we need to
            implicitely infer it here from the value of self.node
            """

            if a.type == "tmp" and a.action == "write":
                if self.node is not None: # We read from memory
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
                self.check_deps(a)

            if a.type == "tmp" and a.action == "read":
                self.check_deps(a)

    def _check_deps(self, a):
        """
        Check action @a for tainted dependencies (regs and tmp).
        If a dependency is tainted, then a's temp or reg becomes tainted.
        """
        tainted = False
        # Temporaries
        for dep in a.tmp_deps:
            taint = self._get_taint("tmp", dep.tmp)
            if taint is not None:
                tainted = True

        # Registers
        for dep in a.reg_deps:
            taint = self._get_taint("reg", dep.offset)
            if taint is not None:
                tainted=True

        if tainted is True:
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
        self.edges = []

        imark = None
        for s in self.irsb.statements:
            # Flush temps at new instruction
            if s.imark.addr != imark:
                self._flush_temps()

            # Update the taint state
            stmt = Stmt(self.irsb, s.stmt_idx, node_cache, self.taint)
            self.taint = stmt.taint
            self.edges = self.edges + stmt.edges

    def _flush_temps(self):
        for atom in self.taint:
            if atom.kind == "tmp":
                self.taint.remove(atom)

class DataGraph(Analysis):
    """
    A Data dependency graph based on VSA states.
    That means we don't (and shouldn't) expect any symbolic expressions.
    """

    def __init__(self, start_addr):
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
        self._vfg = self._p.analyses.VFG(function_start = start_addr)
        self.graph = networkx.DiGraph()
        self._node_cache = NodeCache()

        # Get the first node
        for n in self._vfg._nodes.values():
            if n.addr == start_addr:
                self._startnode = n

    def _irsb(self, in_state):
            """
            We expect a VSA state here.
            """
            return self._project.sim_run(in_state)

    def _link_nodes(self, a, b):
        pass
