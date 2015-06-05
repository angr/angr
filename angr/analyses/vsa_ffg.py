import logging
import simuvex
from .datagraph_meta import DataGraphMeta, DataGraphError


l = logging.getLogger(name="angr.analyses.dataflow")


class DataFlowGraph(DataGraphMeta):
    """
    A Data flow graph based on VSA states (and a VSA-based DDG)
    """

    def __init__(self, ddg, start_addr=None, sources=[], sinks=[]):
        """
        @ddg: a data dependency graph (from angr.analyses.VSA_DDG)

        @start_addr: the address where to start the analysis (typically, a
        function's entry point)

        @sources: a list of staements considered as sources. Such statements
        must correspond to reads from registers or temps.  Adding a mem read
        statement to the list of sources has no effect, as mem reads are already
        tracked as taint source by default.

        @sinks: a list of statements considered as sinks. Such statements must
        correspond to writes to registers or temps. Adding a mem write to the
        list of sinks has no effect, as mem writes are already tracked as sinks
        by default.

        For both sources and sinks, we expect lists of tuples (irsb_addr, stmt_idx).

        This analysis creates a NetworkX graph representing data dependency within the
        analyzed function's scope (including calls to subfunctions).

        The logic:
            Nodes in the graph are statements of the program.
            Edges represent their dependencies, and are:
                - either data dependencies as part of the DDG, in this case the
                edges are labelled with addresse
                - or tainted dependencies.

        """

        # This analysis actually completes the DDG by adding read to write
        # data dependencies
        self.graph = ddg.graph.copy()
        self._vfg = ddg._vfg
        self._simproc_map = {}

        # A mapping (irsb, stmt_idx) -> imark, useful for pp()
        self._imarks = ddg._imarks

        # We add sources and sinks as disconnected nodes in the graph
        for s in sources:
            self.graph.add_node(s, type="source")

        for s in sinks:
            self.graph.add_node(s, type="sink")

        if start_addr is not None:
            start_node = self._vfg_node(start_addr)
        else:
            start_node = ddg._startnode

        # We explore one path at a time
        self._branch({}, start_node)

    def _make_block(self, irsb, taint):
        return TaintBlock(irsb, taint, self.graph)

class Stmt(object):
    """
    Taint tracking inside SimStmt objects.
    @in_taint is a dict of ("tmp|reg", id) : (irsb_addr, stmt_idx) It represents
    a list of registers and temps and which statement tainted them.

    A statement is tainted by a read from memory, and creates a node when
    writing tainted data.
    """
    def __init__(self, irsb, idx, graph, in_taint):

        # SimProcedure identification
        self.node = (irsb.addr, idx)

        self.taint = in_taint  # What is tainted (regs and temps)
        self.loop = False # Have we already analyzed this stmt ?
        self.graph = graph
        self._write_edge = False
        self._new = False
        self._read = False

        if idx == -1:
            a_list = irsb.successors[0].log # This is where SimProcedure actions are
        else:
            a_list = irsb.statements[idx]

        for a in a_list.actions:

            if not isinstance(a, simuvex.SimActionData):
                continue

            # If this action is an extra source, no need to go further
            if self._check_extra_source(a) is True:
                continue

            if a.type == "mem" and a.action == "read":
                # We cannot add taint yet, as we don't know which temp is
                # getting the data at this point. We only know that there is
                # only one write per statement, and that the following temp
                # write in the same statement will be tainted.

                l.debug("Mem read at (0x%x, %d)" % (irsb.addr, idx))
                self._read = True
                continue

            elif a.type == "tmp" and a.action == "write":
                if self._read is True:
                    l.debug("(Hack) TMP write following mem read: (0x%x, %d)" %
                            (self.node[0], self.node[1]))
                    self._add_taint(a, self.node)

            # Is any of the dependencies tainted ?
            dep = self._tainted_dep(a)
            if dep is None:
                continue

            # Extra sink ?
            if self._check_extra_sink(a, dep) is True:
                continue

            if a.type == "mem" and a.action == "write":
                self._do_mem_write(a, dep)

            # All other cases
            else:
                self._add_taint(a, self.taint[dep])

    def _do_mem_write(self, a, dep):
            l.debug("Mem write tainted by %s at (0x%x, %d)" % (dep, self.node[0], self.node[1]))
            self._write_edge = True
            destnode = self.node
            taintnode = self.taint[dep]

            # We create an edge from the original node from the taint to
            # the current node
            if (taintnode, destnode) not in self.graph.edges():
                l.info("Adding new edge: (0x%x, %d) -> (0x%x, %d)" %
                        (taintnode[0], taintnode[1], destnode[0], destnode[1]))
                self.graph.add_edge(taintnode, destnode, label="tainted_write")
                self.new = True

    def _check_extra_source(self, a):
        """
        Is the SimAction @a related to an extra source ?
        If so, we taint what results from that read
        Ret: True or False
        """

        # Only for explicitely added "fake nodes"
        if self.node not in self.graph.nodes():
            return

        # We already track mem reads as sources by default
        if a.action == 'read' and not a.type == 'mem':
            data = self.graph[self.node]
            if "source" in data.values():
                self._add_taint(a, self.node)
                l.info("Traking source (0x%x, %d)" % self.node)
                return True
        return False

    def _check_extra_sink(self, a, dep):
        """
        Is the SimAction @a related to an extra sink ?
        If so, we add an edge from the current tainted source to the graph node
        representing the current statement

        Ret: True or False
        """
        if dep is None:
            return False

        # Only for explicitely added "fake nodes"
        if self.node not in self.graph.nodes():
            return

        # We already track mem writes as sinks by default
        if a.action == 'write' and not a.type == 'mem':
            data = self.graph[self.node]
            if "sink" in data.values():
                self.graph.add_edge(self.taint[dep], self.node)
                l.info("(0x%x, %d) -> (0x%x, %d) [sink]" % self.taint[dep], self.node)
                return True
        return False

    def _tainted_dep(self, a):
        """
        Check action @a for tainted dependencies (regs and tmp).
        If a dependency is tainted, then a's temp or reg becomes tainted.
        """

        #TODO: what is several deps are tainted ? Is that even possible ?

        for dep in a.reg_deps:
            if ("reg", dep) in self.taint:
                return ("reg", dep)

        for dep in a.tmp_deps:
            if ("tmp", dep) in self.taint:
                return ("tmp", dep)

    def _add_taint(self, a, node):
        """
        Overwrites the taint status of the reg or temp defined by the SimAction
        @a
        """

        kind = a.type
        if kind == "tmp":
            id = a.tmp
        elif kind == "reg":
            id = a.offset
        else:
            raise DataGraphError("Unknown action type")

        self.taint[(kind, id)] = node

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
        self._imarks = {}

        # SimProcedures have no statements (-1)
        if isinstance(self.irsb, simuvex.SimProcedure):
            self._flush_temps()
            stmt = Stmt(self.irsb, -1, graph, self.live_defs)
            self.live_defs = stmt.taint
            return

        # Fist instruction in the block
        imark = irsb.statements[0].imark.addr

        for s in self.irsb.statements:
            # Flush temps at new instruction
            if s.imark.addr != imark:
                self._flush_temps()
                self._imarks[(self.irsb.addr, s.stmt_idx)] = s.imark.addr

            # Update the taint state
            stmt = Stmt(self.irsb, s.stmt_idx, graph, self.live_defs)
            if stmt.stop is True:
                self.stop = True

            self.live_defs = stmt.taint

    def _flush_temps(self):
        for atom in self.live_defs.keys():
            if atom[0] == "tmp":
                del self.live_defs[atom]
                #self.live_defs[atom] = None

