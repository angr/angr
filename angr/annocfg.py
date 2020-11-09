from collections import defaultdict
import logging

import networkx

from .utils.constants import DEFAULT_STATEMENT
from .errors import AngrAnnotatedCFGError, AngrExitError
from .knowledge_plugins.cfg import CFGNode

l = logging.getLogger(name=__name__)

class AnnotatedCFG:
    """
    AnnotatedCFG is a control flow graph with statement whitelists and exit whitelists to describe a slice of the
    program.
    """
    def __init__(self, project, cfg=None, detect_loops=False):
        """
        Constructor.

        :param project: The angr Project instance
        :param cfg: Control flow graph.
        :param detect_loops:
        """
        self._project = project

        self._cfg = None
        self._target = None

        self._run_statement_whitelist = defaultdict(list)
        self._exit_taken = defaultdict(list)
        self._addr_to_run = {}
        self._addr_to_last_stmt_id = {}
        self._loops = []
        self._path_merge_points = [ ]

        if cfg is not None:
            self._cfg = cfg

        if self._cfg is not None:
            for run in self._cfg.model.nodes():
                self._addr_to_run[self.get_addr(run)] = run

    #
    # Public methods
    #

    def from_digraph(self, digraph):
        """
        Initialize this AnnotatedCFG object with a networkx.DiGraph consisting of the following
        form of nodes:

        Tuples like (block address, statement ID)

        Those nodes are connected by edges indicating the execution flow.

        :param networkx.DiGraph digraph: A networkx.DiGraph object
        """

        for n1 in digraph.nodes():
            addr1, stmt_idx1 = n1
            self.add_statements_to_whitelist(addr1, (stmt_idx1,))

            successors = digraph[n1]
            for n2 in successors:
                addr2, stmt_idx2 = n2

                if addr1 != addr2:
                    # There is a control flow transition from block `addr1` to block `addr2`
                    self.add_exit_to_whitelist(addr1, addr2)

                self.add_statements_to_whitelist(addr2, (stmt_idx2,))

    def get_addr(self, run):
        if isinstance(run, CFGNode):
            return run.addr
        elif type(run) is int:
            return run
        else:
            raise AngrAnnotatedCFGError("Unknown type '%s' of the 'run' argument" % type(run))

    def add_block_to_whitelist(self, block):
        addr = self.get_addr(block)
        self._run_statement_whitelist[addr] = True

    def add_statements_to_whitelist(self, block, stmt_ids):
        addr = self.get_addr(block)
        if type(stmt_ids) is bool:
            if type(self._run_statement_whitelist[addr]) is list and self._run_statement_whitelist[addr]:
                raise Exception("WTF")
            self._run_statement_whitelist[addr] = stmt_ids
        elif -1 in stmt_ids:
            self._run_statement_whitelist[addr] = True
        else:
            self._run_statement_whitelist[addr].extend(stmt_ids)
            self._run_statement_whitelist[addr] = \
                sorted(set(self._run_statement_whitelist[addr]), key=lambda v: v if type(v) is int else float('inf'))

    def add_exit_to_whitelist(self, run_from, run_to):
        addr_from = self.get_addr(run_from)
        addr_to = self.get_addr(run_to)
        self._exit_taken[addr_from].append(addr_to)

    def set_last_statement(self, block_addr, stmt_id):
        self._addr_to_last_stmt_id[block_addr] = stmt_id

    def add_loop(self, loop_tuple):
        """
        A loop tuple contains a series of IRSB addresses that form a loop. Ideally
        it always starts with the first IRSB that we meet during the execution.
        """
        self._loops.append(loop_tuple)

    def should_take_exit(self, addr_from, addr_to):
        if addr_from in self._exit_taken:
            return addr_to in self._exit_taken[addr_from]

        return False

    def should_execute_statement(self, addr, stmt_id):
        if self._run_statement_whitelist is None:
            return True
        elif addr in self._run_statement_whitelist:
            r = self._run_statement_whitelist[addr]
            if isinstance(r, bool):
                return r
            else:
                return stmt_id in self._run_statement_whitelist[addr]
        return False

    def get_run(self, addr):
        if addr in self._addr_to_run:
            return self._addr_to_run[addr]
        return None

    def get_whitelisted_statements(self, addr):
        """
        :returns: True if all statements are whitelisted
        """
        if addr in self._run_statement_whitelist:
            if self._run_statement_whitelist[addr] is True:
                return None # This is the default value used to say
                            # we execute all statements in this basic block. A
                            # little weird...

            else:
                return self._run_statement_whitelist[addr]

        else:
            return []

    def get_last_statement_index(self, addr):
        """
        Get the statement index of the last statement to execute in the basic block specified by `addr`.

        :param int addr:    Address of the basic block.
        :return:            The statement index of the last statement to be executed in the block. Usually if the
                            default exit is taken, it will be the last statement to execute. If the block is not in the
                            slice or we should never take any exit going to this block, None is returned.
        :rtype:             int or None
        """

        if addr in self._exit_taken:
            return None
        if addr in self._addr_to_last_stmt_id:
            return self._addr_to_last_stmt_id[addr]
        elif addr in self._run_statement_whitelist:
            # is the default exit there? it equals to a negative number (-2 by default) so `max()` won't work.
            if DEFAULT_STATEMENT in self._run_statement_whitelist[addr]:
                return DEFAULT_STATEMENT
            return max(self._run_statement_whitelist[addr], key=lambda v: v if type(v) is int else float('inf'))
        return None

    def get_loops(self):
        return self._loops

    def get_targets(self, source_addr):
        if source_addr in self._exit_taken:
            return self._exit_taken[source_addr]
        return None

    #
    # Debugging helpers
    #

    def dbg_repr(self):
        ret_str = ""

        ret_str += "IRSBs:\n"
        for addr, run in self._addr_to_run.items():
            if addr is None:
                continue
            ret_str += "%#x => %s\n" % (addr, run)
        l.debug("statements: ")
        for addr, stmts in self._run_statement_whitelist.items():
            if addr is None:
                continue
            ret_str += "Address 0x%08x:\n" % addr
            l.debug(stmts)
        l.debug("Loops: ")
        for loop in self._loops:
            s = ""
            for addr in loop:
                s += "0x%08x -> " % addr
            ret_str += s + "\n"

        return ret_str

    def dbg_print_irsb(self, irsb_addr, project=None):
        """
        Pretty-print an IRSB with whitelist information
        """

        if project is None:
            project = self._project

        if project is None:
            raise Exception("Dict addr_to_run is empty. " + \
                            "Give me a project, and I'll recreate the IRSBs for you.")

        vex_block = project.factory.block(irsb_addr).vex
        statements = vex_block.statements
        whitelist = self.get_whitelisted_statements(irsb_addr)
        for i in range(0, len(statements)):
            if whitelist is True or i in whitelist:
                line = "+"
            else:
                line = "-"
            line += "[% 3d] " % i
            # We cannot get data returned by pp(). WTF?
            print(line, end='')
            statements[i].pp()

    #
    # Helper methods for path priorization
    #

    def keep_path(self, path):
        """
        Given a path, returns True if the path should be kept, False if it should be cut.
        """
        if len(path.addr_trace) < 2:
            return True

        return self.should_take_exit(path.addr_trace[-2], path.addr_trace[-1])

    def merge_points(self, path):
        addr = path.addr
        if addr in self._path_merge_points:
            return {self._path_merge_points[addr]}
        else:
            return set()

    def successor_func(self, path):
        """
        Callback routine that takes in a path, and returns all feasible successors to path group. This callback routine
        should be passed to the keyword argument "successor_func" of PathGroup.step().

        :param path: A Path instance.
        :return: A list of all feasible Path successors.
        """

        whitelist = self.get_whitelisted_statements(path.addr)
        last_stmt = self.get_last_statement_index(path.addr)

        # pass in those arguments
        successors = path.step(
            stmt_whitelist=whitelist,
            last_stmt=None
        )

        # further filter successors based on the annotated CFG
        taken_successors = [ ]
        for suc in successors:
            try:
                taken = self.should_take_exit(path.addr, suc.addr)
            except AngrExitError:
                l.debug("Got an unknown exit that AnnotatedCFG does not know about: %#x -> %#x", path.addr, suc.addr)
                continue

            if taken:
                taken_successors.append(suc)

        return taken_successors

    #
    # Overridden methods
    #

    def __getstate__(self):
        state = {}
        state['_run_statement_whitelist'] = self._run_statement_whitelist
        state['_exit_taken'] = self._exit_taken
        # state['_addr_to_run'] = self._addr_to_run
        state['_addr_to_last_stmt_id'] = self._addr_to_last_stmt_id
        state['_loops'] = self._loops
        state['_path_merge_points'] = self._path_merge_points
        state['_cfg'] = None
        state['_project'] = None
        state['_addr_to_run'] = None
        return state

    #
    # Private methods
    #

    def _detect_loops(self):
        temp_graph = networkx.DiGraph()
        for source, target_list in self._cfg._edge_map.items():
            for target in target_list:
                temp_graph.add_edge(source, target)
        ctr = 0
        for loop_lst in networkx.simple_cycles(temp_graph):
            l.debug("A loop is found. %d", ctr)
            ctr += 1
            loop = (tuple([x[-1] for x in loop_lst]))
            print(" => ".join(["0x%08x" % x for x in loop]))
            self.add_loop(loop)
