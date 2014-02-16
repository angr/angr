from collections import defaultdict
import logging

import networkx

import simuvex

l = logging.getLogger("angr.annocfg")

class AnnotatedCFG(object):
    # cfg : class CFG
    def __init__(self, project, cfg, detect_loops=False):
        self._cfg = cfg
        self._project = project

        self._run_statement_whitelist = defaultdict(list)
        self._exit_taken = defaultdict(list)
        self._addr_to_run = {}
        self._addr_to_last_stmt_id = {}
        self._loops = []

        if detect_loops:
            self._detect_loops()

        for run in self._cfg.get_nodes():
            self._addr_to_run[self.get_addr(run)] = run

    def _detect_loops(self):
        temp_graph = networkx.DiGraph()
        for source, target_list in self._cfg._edge_map.items():
            for target in target_list:
                temp_graph.add_edge(source, target)
        for loop_lst in networkx.simple_cycles(temp_graph):
            self.add_loop(tuple([x[-1] for x in loop_lst]))

    def get_addr(self, run):
        if isinstance(run, simuvex.SimIRSB):
            return run.first_imark.addr
        elif isinstance(run, simuvex.SimProcedure):
            pseudo_addr = self._project.get_pseudo_addr_for_sim_procedure(run)
            return pseudo_addr
        else:
            raise Exception()

    def add_statements_to_whitelist(self, run, stmt_ids):
        addr = self.get_addr(run)
        self._run_statement_whitelist[addr].extend(stmt_ids)
        self._run_statement_whitelist[addr] = \
            sorted(list(set(self._run_statement_whitelist[addr])))

    def add_exit_to_whitelist(self, run_from, run_to):
        addr_from = self.get_addr(run_from)
        addr_to = self.get_addr(run_to)
        self._exit_taken[addr_from].append(addr_to)

    def set_last_stmt(self, run, stmt_id):
        addr = self.get_addr(run)
        self._addr_to_last_stmt_id[addr] = stmt_id

    '''
    A loop tuple contains a series of IRSB addresses that form a loop. Ideally
    it always starts with the first IRSB that we meet during the execution.
    '''
    def add_loop(self, loop_tuple):
        self._loops.append(loop_tuple)

    def should_take_exit(self, addr_from, addr_to):
        if addr_from in self._exit_taken:
            return addr_to in self._exit_taken[addr_from]

        return False

    def should_execute_statement(self, addr, stmt_id):
        if addr in self._run_statement_whitelist:
            return stmt_id in self._run_statement_whitelist[addr]
        return False

    def get_run(self, addr):
        if addr in self._addr_to_run:
            return self._addr_to_run[addr]
        return None

    def get_whitelisted_statements(self, addr):
        if addr in self._run_statement_whitelist:
            return self._run_statement_whitelist[addr]
        return []

    def get_last_statement_index(self, addr):
        if addr in self._addr_to_last_stmt_id:
            return self._addr_to_last_stmt_id[addr]
        return None

    def get_loops(self):
        return self._loops

    def debug_print(self):
        l.debug("SimRuns:")
        for addr, run in self._addr_to_run.items():
            if addr is None:
                continue
            l.debug("0x%08x => %s", addr, run)
        l.debug("statements: ")
        for addr, stmts in self._run_statement_whitelist.items():
            if addr is None:
                continue
            l.debug("Address 0x%08x:", addr)
            l.debug(stmts)
        l.debug("Loops: ")
        for l in self._loops:
            s = ""
            for addr in l:
                s += "0x%08x -> " % addr
            l.debug(s)
        l.debug("=== EOF ===")

    '''
    Only for debugging purposes.
    '''
    def _dbg_print_irsb(self, irsb_addr):
        result = ""
        if irsb_addr not in self._addr_to_run:
            result = "0x%08x not found." % irsb_addr
        else:
            irsb = self._addr_to_run[irsb_addr]
            if not isinstance(irsb, simuvex.SimIRSB):
                result = "0x%08x is not a SimIRSB instance."
            else:
                statements = irsb.statements
                whitelist = self.get_whitelisted_statements(irsb_addr)
                for i in range(0, len(statements)):
                    if i in whitelist:
                        line = "+"
                    else:
                        line = "-"
                    line += "[% 3d] " % i
                    # We cannot get data returned by pp(). WTF?
                    print line,
                    statements[i].stmt.pp()
                    print ""

        return result
