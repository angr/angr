from collections import defaultdict
import logging

import networkx

import simuvex

from .pathprioritizer import PathPrioritizer
from .errors import AngrAnnotatedCFGError
from .analyses.cfg import CFGNode

l = logging.getLogger("angr.annocfg")

class AnnotatedCFG(object):
    # cfg : class CFG
    def __init__(self, project, cfg=None, target_irsb_addr=None, detect_loops=False):
        self._project = project

        self._cfg = None
        self._target = None

        self._run_statement_whitelist = defaultdict(list)
        self._exit_taken = defaultdict(list)
        self._addr_to_run = {}
        self._addr_to_last_stmt_id = {}
        self._loops = []
        self._path_merge_points = [ ]
        self._path_prioritizer = None


        if cfg is not None:
            self._cfg = cfg

            if target_irsb_addr is not None:
                self._target = self._cfg.get_any_node(target_irsb_addr)
                self._path_prioritizer = PathPrioritizer(self._cfg, self._target)

        # if detect_loops:
        #     self._detect_loops()

        if self._cfg is not None:
            for run in self._cfg.nodes():
                self._addr_to_run[self.get_addr(run)] = run

    def __getstate__(self):
        state = { }
        state['_run_statement_whitelist'] = self._run_statement_whitelist
        state['_exit_taken'] = self._exit_taken
        # state['_addr_to_run'] = self._addr_to_run
        state['_addr_to_last_stmt_id'] = self._addr_to_last_stmt_id
        state['_loops'] = self._loops
        state['_path_merge_points'] = self._path_merge_points
        state['_path_prioritizer'] = self._path_prioritizer
        state['_cfg'] = None
        state['_project'] = None
        state['_addr_to_run'] = None
        return state

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
            print " => ".join(["0x%08x" % x for x in loop])
            self.add_loop(loop)

    def from_digraph(self, digraph):
        '''
        Initialize this AnnotatedCFG object with a networkx.DiGraph consisting of the following
        form of nodes:

        Tuples like (SimRun address, statement ID)

        Those nodes are connected by edges indicating the execution flow.

        :param digraph: A networkx.DiGraph object
        :return: None
        '''

        for n1, n2 in digraph.edges():
            addr1, stmt_idx1 = n1
            addr2, stmt_idx2 = n2

            if addr1 != addr2:
                # There is a control flow transition from SimRun `addr1` to SimRun `addr2`
                self.add_exit_to_whitelist(addr1, addr2)

            self.add_statements_to_whitelist(addr1, (stmt_idx1,))
            self.add_statements_to_whitelist(addr2, (stmt_idx2,))

    def get_addr(self, run):
        if isinstance(run, simuvex.SimIRSB):
            return run.first_imark.addr
        elif isinstance(run, simuvex.SimProcedure):
            # pseudo_addr = self._project.get_pseudo_addr_for_sim_procedure(run)
            pseudo_addr = run.addr
            return pseudo_addr
        elif isinstance(run, CFGNode):
            return run.addr
        elif type(run) in (int, long):
            return run
        else:
            raise AngrAnnotatedCFGError("Unknown type '%s' of the 'run' argument" % type(run))

    def add_simrun_to_whitelist(self, simrun):
        addr = self.get_addr(simrun)
        self._run_statement_whitelist[addr] = True

    def add_statements_to_whitelist(self, simrun, stmt_ids):
        addr = self.get_addr(simrun)
        if type(stmt_ids) is bool:
            if type(self._run_statement_whitelist[addr]) is list and self._run_statement_whitelist[addr]:
                raise Exception("WTF")
            self._run_statement_whitelist[addr] = stmt_ids
        else:
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

    def add_loop(self, loop_tuple):
        '''
        A loop tuple contains a series of IRSB addresses that form a loop. Ideally
        it always starts with the first IRSB that we meet during the execution.
        '''
        self._loops.append(loop_tuple)

    def set_path_merge_points(self, points):
        self._path_merge_points = points.copy()

    def should_take_exit(self, addr_from, addr_to):
        if addr_from in self._exit_taken:
            return addr_to in self._exit_taken[addr_from]

        return False

    def should_execute_statement(self, addr, stmt_id):
        if self._run_statement_whitelist is None:
            return True
        elif addr in self._run_statement_whitelist:
            return stmt_id in self._run_statement_whitelist[addr]
        return False

    def get_run(self, addr):
        if addr in self._addr_to_run:
            return self._addr_to_run[addr]
        return None

    def get_whitelisted_statements(self, addr):
        '''
        @return: True if all statements are whitelisted
        '''
        if addr in self._run_statement_whitelist:
            if self._run_statement_whitelist[addr] is True:
                return None # This is the default value used in SimuVEX to say
                            # we execute all statements in this basic block. A
                            # little weird...
            else:
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
        for loop in self._loops:
            s = ""
            for addr in loop:
                s += "0x%08x -> " % addr
            l.debug(s)
        l.debug("=== EOF ===")

    def _dbg_print_irsb(self, irsb_addr, project=None):
        '''
        Only for debugging purposes.
        '''
        if self._addr_to_run is None:
            if project is None:
                raise Exception("Dict addr_to_run is empty. " + \
                                "Give me a project, and I'll recreate the IRSBs for you.")
            else:
                irsb = project.factory.sim_run(project.exit_to(irsb_addr, project.initial_state(mode="static")))

        elif irsb_addr not in self._addr_to_run:
            raise Exception("0x%08x not found." % irsb_addr)
        else:
            irsb = self._addr_to_run[irsb_addr]
            if not isinstance(irsb, simuvex.SimIRSB):
                raise Exception("0x%08x is not a SimIRSB instance.")
        statements = irsb.statements
        whitelist = self.get_whitelisted_statements(irsb_addr)
        for i in range(0, len(statements)):
            if whitelist is True or i in whitelist:
                line = "+"
            else:
                line = "-"
            line += "[% 3d] " % i
            # We cannot get data returned by pp(). WTF?
            print line,
            statements[i].stmt.pp()
            print ""

    def keep_path(self, path):
        '''
        Given a path, returns True if the path should be kept, False if it should be cut.
        '''
        if len(path.addr_backtrace) < 2:
            return True

        return self.should_take_exit(path.addr_backtrace[-2], path.addr_backtrace[-1])

    def filter_path(self, path):
        '''
        Only for debugging purposes!
        '''
        #s = [4286871328L, 4286871380L, 4286871392L, 4288524088, 4286871416L, 4286871444L, 4288360060, 4286871460L, 4286871468L, 4286871476L, 4288441092, 4286871484L, 4286871496L, 4286871528L, 4286871536L, 4286871568L, 4286871576L, 4286871596L, 4286871604L, 4286871624L, 4286871632L, 4286871640L, 4286871652L, 4286871664L, 4286872764, 4286871684L, 4286871708L, 4286871788L, 4286871800L, 4286871816L, 4288504180L, 4286871820L, 4286871840L, 4288504180L, 4286871844L, 4286871880L, 4286871896L, 4286871400L, 4288524088, 4286871416L, 4286871444L, 4288360060, 4286871460L, 4286871468L, 4286871476L, 4288441092, 4286871484L, 4286871496L, 4286871528L, 4286871536L, 4286871568L, 4286871576L, 4286871596L, 4286871604L, 4286871624L, 4286871632L, 4286871640L, 4286871652L, 4286871664L, 4286872764, 4286871684L, 4286871708L, 4286871788L, 4286871800L, 4286871816L, 4288504180L, 4286871820L, 4286871840L, 4288504180L, 4286871844L, 4286871880L, 4286871896L, 4286871400L, 4288524088, 4286871416L, 4286871444L, 4288360060, 4286871460L, 4286871468L, 4286871476L, 4288441092, 4286871484L, 4286871496L, 4286871528L, 4286871536L, 4286871568L, 4286871576L, 4286871596L, 4286871604L, 4286871624L, 4286871632L, 4286871640L, 4286871652L, 4286871664L, 4286872764, 4286871684L, 4286871708L, 4286871788L, 4286871800L, 4286871816L, 4288504180L, 4286871820L, 4286871840L, 4288504180L, 4286871844L, 4286871880L, 4286871896L, 4286871400L, 4288524088, 4286871416L, 4286871444L, 4288360060, 4286871460L, 4286871468L, 4286871476L, 4288441092, 4286871484L, 4286871496L, 4286871528L, 4286871536L, 4286871568L, 4286871576L, 4286871596L, 4286871604L, 4286871624L, 4286871632L, 4286871640L, 4286871652L, 4286871664L, 4286872764, 4286871684L, 4286871708L, 4286871788L, 4286871800L, 4286871816L, 4288504180L, 4286871820L, 4286871840L, 4288504180L, 4286871844L, 4286871880L, 4286871896L, 4286871400L, 4288524088, 4286871416L, 4286871444L, 4288360060, 4286871460L, 4286871468L, 4286871476L, 4288441092, 4286871484L, 4286871496L, 4286871528L, 4286871536L, 4286871568L, 4286871576L, 4286871596L, 4286871604L, 4286871624L, 4286871632L, 4286871640L, 4286871652L, 4286871664L, 4286872764, 4286871684L, 4286871708L, 4286871788L, 4286871800L, 4286871816L, 4288504180L, 4286871820L, 4286871840L, 4288504180L, 4286871844L, 4286871880L, 4286871896L, 4286871400L, 4288524088, 4286871416L, 4286871444L, 4288360060, 4286871460L, 4286871468L, 4286871476L, 4288441092, 4286871484L, 4286871496L, 4286871528L, 4286871536L, 4286871568L, 4286871576L, 4286871596L, 4286871604L, 4286871624L, 4286871632L, 4286871640L, 4286871652L, 4286871664L, 4286872764, 4286871684L, 4286871708L, 4286871788L, 4286871800L, 4286871816L, 4288504180L, 4286871820L, 4286871840L, 4288504180L, 4286871844L, 4286871880L, 4286871896L, 4286871400L, 4288524088, 4286871416L, 4286871444L, 4288360060, 4286871460L, 4286871468L, 4286871476L, 4288441092, 4286871484L, 4286871496L, 4286871528L, 4286871536L, 4286871568L, 4286871576L, 4286871596L, 4286871604L, 4286871624L, 4286871632L, 4286871640L, 4286871652L, 4286871664L, 4286872764, 4286871684L, 4286871708L, 4286871788L, 4286871800L, 4286871816L, 4288504180L, 4286871820L, 4286871840L, 4288504180L, 4286871844L, 4286871880L, 4286871896L, 4286871400L, 4288524088, 4286871416L, 4286871444L, 4288360060, 4286871460L, 4286871468L, 4286871476L, 4288441092, 4286871484L, 4286871496L, 4286871528L, 4286871544L, 4286871596L, 4286871604L, 4286871624L, 4286871688L, 4286872764, 4286871708L, 4286871720L, 4286871764L, 4286871992L]
        #result = not any(i != j for i,j in zip(path.addr_backtrace, s))
        #if result:
        #    if not hasattr(self, "_fuckyou"):
        #        self._fuckyou = True
        #    if self._fuckyou and 0xff8479e0 in path.addr_backtrace:
        #        import ipdb
        #        ipdb.set_trace()
        #    return True
        #else:
        #    return False
        ############### INSANE
        return True

        if not hasattr(self, "_fuckyou"):
            self._fuckyou = True
        if self._fuckyou and 0xff8479e0 in path.addr_backtrace:
            import ipdb
            ipdb.set_trace()

        telnet = 0xff8479b8
        input_char = 0xff847818
        loop_head = 0xff847768
        path = path.addr_backtrace
        if telnet in path:
            if path.count(telnet) >= 3:
                return False
            pos1 = path.index(telnet)
            if path[: pos1].count(input_char) < 7:
                return False
            if pos1 + 1 < len(path):
                new_path = path[pos1 + 1 : ]
                if telnet in new_path:
                    pos2 = new_path.index(telnet)
                    new_path = new_path[ : pos2]
                    if new_path.count(input_char) == 0:
                        return False
                    if new_path.count(input_char) > 3:
                        return False
            return True
        else:
            if path.count(loop_head) > 8:
                return False
            else:
                return True


    def merge_points(self, path):
        addr = path.addr
        if addr in self._path_merge_points:
            return {self._path_merge_points[addr]}
        else:
            return set()

    def path_priority(self, path):
        '''
        Given a path, returns the path priority. A lower number means a higher priority.
        '''
        return self._path_prioritizer.get_priority(path)
        # FIXME: Testing code for smartmeter stuff!
        # bt = ",".join(path.backtrace)
        # if "ff8479b8" in bt:
        #     if bt.count("ff8479b8") >= 3:
        #         # l.debug("I saw... we shouldn't get into login function too many times...")
        #         return 200
        #     else:
        #         prior = bt[ : bt.find("ff8479b8")]
        #         if prior.count("ff847818") < 4:
        #             l.debug("Entered too early...")
        #             return 200
        #         if bt.count("ff8479f4") == 1:
        #             # l.debug("I saw path going to password_asking phase!")
        #             return 1
        #         l.debug("I saw path going to checking phase!")
        #         return 2
        # else:
        #     if bt.count("ff847818") < 7 and bt.count("ff847818") >= 4:
        #         # l.debug("I saw monkey-input process...")
        #         return 3
        #     elif bt.count("ff847818") < 4:
        #         return 50
        # return 100
