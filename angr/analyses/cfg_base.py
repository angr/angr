
import logging
from collections import defaultdict

import networkx

from cle import ELF, PE
import simuvex

from ..knowledge import Function, HookNode, BlockNode
from ..analysis import Analysis
from ..errors import AngrCFGError, AngrTranslationError, AngrMemoryError
from ..extern_obj import AngrExternObject

from .cfg_node import CFGNode

l = logging.getLogger(name="angr.cfg_base")


class IndirectJump(object):
    def __init__(self, addr, ins_addr, func_addr, jumpkind, stmt_idx, resolved_targets=None, jumptable=False,
                 jumptable_addr=None, jumptable_entries=None):
        self.addr = addr
        self.ins_addr = ins_addr
        self.func_addr = func_addr
        self.jumpkind = jumpkind
        self.stmt_idx = stmt_idx
        self.resolved_targets = set() if resolved_targets is None else set(resolved_targets)
        self.jumptable = jumptable
        self.jumptable_addr = jumptable_addr
        self.jumptable_entries = jumptable_entries

    def __repr__(self):

        status = ""
        if self.jumptable:
            status = "jumptable"
            if self.jumptable_addr is not None:
                status += "@%#08x" % self.jumptable_addr
            if self.jumptable_entries is not None:
                status += " with %d entries" % self.jumptable_entries

        return "<IndirectJump %#08x - ins %#08x%s>" % (self.addr, self.ins_addr, " " + status if status else "")


class CFGBase(Analysis):
    """
    The base class for control flow graphs.
    """
    def __init__(self, context_sensitivity_level, normalize=False, binary=None, force_segment=False, iropt_level=None):

        self._context_sensitivity_level=context_sensitivity_level

        # Sanity checks
        if context_sensitivity_level < 0:
            raise ValueError("Unsupported context sensitivity level %d" % context_sensitivity_level)

        self._binary = binary if binary is not None else self.project.loader.main_bin
        self._force_segment = force_segment
        self._iropt_level = iropt_level

        # Initialization
        self._graph = None
        self._edge_map = None
        self._loop_back_edges = None
        self._overlapped_loop_headers = None
        self._thumb_addrs = set()

        # Traverse all the IRSBs, and put the corresponding CFGNode objects to a dict
        # CFGNodes dict indexed by SimRun key
        self._nodes = None
        # Lists of CFGNodes indexed by addresses of each SimRun
        self._nodes_by_addr = None

        # Store all the functions analyzed before the set is cleared
        # Used for performance optimization
        self._changed_functions = None

        self._normalize = normalize
        # Flag, whether the CFG has been normalized or not
        self._normalized = False

        # IndirectJump object that describe all indirect exits found in the binary
        # stores as a map between addresses and IndirectJump objects
        self.indirect_jumps = {}

        # Get all executable memory regions
        self._exec_mem_regions = self._executable_memory_regions(self._binary, self._force_segment)
        self._exec_mem_region_size = sum([(end - start) for start, end in self._exec_mem_regions])

        # initialize an UnresolvableTarget SimProcedure
        # but we do not want to hook the same symbol multiple times
        if not self.project.is_symbol_hooked('UnresolvableTarget'):
            ut_addr = self.project.hook_symbol('UnresolvableTarget',
                                               simuvex.SimProcedures['stubs']['UnresolvableTarget']
                                               )
        else:
            ut_addr = self.project.hooked_symbol_addr('UnresolvableTarget')
        self._unresolvable_target_addr = ut_addr

        # TODO: A segment tree to speed up CFG node lookups
        self._node_lookup_index = None
        self._node_lookup_index_warned = False

    def __contains__(self, cfg_node):
        return cfg_node in self._graph

    @property
    def normalized(self):
        return self._normalized

    @property
    def context_sensitivity_level(self):
        return self._context_sensitivity_level

    def _initialize_cfg(self):
        """
        Re-create the DiGraph
        """
        self._graph = networkx.DiGraph()

    def _post_analysis(self):

        if self._normalize:

            if not self._normalized:
                self.normalize()

            # Call normalize() on each function
            for f in self.kb.functions.values():
                if not self.project.is_hooked(f.addr):
                    f.normalize()

    # pylint: disable=no-self-use
    def copy(self):
        raise NotImplementedError()

    def output(self):
        raise NotImplementedError()

    def generate_index(self):
        """
        Generate an index of all nodes in the graph in order to speed up get_any_node() with anyaddr=True.

        :return: None
        """

        raise NotImplementedError("I'm too lazy to implement it right now")

    # TODO: Mark as deprecated
    def get_bbl_dict(self):
        return self._nodes

    def get_predecessors(self, cfgnode, excluding_fakeret=True, jumpkind=None):
        """
        Get predecessors of a node in the control flow graph.

        :param CFGNode cfgnode:             The node.
        :param bool excluding_fakeret:      True if you want to exclude all predecessors that is connected to the node
                                            with a fakeret edge.
        :param str or None jumpkind:        Only return predecessors with the specified jumpkind. This argument will be
                                            ignored if set to None.
        :return:                            A list of predecessors
        :rtype:                             list
        """

        if excluding_fakeret and jumpkind == 'Ijk_FakeRet':
            return [ ]

        if not excluding_fakeret and jumpkind is None:
            # fast path
            if cfgnode in self._graph:
                return self._graph.predecessors(cfgnode)
            else:
                return []
        else:
            predecessors = []
            for pred, _, data in self._graph.in_edges_iter([cfgnode], data=True):
                jk = data['jumpkind']
                if jumpkind is not None:
                    if jk == jumpkind:
                        predecessors.append(pred)
                elif excluding_fakeret:
                    if jk != 'Ijk_FakeRet':
                        predecessors.append(pred)
                else:
                    predecessors.append(pred)
            return predecessors

    def get_successors(self, basic_block, excluding_fakeret=True, jumpkind=None):
        """
        Get successors of a node in the control flow graph.

        :param CFGNode cfgnode:             The node.
        :param bool excluding_fakeret:      True if you want to exclude all successors that is connected to the node
                                            with a fakeret edge.
        :param str or None jumpkind:        Only return successors with the specified jumpkind. This argument will be
                                            ignored if set to None.
        :return:                            A list of successors
        :rtype:                             list
        """

        if jumpkind is not None:
            if excluding_fakeret and jumpkind == 'Ijk_FakeRet':
                return []

        if not excluding_fakeret and jumpkind is None:
            # fast path
            if basic_block in self._graph:
                return self._graph.successors(basic_block)
            else:
                return []
        else:
            successors = []
            for _, suc, data in self._graph.out_edges_iter([basic_block], data=True):
                jk = data['jumpkind']
                if jumpkind is not None:
                    if jumpkind == jk:
                        successors.append(suc)
                elif excluding_fakeret:
                    if jk != 'Ijk_FakeRet':
                        successors.append(suc)
                else:
                    successors.append(suc)
            return successors

    def get_successors_and_jumpkind(self, basic_block, excluding_fakeret=True):
        successors = []
        for _, suc, data in self._graph.out_edges_iter([basic_block], data=True):
            if not excluding_fakeret or data['jumpkind'] != 'Ijk_FakeRet':
                successors.append((suc, data['jumpkind']))
        return successors

    def get_all_predecessors(self, cfgnode):
        """
        Get all predecessors of a specific node on the control flow graph.

        :param CFGNode cfgnode: The CFGNode object
        :return: A list of predecessors in the CFG
        :rtype: list
        """

        return networkx.dfs_predecessors(self._graph, cfgnode)

    def get_all_successors(self, basic_block):
        return networkx.dfs_successors(self._graph, basic_block)

    def get_node(self, node_key):
        """
        Get a single node from node key.

        :param SimRunKey node_key: The node key
        :return: The CFGNode
        :rtype: CFGNode.
        """
        if node_key in self._nodes:
            return self._nodes[node_key]
        else:
            return None

    def nodes(self):
        return self._graph.nodes()

    def get_any_node(self, addr, is_syscall=None, anyaddr=False):
        """
        Get an arbitrary CFGNode (without considering their contexts) from our graph.

        :param int addr:        Address of the beginning of the basic block. Set anyaddr to True to support arbitrary
                                address.
        :param bool is_syscall: Whether you want to get the syscall node or any other node. This is due to the fact that
                                syscall SimProcedures have the same address as the targer it returns to.
                                None means get either, True means get a syscall node, False means get something that isn't
                                a syscall node.
        :param bool anyaddr:    If anyaddr is True, then addr doesn't have to be the beginning address of a basic
                                block. By default the entire graph.nodes() will be iterated, and the first node
                                containing the specific address is returned, which is slow. If you need to do many such
                                queries, you may first call `generate_index()` to create some indices that may speed up the
                                query.
        :return: A CFGNode if there is any that satisfies given conditions, or None otherwise
        """

        # fastpath: directly look in the nodes list
        if not anyaddr and self._nodes_by_addr and \
                addr in self._nodes_by_addr and self._nodes_by_addr[addr]:
            return self._nodes_by_addr[addr][0]

        # slower path
        #if self._node_lookup_index is not None:
        #    pass

        # the slowest path
        # try to show a warning first
        # TODO: re-enable it once the segment tree is implemented
        #if self._node_lookup_index_warned == False:
        #    l.warning('Calling get_any_node() with anyaddr=True is slow on large programs. '
        #              'For better performance, you may first call generate_index() to generate some indices that may '
        #              'speed the node lookup.')
        #    self._node_lookup_index_warned = True

        for n in self.graph.nodes_iter():
            cond = n.looping_times == 0
            if anyaddr and n.size is not None:
                cond = cond and (addr >= n.addr and addr < n.addr + n.size)
            else:
                cond = cond and (addr == n.addr)
            if cond:
                if is_syscall is None:
                    return n
                if n.is_syscall == is_syscall:
                    return n

        return None

    def _get_irsb(self, cfg_node):
        if cfg_node is None:
            return None

        if cfg_node.input_state is None:
            raise AngrCFGError(
                'You should save the input state when generating the CFG if you want to retrieve the SimIRSB later.')

        # Recreate the SimIRSB
        return self.project.factory.sim_run(cfg_node.input_state, max_size=cfg_node.size, opt_level=self._iropt_level)

    def irsb_from_node(self, cfg_node):
        """
        Create SimRun from a CFGNode object.
        """
        return self._get_irsb(cfg_node)

    def get_any_irsb(self, addr):
        """
        Returns a SimRun of a certain address. If there are many SimRuns with the same address in CFG,
        return an arbitrary one.
        You should never assume this method returns a specific one.
        """
        cfg_node = self.get_any_node(addr)

        return self._get_irsb(cfg_node)

    def get_all_nodes(self, addr, is_syscall=None):
        """
        Get all CFGNodes whose address is the specified one.

        :param addr:       Address of the node
        :param is_syscall: True returns the syscall node, False returns the normal CFGNode, None returns both
        :return:           all CFGNodes
        """
        results = [ ]

        for cfg_node in self._graph.nodes_iter():
            if cfg_node.addr == addr:
                if is_syscall and cfg_node.is_syscall:
                    results.append(cfg_node)
                elif is_syscall is False and not cfg_node.is_syscall:
                    results.append(cfg_node)
                else:
                    results.append(cfg_node)

        return results

    def nodes_iter(self):
        """
        An iterator of all nodes in the graph.

        :return: The iterator.
        :rtype: iterator
        """

        return self._graph.nodes_iter()

    def get_all_irsbs(self, addr):
        """
        Returns all SimRuns of a certain address, without considering contexts.
        """

        nodes = self.get_all_nodes(addr)

        results = [ ]

        for n in nodes:
            results.append(self._get_irsb(n))

        return results

    def get_loop_back_edges(self):
        return self._loop_back_edges

    def get_irsb_addr_set(self):
        irsb_addr_set = set()
        for tpl, _ in self._nodes:
            irsb_addr_set.add(tpl[-1]) # IRSB address
        return irsb_addr_set

    def get_branching_nodes(self):
        """
        Returns all nodes that has an out degree >= 2
        """
        nodes = set()
        for n in self._graph.nodes():
            if self._graph.out_degree(n) >= 2:
                nodes.add(n)
        return nodes

    def get_exit_stmt_idx(self, src_block, dst_block):
        """
        Get the corresponding exit statement ID for control flow to reach destination block from source block. The exit
        statement ID was put on the edge when creating the CFG.
        Note that there must be a direct edge between the two blocks, otherwise an exception will be raised.

        :return: The exit statement ID
        """

        if not self.graph.has_edge(src_block, dst_block):
            raise AngrCFGError('Edge (%s, %s) does not exist in CFG' % (src_block, dst_block))

        return self.graph[src_block][dst_block]['exit_stmt_idx']

    @property
    def graph(self):
        return self._graph

    def remove_edge(self, simrun_from, simrun_to):
        edge = (simrun_from, simrun_to)

        if edge in self._graph:
            self._graph.remove_edge(*edge)

    def _to_snippet(self, cfg_node, jumpkind=None):
        """
        Convert a CFGNode instance to a CodeNode object.

        :param angr.analyses.CFGNode cfg_node: The CFGNode instance.
        :return: A converted CodeNode instance.
        :rtype: CodeNode
        """

        addr = cfg_node.addr

        if self.project.is_hooked(addr) and jumpkind != 'Ijk_NoHook':
            _, kwargs = self.project._sim_procedures[addr]
            size = kwargs.get('length', 0)
            return HookNode(addr, size, self.project.hooked_by(addr))
        else:
            return BlockNode(cfg_node.addr, cfg_node.size)  # pylint: disable=no-member

    def is_thumb_addr(self, addr):
        return addr in self._thumb_addrs

    def _arm_thumb_filter_jump_successors(self, addr, successors, get_ins_addr, get_exit_stmt_idx):
        """
        Filter successors for THUMB mode basic blocks, and remove those successors that won't be taken normally.

        :param int addr: Address of the basic block / SimIRSB.
        :param list successors: A list of successors.
        :param func get_ins_addr: A callable that returns the source instruction address for a successor.
        :param func get_stmt_idx: A callable that returns the source statement ID for a successor.
        :return: A new list of successors after filtering.
        :rtype: list
        """

        if not successors:
            return [ ]

        it_counter = 0
        conc_temps = {}
        can_produce_exits = set()
        bb = self.project.factory.block(addr, thumb=True, opt_level=0)

        for stmt in bb.vex.statements:
            if stmt.tag == 'Ist_IMark':
                if it_counter > 0:
                    it_counter -= 1
                    can_produce_exits.add(stmt.addr)
            elif stmt.tag == 'Ist_WrTmp':
                val = stmt.data
                if val.tag == 'Iex_Const':
                    conc_temps[stmt.tmp] = val.con.value
            elif stmt.tag == 'Ist_Put':
                if stmt.offset == self.project.arch.registers['itstate'][0]:
                    val = stmt.data
                    if val.tag == 'Iex_RdTmp':
                        if val.tmp in conc_temps:
                            # We found an IT instruction!!
                            # Determine how many instructions are conditional
                            it_counter = 0
                            itstate = conc_temps[val.tmp]
                            while itstate != 0:
                                it_counter += 1
                                itstate >>= 8

        if it_counter != 0:
            l.debug('Basic block ends before calculated IT block (%#x)', addr)

        THUMB_BRANCH_INSTRUCTIONS = ('beq', 'bne', 'bcs', 'bhs', 'bcc', 'blo', 'bmi', 'bpl', 'bvs',
                                     'bvc', 'bhi', 'bls', 'bge', 'blt', 'bgt', 'ble', 'cbz', 'cbnz')
        for cs_insn in bb.capstone.insns:
            if cs_insn.mnemonic in THUMB_BRANCH_INSTRUCTIONS:
                can_produce_exits.add(cs_insn.address)

        successors = filter(lambda suc: get_ins_addr(suc) in can_produce_exits or
                                        get_exit_stmt_idx(suc) == 'default',
                            successors
                            )

        return successors

    def _executable_memory_regions(self, binary=None, force_segment=False):
        """
        Get all executable memory regions from the binaries

        :param binary: Binary object to collect regions from. If None, regions from all project binary objects are used.
        :param bool force_segment: Rely on binary segments instead of sections.
        :return: A sorted list of tuples (beginning_address, end_address)
        """

        if binary is None:
            binaries = self.project.loader.all_objects
        else:
            binaries = [ binary ]

        memory_regions = [ ]

        for b in binaries:
            rebase_addr = b.rebase_addr

            if isinstance(b, ELF):
                # If we have sections, we get result from sections
                if not force_segment and b.sections:
                    # Get all executable sections
                    for section in b.sections:
                        if section.is_executable:
                            tpl = (rebase_addr + section.min_addr, rebase_addr + section.max_addr)
                            memory_regions.append(tpl)

                else:
                    # Get all executable segments
                    for segment in b.segments:
                        if segment.is_executable:
                            tpl = (rebase_addr + segment.min_addr, rebase_addr + segment.max_addr)
                            memory_regions.append(tpl)

            elif isinstance(b, PE):
                for section in b.sections:
                    if section.is_executable:
                        tpl = (rebase_addr + section.min_addr, rebase_addr + section.max_addr)
                        memory_regions.append(tpl)

        if not memory_regions:
            memory_regions = [
                (self.project.loader.main_bin.rebase_addr + start,
                 self.project.loader.main_bin.rebase_addr + start + len(cbacker)
                 )
                for start, cbacker in self.project.loader.memory.cbackers
                ]

        memory_regions = sorted(memory_regions, key=lambda x: x[0])

        return memory_regions

    def _addr_in_exec_memory_regions(self, addr):
        """
        Test if the address belongs to an executable memory region.

        :param int addr: The address to test
        :return: True if the address belongs to an exectubale memory region, False otherwise
        :rtype: bool
        """

        for start, end in self._exec_mem_regions:
            if start <= addr < end:
                return True
        return False

    def _addr_belongs_to_section(self, addr):
        """
        Return the section object that the address belongs to.

        :param int addr: The address to test
        :return: The section that the address belongs to, or None if the address does not belong to any section, or if
                section information is not available.
        :rtype: cle.Section
        """

        obj = self.project.loader.addr_belongs_to_object(addr)

        if obj is None:
            return None

        if isinstance(obj, AngrExternObject):
            # the address is from a section allocated by angr.
            return None

        for section in obj.sections:
            start = section.vaddr + obj.rebase_addr
            end = section.vaddr + section.memsize + obj.rebase_addr

            if start <= addr < end:
                return section

        return None

    def _addr_next_section(self, addr):
        """
        Return the next section object after the given address.

        :param int addr: The address to test
        :return: The next section that goes after the given address, or None if there is no section after the address,
                 or if section information is not available.
        :rtype: cle.Section
        """

        obj = self.project.loader.addr_belongs_to_object(addr)

        if obj is None:
            return None

        if isinstance(obj, AngrExternObject):
            # the address is from a section allocated by angr.
            return None

        for section in obj.sections:
            start = section.vaddr + obj.rebase_addr

            if addr < start:
                return section

        return None

    def _addr_belongs_to_segment(self, addr):
        """
        Return the section object that the address belongs to.

        :param int addr: The address to test
        :return: The section that the address belongs to, or None if the address does not belong to any section, or if
                section information is not available.
        :rtype: cle.Segment
        """

        obj = self.project.loader.addr_belongs_to_object(addr)

        if obj is None:
            return None

        if isinstance(obj, AngrExternObject):
            # the address is from a section allocated by angr.
            return None

        for segment in obj.segments:
            start = segment.vaddr + obj.rebase_addr
            end = segment.vaddr + segment.memsize + obj.rebase_addr

            if start <= addr < end:
                return segment

        return None

    def _fast_memory_load(self, addr):
        """
        Perform a fast memory loading of static content from static regions, a.k.a regions that are mapped to the
        memory by the loader.

        :param int addr: Address to read from.
        :return: The data, or None if the address does not exist.
        :rtype: cffi.CData
        """

        try:
            buff, _ = self.project.loader.memory.read_bytes_c(addr)
            return buff

        except KeyError:
            return None

    #
    # Analyze function features
    #

    def _analyze_function_features(self):
        """
        For each function in the function_manager, try to determine if it returns or not. A function does not return if
        it calls another function that is known to be not returning, and this function does not have other exits.

        We might as well analyze other features of functions in the future.
        """

        # TODO: This implementation is slow as f*ck. Some optimizations should be useful, like:
        # TODO: - Building a call graph before performing such an analysis. With the call dependency information, we
        # TODO:   don't have to revisit functions unnecessarily
        # TODO: - Create less temporary graphs, or reuse previously-created graphs

        changes = {
            'functions_return': [],
            'functions_do_not_return': []
        }

        if self._changed_functions is not None:
            all_functions = self._changed_functions
            caller_functions = set()

            for func_addr in self._changed_functions:
                if func_addr not in self.kb.functions.callgraph:
                    continue
                callers = self.kb.functions.callgraph.predecessors(func_addr)
                for f in callers:
                    caller_functions.add(f)

            all_functions |= caller_functions

            all_functions = [ self.kb.functions.function(addr=f) for f in all_functions ]

        else:
            all_functions = self.kb.functions.values()

        # pylint: disable=too-many-nested-blocks
        for func in all_functions:
            if func.returning is not None:
                # It has been determined before. Skip it
                continue

            # If there is at least one endpoint, then this function is definitely returning
            if func.endpoints:
                changes['functions_return'].append(func)
                func.returning = True
                continue

            # This function does not have endpoints. It's either because it does not return, or we haven't analyzed all
            # blocks of it.

            # Let's first see if it's a known SimProcedure that does not return
            if self.project.is_hooked(func.addr):
                hooker = self.project.hooked_by(func.addr)
                if hasattr(hooker, 'NO_RET'):
                    if hooker.NO_RET:
                        func.returning = False
                        changes['functions_do_not_return'].append(func)
                    else:
                        func.returning = True
                        changes['functions_return'].append(func)
                    continue

            tmp_graph = networkx.DiGraph(func.graph)
            # Remove all fakeret edges from a non-returning function
            edges_to_remove = [ ]
            for src, dst, data in tmp_graph.edges_iter(data=True):
                if data['type'] == 'fake_return':
                    edges = [ edge for edge in func.transition_graph.edges(
                                                nbunch=[src], data=True
                                                ) if edge[2]['type'] != 'fake_return'
                              ]
                    if not edges:
                        # We don't know which function it's supposed to call
                        # skip
                        continue
                    target_addr = edges[0][1].addr
                    target_func = self.kb.functions.function(addr=target_addr)
                    if target_func is not None and target_func.returning is False:
                        edges_to_remove.append((src, dst))

            for src, dst in edges_to_remove:
                tmp_graph.remove_edge(src, dst)

            # We check all its current nodes in transition graph whose out degree is 0 (call them
            # temporary endpoints)
            temporary_local_endpoints = [a for a in tmp_graph.nodes()
                                         if tmp_graph.out_degree(a) == 0]

            if not temporary_local_endpoints:
                # It might be empty if our transition graph is fucked up (for example, the freaking
                # SimProcedureContinuation can be used in any SimProcedure and almost always creates loops in its
                # transition graph). Just ignore it.
                continue

            all_endpoints_returning = []
            temporary_endpoints = []

            for local_endpoint in temporary_local_endpoints:

                if local_endpoint in func.transition_graph.nodes():

                    in_edges = func.transition_graph.in_edges([local_endpoint], data=True)
                    transition_type = None if not in_edges else in_edges[0][2]['type']

                    out_edges = func.transition_graph.out_edges([local_endpoint], data=True)

                    if not out_edges:
                        temporary_endpoints.append((transition_type, local_endpoint))

                    else:
                        for src, dst, data in out_edges:
                            t = data['type']

                            if t != 'fake_return':
                                temporary_endpoints.append((transition_type, dst))

            for transition_type, endpoint in temporary_endpoints:
                if endpoint in func.nodes:
                    # Somehow analysis terminated here (e.g. an unsupported instruction, or it doesn't generate an exit)

                    if isinstance(endpoint, Function):
                        all_endpoints_returning.append((transition_type, endpoint.returning))

                    elif isinstance(endpoint, HookNode):
                        hooker = self.project.hooked_by(endpoint.addr)
                        if hooker is None:
                            l.error('CFGBase._analyze_function_features(): Cannot find the hooking object for %s',
                                    endpoint
                                    )
                        else:
                            all_endpoints_returning.append((transition_type, not hooker.NO_RET))

                    else:
                        successors = [ dst for _, dst in func.transition_graph.out_edges(endpoint) ]
                        all_noret = True
                        for suc in successors:
                            if isinstance(suc, Function):
                                if suc.returning is not False:
                                    all_noret = False
                            else:
                                n = self.get_any_node(endpoint.addr, is_syscall=func.is_syscall)
                                if n:
                                    # It might be a SimProcedure or a syscall, or even a normal block
                                    if n.no_ret is not True:
                                        all_noret = False

                        if all_noret:
                            all_endpoints_returning.append((transition_type, True))
                        else:
                            all_endpoints_returning.append((transition_type, None))

                else:
                    # This block is not a member of the current function
                    call_target = endpoint

                    call_target_func = self.kb.functions.function(call_target)
                    if call_target_func is None:
                        all_endpoints_returning.append(None)
                        continue

                    all_endpoints_returning.append(call_target_func.returning)

            if all_endpoints_returning and all([i is False for _, i in all_endpoints_returning]):
                # All target functions that this function calls is not returning
                func.returning = False
                changes['functions_do_not_return'].append(func)

            if all_endpoints_returning and all([ tpl == ("transition", True) for tpl in all_endpoints_returning ]):
                func.returning = True
                changes['functions_return'].append(func)

        return changes

    def normalize(self):
        """
        Normalize the CFG, making sure that there are no overlapping basic blocks.

        Note that this method will not alter transition graphs of each function in self.kb.functions. You may call
        normalize() on each Function object to normalize their transition graphs.

        :return: None
        """

        graph = self.graph

        smallest_nodes = { }  # indexed by end address of the node
        end_addresses_to_nodes = defaultdict(set)

        for n in graph.nodes():
            if n.is_simprocedure:
                continue
            end_addr = n.addr + n.size
            key = (end_addr, n.callstack_key)
            # add the new item
            end_addresses_to_nodes[key].add(n)

        for key in end_addresses_to_nodes.keys():
            if len(end_addresses_to_nodes[key]) == 1:
                smallest_nodes[key] = next(iter(end_addresses_to_nodes[key]))
                del end_addresses_to_nodes[key]

        while end_addresses_to_nodes:
            key_to_find = (None, None)
            for tpl, x in end_addresses_to_nodes.iteritems():
                if len(x) > 1:
                    key_to_find = tpl
                    break

            end_addr, callstack_key = key_to_find
            all_nodes = end_addresses_to_nodes[key_to_find]

            all_nodes = sorted(all_nodes, key=lambda node: node.addr, reverse=True)
            smallest_node = all_nodes[0] # take the one that has the highest address
            other_nodes = all_nodes[1:]

            self._normalize_core(graph, callstack_key, smallest_node, other_nodes, smallest_nodes,
                                 end_addresses_to_nodes
                                 )

            del end_addresses_to_nodes[key_to_find]
            # make sure the smallest node is stored in end_addresses
            smallest_nodes[key_to_find] = smallest_node

            # corner case
            # sometimes two overlapping blocks may not be ending at the instruction. this might happen when one of the
            # blocks (the bigger one) hits the instruction count limit or bytes limit before reaching the end address
            # of the smaller block. in this case we manually pick up those blocks.
            if not end_addresses_to_nodes:
                # find if there are still overlapping blocks
                sorted_smallest_nodes = defaultdict(list)  # callstack_key is the key of this dict
                for k, node in smallest_nodes.iteritems():
                    _, callstack_key = k
                    sorted_smallest_nodes[callstack_key].append(node)
                for k in sorted_smallest_nodes.iterkeys():
                    sorted_smallest_nodes[k] = sorted(sorted_smallest_nodes[k], key=lambda node: node.addr)

                for callstack_key, lst in sorted_smallest_nodes.iteritems():
                    lst_len = len(lst)
                    for i, node in enumerate(lst):
                        if i == lst_len - 1:
                            break
                        next_node = lst[i + 1]
                        if node.addr <= next_node.addr < node.addr + node.size:
                            # umm, those nodes are overlapping, but they must have different end addresses
                            # misuse end_addresses_to_nodes
                            end_addresses_to_nodes[(node.addr + node.size, callstack_key)].add(node)
                            end_addresses_to_nodes[(node.addr + node.size, callstack_key)].add(next_node)

                            del smallest_nodes[(node.addr + node.size, callstack_key)]
                            del smallest_nodes[(next_node.addr + next_node.size, callstack_key)]

        self._normalized = True

    def _normalize_core(self, graph, callstack_key, smallest_node, other_nodes, smallest_nodes, end_addresses_to_nodes):

        # Break other nodes
        for n in other_nodes:
            new_size = smallest_node.addr - n.addr
            if new_size == 0:
                # This node has the same size as the smallest one. Don't touch it.
                continue

            new_end_addr = n.addr + new_size

            # Does it already exist?
            new_node = None
            key = (new_end_addr, n.callstack_key)
            # the logic below is a little convoluted. we check if key exists in either end_address_to_nodes or
            # smallest_nodes, since we don't always add the new node back to end_addresses_to_nodes dict - we only do so
            # when there are more than one node with that key.
            if key in end_addresses_to_nodes:
                new_node = next((i for i in end_addresses_to_nodes[key] if i.addr == n.addr), None)
            if new_node is None:
                if key in smallest_nodes and smallest_nodes[key].addr == n.addr:
                    new_node = smallest_nodes[key]

            if new_node is None:
                # Create a new one
                new_node = CFGNode(n.addr, new_size, self, callstack_key=callstack_key,
                                   function_address=n.function_address, simrun_key=n.simrun_key,
                                   instruction_addrs=[i for i in n.instruction_addrs
                                                      if n.addr <= i <= n.addr + new_size
                                                      ]
                                   )

                # Copy instruction addresses
                new_node.instruction_addrs = [ins_addr for ins_addr in n.instruction_addrs
                                              if ins_addr < n.addr + new_size]
                # Put the new node into end_addresses list
                if key in smallest_nodes:
                    end_addresses_to_nodes[key].add(smallest_nodes[key])
                    end_addresses_to_nodes[key].add(new_node)
                else:
                    smallest_nodes[key] = new_node

            # Modify the CFG
            original_predecessors = list(graph.in_edges_iter([n], data=True))
            original_successors = list(graph.out_edges_iter([n], data=True))

            for _, d, data in original_successors:
                if d not in graph[smallest_node]:
                    if d is n:
                        graph.add_edge(smallest_node, new_node, **data)
                    else:
                        graph.add_edge(smallest_node, d, **data)

            for p, _, _ in original_predecessors:
                graph.remove_edge(p, n)
            graph.remove_node(n)

            # Update nodes dict
            self._nodes[n.simrun_key] = new_node
            if n in self._nodes_by_addr[n.addr]:
                self._nodes_by_addr[n.addr] = filter(lambda x,the_node=n: x is not the_node,
                                                     self._nodes_by_addr[n.addr]
                                                     )
                self._nodes_by_addr[n.addr].append(new_node)

            for p, _, data in original_predecessors:
                # Consider the following case: two basic blocks ending at the same position, where A is larger, and
                # B is smaller. Suppose there is an edge going from the end of A to A itself, and apparently there
                # is another edge from B to A as well. After splitting A into A' and B, we DO NOT want to add A back
                # in, otherwise there will be an edge from A to A`, while A should totally be got rid of in the new
                # graph.
                if p not in other_nodes:
                    graph.add_edge(p, new_node, data)

            # We should find the correct successor
            new_successors = [i for i in [smallest_node] + other_nodes
                              if i.addr == smallest_node.addr]
            if new_successors:
                new_successor = new_successors[0]
                graph.add_edge(new_node, new_successor, jumpkind='Ijk_Boring')
            else:
                # We gotta create a new one
                l.error('normalize(): Please report it to Fish.')

    #
    # Function identification and such
    #

    def remove_function_alignments(self):
        """
        Remove all function alignments.

        :return: None
        """

        for func_addr in self.kb.functions.keys():
            function = self.kb.functions[func_addr]
            if len(function.block_addrs_set) == 1:
                block = next((b for b in function.blocks), None)
                if block is None:
                    continue
                if all(self._is_noop_insn(insn) for insn in block.capstone.insns):
                    # remove this function
                    l.debug('Function chunk %#x is used as function alignments. Removing it.', func_addr)
                    del self.kb.functions[func_addr]

    def make_functions(self):
        """
        Revisit the entire control flow graph, create Function instances accordingly, and correctly put blocks into
        each function.

        Although Function objects are crated during the CFG recovery, they are neither sound nor accurate. With a
        pre-constructed CFG, this method rebuilds all functions bearing the following rules:
        - A block may only belong to one function.
        - Small functions lying inside the startpoint and the endpoint of another function will be merged with the
          other function
        - Tail call optimizations are detected.
        - PLT stubs are aligned by 16.

        :return: None
        """

        # TODO: Is it required that PLT stubs are always aligned by 16? If so, on what architectures and platforms is it
        # TODO:  enforced?

        tmp_functions = self.kb.functions.copy()

        for function in tmp_functions.values():
            function.mark_nonreturning_calls_endpoints()

        # Clear old functions dict
        self.kb.functions.clear()

        blockaddr_to_function = { }
        traversed_cfg_nodes = set()

        function_nodes = set()

        # Find nodes for beginnings of all functions
        for _, dst, data in self.graph.edges_iter(data=True):
            jumpkind = data.get('jumpkind', "")
            if jumpkind == 'Ijk_Call' or jumpkind.startswith('Ijk_Sys'):
                function_nodes.add(dst)

        entry_node = self.get_any_node(self._binary.entry)
        if entry_node is not None:
            function_nodes.add(entry_node)

        # aggressively remove and merge functions
        # For any function, if there is a call to it, it won't be removed
        removed_functions = self._process_irrational_functions(tmp_functions,
                                                               set([n.addr for n in function_nodes]),
                                                               blockaddr_to_function
                                                               )

        for n in self.graph.nodes_iter():
            if n.addr in tmp_functions or n.addr in removed_functions:
                function_nodes.add(n)

        # traverse the graph starting from each node, not following call edges
        # it's important that we traverse all functions in order so that we have a greater chance to come across
        # rational functions before its irrational counterparts (e.g. due to failed jump table resolution)

        min_stage_2_progress = 50.0
        max_stage_2_progress = 90.0
        nodes_count = len(function_nodes)
        for i, fn in enumerate(sorted(function_nodes, key=lambda n: n.addr)):

            if self._show_progressbar or self._progress_callback:
                progress = min_stage_2_progress + (max_stage_2_progress - min_stage_2_progress) * (i * 1.0 / nodes_count)
                self._update_progress(progress)

            self._graph_bfs_custom(self.graph, [ fn ], self._graph_traversal_handler, blockaddr_to_function,
                                   tmp_functions, traversed_cfg_nodes
                                   )

        # Don't forget those small function chunks that are not called by anything.
        # There might be references to them from data, or simply references that we cannot find via static analysis

        secondary_function_nodes = set()
        # add all function chunks ("functions" that are not called from anywhere)
        for func_addr in tmp_functions:
            node = self.get_any_node(func_addr)
            if node is None:
                continue
            if node.addr not in blockaddr_to_function:
                secondary_function_nodes.add(node)

        missing_cfg_nodes = set(self.graph.nodes()) - traversed_cfg_nodes
        missing_cfg_nodes = { node for node in missing_cfg_nodes if node.function_address is not None }
        if missing_cfg_nodes:
            l.debug('%d CFGNodes are missing in the first traversal.', len(missing_cfg_nodes))
            secondary_function_nodes |=  missing_cfg_nodes

        min_stage_3_progress = 90.0
        max_stage_3_progress = 99.9

        nodes_count = len(secondary_function_nodes)
        for i, fn in enumerate(sorted(secondary_function_nodes, key=lambda n: n.addr)):

            if self._show_progressbar or self._progress_callback:
                progress = min_stage_3_progress + (max_stage_3_progress - min_stage_3_progress) * (i * 1.0 / nodes_count)
                self._update_progress(progress)

            self._graph_bfs_custom(self.graph, [fn], self._graph_traversal_handler, blockaddr_to_function,
                                   tmp_functions
                                   )

        # Remove all stubs after PLT entries
        to_remove = set()
        for fn in self.kb.functions.values():
            addr = fn.addr - (fn.addr % 16)
            if addr != fn.addr and addr in self.kb.functions and self.kb.functions[addr].is_plt:
                to_remove.add(fn.addr)

        for addr in to_remove:
            del self.kb.functions[addr]

        # Update CFGNode.function_address
        for node in self._nodes.itervalues():
            if node.addr in blockaddr_to_function:
                node.function_address = blockaddr_to_function[node.addr].addr

        # mark endpoints
        for function in self.kb.functions.values():
            function.mark_nonreturning_calls_endpoints()

    def _process_irrational_functions(self, functions, predetermined_function_addrs, blockaddr_to_function):
        """
        For unresolveable indirect jumps, angr marks those jump targets as individual functions. For example, usually
        the following pattern is seen:

        sub_0x400010:
            push ebp
            mov esp, ebp
            ...
            cmp eax, 10
            ja end
            mov eax, jumptable[eax]
            jmp eax

        sub_0x400080:
            # do something here
            jmp end

        end (0x400e00):
            pop ebp
            ret

        In the example above, `process_irrational_functions` will remove function 0x400080, and merge it with function
        0x400010.

        :param angr.knowledge.FunctionManager functions: all functions that angr recovers, including those ones that are
            misidentified as functions.
        :param dict blockaddr_to_function: A mapping between block addresses and Function instances.
        :return: a list of addresses of all removed functions
        :rtype: list
        """

        functions_to_remove = { }

        functions_can_be_removed = set(functions.keys()) - set(predetermined_function_addrs)

        for func_addr, function in functions.iteritems():

            if func_addr in functions_to_remove:
                continue

            # check all blocks and see if any block ends with an indirect jump and is not resolved
            has_unresolved_jumps = False
            # the functions to merge with must be locating between the unresolved basic block address and the endpoint
            # of the current function
            max_unresolved_jump_addr = 0
            for block_addr in function.block_addrs_set:
                if block_addr in self.indirect_jumps and \
                        self.indirect_jumps[block_addr].jumpkind == 'Ijk_Boring' and \
                        not self.indirect_jumps[block_addr].resolved_targets:
                    # it's not resolved
                    # we should also make sure it's a jump, not a call
                    has_unresolved_jumps = True
                    max_unresolved_jump_addr = max(max_unresolved_jump_addr, block_addr)

            if not has_unresolved_jumps:
                continue

            startpoint_addr = function.startpoint.addr
            if not function.endpoints:
                # Function should have at least one endpoint
                continue
            endpoint_addr = max([ a.addr for a in function.endpoints ])
            the_endpoint = next(a for a in function.endpoints if a.addr == endpoint_addr)
            endpoint_addr += the_endpoint.size

            # sanity check: startpoint of the function should be greater than its endpoint
            if startpoint_addr >= endpoint_addr:
                continue
            if max_unresolved_jump_addr >= endpoint_addr:
                continue

            # scan forward from the endpoint to include any function tail jumps
            # Here is an example:
            # loc_8049562:
            #       mov eax, ebp
            #       add esp, 3ch
            #       ...
            #       ret
            # loc_804956c:
            #       mov ebp, 3
            #       jmp loc_8049562
            # loc_8049573:
            #       mov ebp, 4
            #       jmp loc_8049562
            #
            last_addr = endpoint_addr
            tmp_state = self.project.factory.blank_state(mode='fastpath')
            while True:
                try:
                    # use simrun is slow, but acceptable since we won't be creating millions of blocks here...
                    tmp_state.ip = last_addr
                    b = self.project.factory.sim_run(tmp_state, jumpkind='Ijk_Boring')
                    if len(b.successors) != 1:
                        break
                    if b.successors[0].scratch.jumpkind != 'Ijk_Boring':
                        break
                    if b.successors[0].ip.symbolic:
                        break
                    suc_addr = b.successors[0].ip._model_concrete
                    if max(startpoint_addr, the_endpoint.addr - 0x40) <= suc_addr < the_endpoint.addr + the_endpoint.size:
                        # increment the endpoint_addr
                        endpoint_addr = b.addr + b.irsb.size
                    else:
                        break

                    last_addr = b.addr + b.irsb.size

                except (AngrTranslationError, AngrMemoryError, simuvex.SimIRSBError):
                    break

            # find all functions that are between [ startpoint, endpoint ]

            should_merge = True
            functions_to_merge = set()
            for f_addr in functions_can_be_removed:
                f = functions[f_addr]
                if f_addr == func_addr:
                    continue
                if max_unresolved_jump_addr < f_addr < endpoint_addr and \
                        all([max_unresolved_jump_addr < b_addr < endpoint_addr for b_addr in f.block_addrs]):
                    if f_addr in functions_to_remove:
                        # this function has already been merged with other functions before... it cannot be merged with
                        # this function anymore
                        should_merge = False
                        break
                    if f_addr in predetermined_function_addrs:
                        # this function is a legit one. it shouldn't be removed/merged
                        should_merge = False
                        break
                    functions_to_merge.add(f_addr)

            if not should_merge:
                # we shouldn't merge...
                continue

            for f_addr in functions_to_merge:
                functions_to_remove[f_addr] = func_addr
                continue

        # merge all functions
        for to_remove, merge_with in functions_to_remove.iteritems():
            func_merge_with = self._addr_to_function(merge_with, blockaddr_to_function, functions)

            for block_addr in functions[to_remove].block_addrs:
                blockaddr_to_function[block_addr] = func_merge_with

            del functions[to_remove]

        return functions_to_remove.keys()

    def _addr_to_function(self, addr, blockaddr_to_function, known_functions):
        """
        Convert an address to a Function object, and store the mapping in a dict. If the block is known to be part of a
        function, just return that function.

        :param int addr: Address to convert
        :param dict blockaddr_to_function: A mapping between block addresses to Function instances.
        :param angr.knowledge.FunctionManager known_functions: Recovered functions.
        :return: a Function object
        :rtype: angr.knowledge.Function
        """

        if addr in blockaddr_to_function:
            f = blockaddr_to_function[addr]
        else:
            is_syscall = False
            if self.project.is_hooked(addr):
                hooker = self.project.hooked_by(addr)
                if isinstance(hooker, simuvex.SimProcedure) and hooker.IS_SYSCALL:
                    is_syscall = True

            n = self.get_any_node(addr, is_syscall=is_syscall)
            if n is None: node = addr
            else: node = self._to_snippet(n)

            self.kb.functions._add_node(addr, node, syscall=is_syscall)
            f = self.kb.functions.function(addr=addr)

            blockaddr_to_function[addr] = f

            if addr in known_functions:
                f.returning = known_functions.function(addr).returning
            else:
                # TODO:
                pass

        return f

    def _graph_bfs_custom(self, g, starts, callback, blockaddr_to_function, known_functions, traversed_cfg_nodes=None):
        """
        A customized control flow graph BFS implementation with the following rules:
        - Call edges are not followed.
        - Syscall edges are not followed.

        :param networkx.DiGraph g: The graph.
        :param list starts: A collection of beginning nodes to start graph traversal.
        :param func callback: Callback function for each edge and node.
        :param dict blockaddr_to_function: A mapping between block addresses to Function instances.
        :param angr.knowledge.FunctionManager known_functions: Already recovered functions.
        :param set traversed_cfg_nodes: A set of CFGNodes that are traversed before.
        :return: None
        """

        stack = list(starts)
        traversed = set() if traversed_cfg_nodes is None else set(traversed_cfg_nodes)

        while stack:
            n = stack[0]  # type: CFGNode
            stack = stack[1:]

            if n in traversed:
                continue

            traversed.add(n)

            if n.has_return:
                callback(n, None, {'jumpkind': 'Ijk_Ret'}, blockaddr_to_function, known_functions)

            elif g.out_degree(n) == 0:
                # it's a single node
                callback(n, None, None, blockaddr_to_function, known_functions)

            else:
                for src, dst, data in g.out_edges_iter(nbunch=[n], data=True):
                    callback(src, dst, data, blockaddr_to_function, known_functions)

                    jumpkind = data.get('jumpkind', "")
                    if not (jumpkind == 'Ijk_Call' or jumpkind.startswith('Ijk_Sys')):
                        # Only follow none call edges
                        stack.extend([m for m in g.successors(n) if m not in traversed])

        if traversed_cfg_nodes is not None:
            traversed_cfg_nodes |= traversed

    def _graph_traversal_handler(self, src, dst, data, blockaddr_to_function, known_functions):
        """
        Graph traversal handler. It takes in a node or an edge, and create new functions or add nodes to existing
        functions accordingly. Oh, it also create edges on the transition map of functions.

        :param CFGNode src: Beginning of the edge, or a single node when dst is None.
        :param CFGNode dst: Destination of the edge. For processing a single node, `dst` is None.
        :param dict data: Edge data in the CFG. 'jumpkind' should be there if it's not None.
        :param dict blockaddr_to_function: A mapping between block addresses to Function instances.
        :param angr.knowledge.FunctionManager known_functions: Already recovered functions.
        :return: None
        """

        src_addr = src.addr
        src_function = self._addr_to_function(src_addr, blockaddr_to_function, known_functions)

        if src_addr not in src_function.block_addrs_set:
            n = self.get_any_node(src_addr)
            if n is None: node = src_addr
            else: node = self._to_snippet(n)
            self.kb.functions._add_node(src_function.addr, node)

        if data is None:
            # it's a single node only
            return

        jumpkind = data['jumpkind']

        if jumpkind == 'Ijk_Ret':
            n = self.get_any_node(src_addr)
            if n is None: from_node = src_addr
            else: from_node = self._to_snippet(n)
            self.kb.functions._add_return_from(src_function.addr, from_node, None)

        if dst is None:
            return

        dst_addr = dst.addr

        if jumpkind == 'Ijk_Call' or jumpkind.startswith('Ijk_Sys'):

            is_syscall = jumpkind.startswith('Ijk_Sys')

            # It must be calling a function
            dst_function = self._addr_to_function(dst_addr, blockaddr_to_function, known_functions)

            n = self.get_any_node(src_addr)
            if n is None: src_node = src_addr
            else: src_node = self._to_snippet(n)

            self.kb.functions._add_call_to(src_function.addr, src_node, dst_addr, None, syscall=is_syscall)

            if dst_function.returning:
                returning_target = src.addr + src.size
                if returning_target not in blockaddr_to_function:
                    if returning_target not in known_functions:
                        blockaddr_to_function[returning_target] = src_function
                    else:
                        self._addr_to_function(returning_target, blockaddr_to_function, known_functions)

                to_outside = not blockaddr_to_function[returning_target] is src_function

                n = self.get_any_node(returning_target)
                if n is None: returning_node = returning_target
                else: returning_node = self._to_snippet(n)

                self.kb.functions._add_fakeret_to(src_function.addr, src_node, returning_node, confirmed=True,
                                                  to_outside=to_outside
                                                  )

        elif jumpkind == 'Ijk_Boring':

            # convert src_addr and dst_addr to CodeNodes
            n = self.get_any_node(src_addr)
            if n is None: src_node = src_addr
            else: src_node = self._to_snippet(n)

            n = self.get_any_node(dst_addr)
            if n is None: dst_node = dst_addr
            else: dst_node = self._to_snippet(n)

            # pre-check: if source and destination do not belong to the same section, it must be jumping to another
            # function
            src_section = self._addr_belongs_to_section(src_addr)
            dst_section = self._addr_belongs_to_section(dst_addr)
            if src_section != dst_section:
                _ = self._addr_to_function(dst_addr, blockaddr_to_function, known_functions)

            # is it a jump to another function?
            if dst_addr in known_functions or (
                dst_addr in blockaddr_to_function and blockaddr_to_function[dst_addr] is not src_function
            ):
                # yes it is
                dst_function_addr = blockaddr_to_function[dst_addr].addr if dst_addr in blockaddr_to_function else \
                    dst_addr

                self.kb.functions._add_outside_transition_to(src_function.addr, src_node, dst_node,
                                                             to_function_addr=dst_function_addr
                                                             )

                _ = self._addr_to_function(dst_addr, blockaddr_to_function, known_functions)
            else:
                # no it's not
                # add the transition code

                if dst_addr not in blockaddr_to_function:
                    blockaddr_to_function[dst_addr] = src_function

                self.kb.functions._add_transition_to(src_function.addr, src_node, dst_node)

        elif jumpkind == 'Ijk_FakeRet':

            # convert src_addr and dst_addr to CodeNodes
            n = self.get_any_node(src_addr)
            if n is None: src_node = src_addr
            else: src_node = self._to_snippet(n)

            n = self.get_any_node(dst_addr)
            if n is None: dst_node = dst_addr
            else: dst_node = self._to_snippet(n)

            if dst_addr not in blockaddr_to_function:
                if dst_addr not in known_functions:
                    blockaddr_to_function[dst_addr] = src_function
                    target_function = src_function
                else:
                    target_function = self._addr_to_function(dst_addr, blockaddr_to_function, known_functions)
            else:
                target_function = blockaddr_to_function[dst_addr]

            to_outside = not target_function is src_function

            self.kb.functions._add_fakeret_to(src_function.addr, src_node, dst_node, confirmed=True,
                                              to_outside=to_outside, to_function_addr=target_function.addr
                                              )

        else:
            l.debug('Ignored jumpkind %s', jumpkind)

    #
    # Other functions
    #

    @staticmethod
    def _is_noop_insn(insn):
        """
        Check if the instruction does nothing.

        :param insn: The capstone insn object.
        :return: True if the instruction does no-op, False otherwise.
        """

        if insn.insn_name() == 'nop':
            # nops
            return True
        if insn.insn_name() == 'lea':
            # lea reg, [reg + 0]
            op0, op1 = insn.operands
            if op0.type == 1 and op1.type == 3:
                # reg and mem
                if op0.reg == op1.mem.base and op1.mem.index == 0 and op1.mem.disp == 0:
                    return True

        # add more types of no-op instructions here :-)

        return False
