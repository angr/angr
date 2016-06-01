import networkx
import logging

from cle import ELF, PE

from ..knowledge import Function, HookNode
from ..analysis import Analysis
from ..errors import AngrCFGError

l = logging.getLogger(name="angr.cfg_base")

class CFGBase(Analysis):
    """
    The base class for control flow graphs.
    """
    def __init__(self, context_sensitivity_level):

        self._context_sensitivity_level=context_sensitivity_level

        # Sanity checks
        if context_sensitivity_level < 0:
            raise ValueError("Unsupported context sensitivity level %d" % context_sensitivity_level)

        # Initialization
        self._graph = None
        self._nodes = None
        self._edge_map = None
        self._loop_back_edges = None
        self._overlapped_loop_headers = None
        self._thumb_addrs = set()

    def __contains__(self, cfg_node):
        return cfg_node in self._graph

    @property
    def context_sensitivity_level(self):
        return self._context_sensitivity_level

    def _initialize_cfg(self):
        """
        Re-create the DiGraph
        """
        self._graph = networkx.DiGraph()

    # pylint: disable=no-self-use
    def copy(self):
        raise NotImplementedError()

    def output(self):
        raise NotImplementedError()

    # TODO: Mark as deprecated
    def get_bbl_dict(self):
        return self._nodes

    def get_predecessors(self, cfgnode, excluding_fakeret=True):
        """
        Get predecessors of a node on the control flow graph.

        :param CFGNode cfgnode: The node
        :param bool excluding_fakeret: True if you want to exclude all predecessors that is connected to the node with
                                       a fakeret edge.
        :return: A list of predecessors
        :rtype: list
        """

        if not excluding_fakeret:
            if cfgnode in self._graph:
                return self._graph.predecessors(cfgnode)
            else:
                return []
        else:
            predecessors = []
            for pred, _, data in self._graph.in_edges_iter([cfgnode], data=True):
                jumpkind = data['jumpkind']
                if jumpkind != 'Ijk_FakeRet':
                    predecessors.append(pred)
            return predecessors

    def get_successors(self, basic_block, excluding_fakeret=True):
        if not excluding_fakeret:
            if basic_block in self._graph:
                return self._graph.successors(basic_block)
            else:
                return []
        else:
            successors = []
            for _, suc, data in self._graph.out_edges_iter([basic_block], data=True):
                jumpkind = data['jumpkind']
                if jumpkind != 'Ijk_FakeRet':
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

    def get_node(self, addr_tuple):
        """
        Get a single node from node key.

        :param addr_tuple: The node key
        :return:
        """
        if addr_tuple in self._nodes.keys():
            return self._nodes[addr_tuple]
        else:
            return None

    def nodes(self):
        return self._graph.nodes()

    def get_any_node(self, addr, is_syscall=None, anyaddr=False):
        """
        Get an artitrary CFGNode (without considering their contexts) from our graph.

        :param addr: Address of the beginning of the basic block. Set anyaddr to True to support arbitrary address.
        :param is_syscall: Whether you want to get the syscall node or any other node. This is due to the fact that
                        syscall SimProcedures have the same address as the targer it returns to.
                        None means get either, True means get a syscall node, False means get something that isn't
                        a syscall node.
        :param anyaddr: If anyaddr is True, then addr doesn't have to be the beginning address of a basic block.
                        `anyaddr=True` makes more sense after the CFG is normalized.
        :return: A CFGNode if there is any that satisfies given conditions, or None otherwise
        """

        # TODO: Loop though self._nodes instead of self.graph.nodes()
        # TODO: Of course, I should first fix the issue that .normalize() doesn't update self._nodes

        for n in self.graph.nodes_iter():
            cond = n.looping_times == 0
            if anyaddr and n.size is not None:
                cond = cond and (addr >= n.addr and addr < n.addr + n.size)
            else:
                cond = cond  and (addr == n.addr)
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
        return self.project.factory.sim_run(cfg_node.input_state)

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
                elif is_syscall == False and not cfg_node.is_syscall:
                    results.append(cfg_node)
                else:
                    results.append(cfg_node)

        return results

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
            self._graph.remove_edge(edge)

    def is_thumb_addr(self, addr):
        return addr in self._thumb_addrs

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
                (b.rebase_addr + start, b.rebase_addr + start + len(cbacker))
                for start, cbacker in self.project.loader.memory.cbackers
                ]

        memory_regions = sorted(memory_regions, key=lambda x: x[0])

        return memory_regions

    #
    # Analyze function features
    #

    def _analyze_function_features(self):
        """
        For each function in the function_manager, try to determine if it returns or not. A function does not return if
        it calls another function that is known to be not returning, and this function does not have other exits.

        We might as well analyze other features of functions in the future.
        """

        changes = {
            'functions_return': [],
            'functions_do_not_return': []
        }

        for func in self.kb.functions.values():
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
                    if target_func.returning is False:
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

            if all([i is False for _, i in all_endpoints_returning]):
                # All target functions that this function calls is not returning
                func.returning = False
                changes['functions_do_not_return'].append(func)

            if all_endpoints_returning and all([ tpl == ("transition", True) for tpl in all_endpoints_returning ]):
                func.returning = True
                changes['functions_return'].append(func)

        return changes
