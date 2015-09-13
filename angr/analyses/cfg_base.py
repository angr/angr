import networkx
import logging
from ..errors import AngrCFGError

l = logging.getLogger(name="angr.cfg_base")

class CFGBase(object):
    def __init__(self, project, context_sensitivity_level):
        self._project = project

        # Initialization
        self._graph = None
        self._nodes = None
        self._edge_map = None
        self._loop_back_edges = None
        self._overlapped_loop_headers = None
        self._function_manager = None
        self._thumb_addrs = set()
        if context_sensitivity_level < 0:
            raise Exception("Unsupported context sensitivity level %d" % context_sensitivity_level)
        self._context_sensitivity_level=context_sensitivity_level

    def __contains__(self, cfg_node):
        return cfg_node in self._graph

    @property
    def context_sensitivity_level(self):
        return self._context_sensitivity_level

    def _initialize_cfg(self):
        '''
        Re-create the DiGraph
        '''
        self._graph = networkx.DiGraph()

    # pylint: disable=no-self-use
    def copy(self):
        raise Exception("Not implemented.")

    def _construct(self):
        raise Exception("Not implemented")

    def output(self):
        raise Exception("Not implemented")

    # TODO: Mark as deprecated
    def get_bbl_dict(self):
        return self._nodes

    def get_predecessors(self, basic_block, excluding_fakeret=True):
        if not excluding_fakeret:
            if basic_block in self._graph:
                return self._graph.predecessors(basic_block)
            else:
                return []
        else:
            predecessors = []
            for pred, _, data in self._graph.in_edges_iter([basic_block], data=True):
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
        return self._project.factory.sim_run(cfg_node.input_state)

    def irsb_from_node(self, cfg_node):
        '''
        Create SimRun from a CFGNode object.
        '''
        return self._get_irsb(cfg_node)

    def get_any_irsb(self, addr):
        '''
        Returns a SimRun of a certain address. If there are many SimRuns with the same address in CFG,
        return an arbitrary one.
        You should never assume this method returns a specific one.
        '''
        cfg_node = self.get_any_node(addr)

        return self._get_irsb(cfg_node)

    def get_all_nodes(self, addr, is_syscall=None):
        """
        Get all CFGNodes whose address is the specified one,
        :param addr: Address of the node
        :param is_syscall: True returns the syscall node, False returns the normal CFGNode, None returns both
        :return: all CFGNodes
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
        '''
        Returns all SimRuns of a certain address, without considering contexts.
        '''

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
        '''
        Returns all nodes that has an out degree >= 2
        '''
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

    @property
    def function_manager(self):
        return self._function_manager

    def is_thumb_addr(self, addr):
        return addr in self._thumb_addrs

