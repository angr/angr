from collections import defaultdict

import networkx

import logging
import simuvex
import angr
from .exit_wrapper import SimExitWrapper
import pdb

l = logging.getLogger(name="angr.cfg_base")

class CFGBase(object):
    def __init__(self, project, context_sensitivity_level):
        self._project = project

        # Initialization
        self._graph = None
        self._bbl_dict = None
        self._edge_map = None
        self._loop_back_edges = None
        self._overlapped_loop_headers = None
        self._function_manager = None
        self._thumb_addrs = set()
        if context_sensitivity_level <= 0:
            raise Exception("Unsupported context sensitivity level %d" % context_sensitivity_level)
        self._context_sensitivity_level=context_sensitivity_level

    @property
    def context_sensitivity_level(self):
        return self._context_sensitivity_level

    def _initialize_cfg(self):
        '''
        Re-create the DiGraph
        '''
        self._graph = networkx.DiGraph()

    def copy(self):
        raise Exception("Not implemented.")

    def construct(self):
        raise Exception("Not implemented")

    def output(self):
        raise Exception("Not implemented")

    # TODO: Mark as deprecated
    def get_bbl_dict(self):
        return self._bbl_dict

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

    def get_irsb(self, addr_tuple):
        # TODO: Support getting irsb at arbitary address
        if addr_tuple in self._bbl_dict.keys():
            return self._bbl_dict[addr_tuple]
        else:
            return None

    def get_nodes(self):
        return self._graph.nodes()

    def get_any_irsb(self, addr):
        for addr_tuple in self._bbl_dict.keys():
            addr_ = addr_tuple[-1]
            if addr_ == addr:
                return self._bbl_dict[addr_tuple]
        return None

    def get_all_irsbs(self, addr):
        results = []
        for addr_tuple in self._bbl_dict.keys():
            addr_ = addr_tuple[-1]
            if addr_ == addr:
                results.append(self._bbl_dict[addr_tuple])
        return results

    def get_loop_back_edges(self):
        return self._loop_back_edges

    def get_irsb_addr_set(self):
        irsb_addr_set = set()
        for tpl, _ in self._bbl_dict:
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
