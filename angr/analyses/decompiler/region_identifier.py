from itertools import count
import logging

import networkx

import ailment
from claripy.utils.orderedset import OrderedSet

from ...utils.graph import dfs_back_edges, subgraph_between_nodes, dominates, shallow_reverse
from .. import Analysis, register_analysis
from .utils import replace_last_statement
from .structurer_nodes import MultiNode, ConditionNode
from .graph_region import GraphRegion
from .condition_processor import ConditionProcessor

l = logging.getLogger(name=__name__)


# an ever-incrementing counter
CONDITIONNODE_ADDR = count(0xff000000)


class RegionIdentifier(Analysis):
    """
    Identifies regions within a function.
    """
    def __init__(self, func, cond_proc=None, graph=None):
        self.function = func
        self.cond_proc = cond_proc if cond_proc is not None else ConditionProcessor()
        self._graph = graph if graph is not None else self.function.graph

        self.region = None
        self._start_node = None
        self._loop_headers = None

        self._analyze()

    @staticmethod
    def slice_graph(graph, node, frontier, include_frontier=False):
        """
        Generate a slice of the graph from the head node to the given frontier.

        :param networkx.DiGraph graph: The graph to work on.
        :param node: The starting node in the graph.
        :param frontier: A list of frontier nodes.
        :param bool include_frontier: Whether the frontier nodes are included in the slice or not.
        :return: A subgraph.
        :rtype: networkx.DiGraph
        """

        subgraph = subgraph_between_nodes(graph, node, frontier, include_frontier=include_frontier)
        if not list(subgraph.nodes):
            # HACK: FIXME: for infinite loop nodes, this would return an empty set, so we include the loop body itself
            # Make sure this makes sense (EDG thinks it does)
            if (node, node) in graph.edges:
                subgraph.add_edge(node, node)
        return subgraph

    def _analyze(self):

        # make a copy of the graph
        graph = networkx.DiGraph(self._graph)

        # preprocess: make it a super graph
        self._make_supergraph(graph)

        self._start_node = self._get_start_node(graph)

        # preprocess: find loop headers
        self._loop_headers = self._find_loop_headers(graph)

        self.region = self._make_regions(graph)

    @staticmethod
    def _get_start_node(graph):
        return next(n for n in graph.nodes() if graph.in_degree(n) == 0)

    def _test_reducibility(self):

        # make a copy of the graph
        graph = networkx.DiGraph(self._graph)

        # preprocess: make it a super graph
        self._make_supergraph(graph)

        while True:

            changed = False

            # find a node with a back-edge, remove the edge (deleting the loop), and replace it with a MultiNode
            changed |= self._remove_self_loop(graph)

            # find a node that has only one predecessor, and merge it with its predecessor (replace them with a
            # MultiNode)
            changed |= self._merge_single_entry_node(graph)

            if not changed:
                # a fixed-point is reached
                break

    def _make_supergraph(self, graph):

        while True:
            for src, dst, data in graph.edges(data=True):
                type_ = data.get('type', None)
                if type_ == 'fake_return':
                    if len(list(graph.successors(src))) == 1 and len(list(graph.predecessors(dst))) == 1:
                        self._merge_nodes(graph, src, dst, force_multinode=True)
                        break
                elif type_ == 'call':
                    graph.remove_node(dst)
                    break
            else:
                break

    def _find_loop_headers(self, graph):
        return OrderedSet(sorted((t for _,t in dfs_back_edges(graph, self._start_node)), key=lambda x: x.addr))

    def _find_initial_loop_nodes(self, graph, head):
        # TODO optimize
        latching_nodes = { s for s,t in dfs_back_edges(graph, self._start_node) if t == head }
        loop_subgraph = self.slice_graph(graph, head, latching_nodes, include_frontier=True)
        nodes = set(loop_subgraph.nodes())
        return nodes

    def _refine_loop(self, graph, head, initial_loop_nodes, initial_exit_nodes):
        refined_loop_nodes = initial_loop_nodes.copy()
        refined_exit_nodes = initial_exit_nodes.copy()

        idom = networkx.immediate_dominators(graph, self._start_node)

        new_exit_nodes = refined_exit_nodes
        while len(refined_exit_nodes) > 1 and new_exit_nodes:
            new_exit_nodes = set()
            for n in list(refined_exit_nodes):
                if all(pred in refined_loop_nodes for pred in graph.predecessors(n)) and dominates(idom, head, n):
                    refined_loop_nodes.add(n)
                    refined_exit_nodes.remove(n)
                    for u in (set(graph.successors(n)) - refined_loop_nodes):
                        new_exit_nodes.add(u)
            refined_exit_nodes |= new_exit_nodes

        refined_loop_nodes = refined_loop_nodes - refined_exit_nodes

        return refined_loop_nodes, refined_exit_nodes

    def _remove_self_loop(self, graph):

        r = False

        while True:
            for node in graph.nodes():
                if node in graph[node]:
                    # found a self loop
                    self._remove_node(graph, node)
                    r = True
                    break
            else:
                break

        return r

    def _merge_single_entry_node(self, graph):

        r = False

        while True:
            for node in networkx.dfs_postorder_nodes(graph):
                preds = graph.predecessors(node)
                if len(preds) == 1:
                    # merge the two nodes
                    self._absorb_node(graph, preds[0], node)
                    r = True
                    break
            else:
                break

        return r

    def _make_regions(self, graph):

        structured_loop_headers = set()
        new_regions = [ ]

        # FIXME: _get_start_node() will fail if the graph is just a loop

        # Find all loops
        while True:
            restart = False

            self._start_node = self._get_start_node(graph)

            # Start from loops
            for node in self._loop_headers:
                if node in structured_loop_headers:
                    continue
                region = self._make_cyclic_region(node, graph)
                if region is not None:
                    l.debug("Structured a loop region %r.", region)
                    new_regions.append(region)
                    structured_loop_headers.add(node)
                    restart = True
                    break

            if restart:
                continue

            break

        new_regions.append(GraphRegion(self._get_start_node(graph), graph, None, None, False))

        l.debug("Identified %d loop regions.", len(structured_loop_headers))
        l.debug("No more loops left. Start structuring acyclic regions.")
        # No more loops left. Structure acyclic regions.
        while new_regions:
            region = new_regions.pop(0)
            head = region.head
            subgraph = region.graph

            failed_region_attempts = set()
            while self._make_acyclic_region(head, subgraph, region.graph_with_successors, failed_region_attempts,
                                            region.cyclic):
                if head not in subgraph:
                    # update head
                    head = next(iter(n for n in subgraph.nodes() if n.addr == head.addr))

            head = next(iter(n for n in subgraph.nodes() if n.addr == head.addr))
            region.head = head

        if len(graph.nodes()) == 1 and isinstance(list(graph.nodes())[0], GraphRegion):
            return list(graph.nodes())[0]
        # create a large graph region
        new_head = self._get_start_node(graph)
        region = GraphRegion(new_head, graph, None, None, False)
        return region

    #
    # Cyclic regions
    #

    def _make_cyclic_region(self, head, graph):

        l.debug("Found cyclic region at %#08x", head.addr)
        initial_loop_nodes = self._find_initial_loop_nodes(graph, head)
        l.debug("Initial loop nodes %s", self._dbg_block_list(initial_loop_nodes))

        # Make sure there is no other loop contained in the current loop
        if {n for n in initial_loop_nodes if n.addr != head.addr}.intersection(self._loop_headers):
            return None

        normal_entries = {n for n in graph.predecessors(head) if n not in initial_loop_nodes}
        abnormal_entries = set()
        for n in initial_loop_nodes:
            if n == head:
                continue
            preds = set(graph.predecessors(n))
            abnormal_entries |= (preds - initial_loop_nodes)
        l.debug("Normal entries %s", self._dbg_block_list(normal_entries))
        l.debug("Abnormal entries %s", self._dbg_block_list(abnormal_entries))

        initial_exit_nodes = set()
        for n in initial_loop_nodes:
            succs = set(graph.successors(n))
            initial_exit_nodes |= (succs - initial_loop_nodes)

        l.debug("Initial exit nodes %s", self._dbg_block_list(initial_exit_nodes))

        refined_loop_nodes, refined_exit_nodes = self._refine_loop(graph, head, initial_loop_nodes,
                                                                   initial_exit_nodes)
        l.debug("Refined loop nodes %s", self._dbg_block_list(refined_loop_nodes))
        l.debug("Refined exit nodes %s", self._dbg_block_list(refined_exit_nodes))

        if len(refined_exit_nodes) > 1:
            # self._get_start_node(graph)
            node_post_order = list(networkx.dfs_postorder_nodes(graph, head))
            sorted_exit_nodes = sorted(list(refined_exit_nodes), key=node_post_order.index)
            normal_exit_node = sorted_exit_nodes[0]
            abnormal_exit_nodes = set(sorted_exit_nodes[1:])
        else:
            normal_exit_node = next(iter(refined_exit_nodes)) if len(refined_exit_nodes) > 0 else None
            abnormal_exit_nodes = set()

        region = self._abstract_cyclic_region(graph, refined_loop_nodes, head, normal_entries, abnormal_entries,
                                              normal_exit_node, abnormal_exit_nodes)
        if len(region.successors) > 1:
            # multi-successor region. refinement is required
            self._refine_loop_successors(region, graph)

        return region

    def _refine_loop_successors(self, region, graph):
        """
        If there are multiple successors of a loop, convert them into conditional gotos. Eventually there should be
        only one loop successor.

        :param GraphRegion region:      The cyclic region to refine.
        :param networkx.DiGraph graph:  The current graph that is being structured.
        :return:                        None
        """
        if len(region.successors) <= 1:
            return

        # recover reaching conditions
        self.cond_proc.recover_reaching_conditions(region, with_successors=True)

        successors = list(region.successors)

        condnode_addr = next(CONDITIONNODE_ADDR)
        # create a new successor
        cond = ConditionNode(
            condnode_addr,
            None,
            self.cond_proc.reaching_conditions[successors[0]],
            successors[0],
            false_node=None,
        )
        for succ in successors[1:]:
            cond = ConditionNode(condnode_addr,
                                 None,
                                 self.cond_proc.reaching_conditions[succ],
                                 succ,
                                 false_node=cond,
                                 )

        g = region.graph_with_successors

        # modify region in place
        region.successors = {cond}
        for succ in successors:
            for src, _, data in list(g.in_edges(succ, data=True)):
                removed_edges = [ ]
                for src2src, _, data_ in list(g.in_edges(src, data=True)):
                    removed_edges.append((src2src, src, data_))
                    g.remove_edge(src2src, src)
                g.remove_edge(src, succ)

                # TODO: rewrite the conditional jumps in src so that it goes to cond-node instead.

                # modify the last statement of src so that it jumps to cond
                replaced_any_stmt = False
                last_stmts = self.cond_proc.get_last_statements(src)
                for last_stmt in last_stmts:
                    if isinstance(last_stmt, ailment.Stmt.ConditionalJump):
                        if last_stmt.true_target.value == succ.addr:
                            new_last_stmt = ailment.Stmt.ConditionalJump(
                                last_stmt.idx,
                                last_stmt.condition,
                                ailment.Expr.Const(None, None, condnode_addr, self.project.arch.bits),
                                last_stmt.false_target,
                                ins_addr=last_stmt.ins_addr,
                            )
                        elif last_stmt.false_target.value == succ.addr:
                            new_last_stmt = ailment.Stmt.ConditionalJump(
                                last_stmt.idx,
                                last_stmt.condition,
                                last_stmt.true_target,
                                ailment.Expr.Const(None, None, condnode_addr, self.project.arch.bits),
                                ins_addr=last_stmt.ins_addr,
                            )
                        else:
                            # none of the two branches is jumping out of the loop
                            continue
                    else:
                        new_last_stmt = ailment.Stmt.Jump(
                            last_stmt.idx,
                            ailment.Expr.Const(None, None, condnode_addr, self.project.arch.bits),
                            ins_addr=last_stmt.ins_addr,
                        )
                    replace_last_statement(src, last_stmt, new_last_stmt)
                    replaced_any_stmt = True
                if not replaced_any_stmt:
                    l.warning("No statement was replaced. Is there anything wrong?")
                    raise Exception()

                # add src back
                for src2src, _, data_ in removed_edges:
                    g.add_edge(src2src, src, **data_)

                g.add_edge(src, cond, **data)

        # modify graph
        graph.add_edge(region, cond)
        for succ in successors:
            edge_data = graph.get_edge_data(region, succ)
            graph.remove_edge(region, succ)
            graph.add_edge(cond, succ, **edge_data)

    #
    # Acyclic regions
    #

    def _make_acyclic_region(self, head, graph, secondary_graph, failed_region_attempts, cyclic):
        # pre-processing

        # we need to create a copy of the original graph if
        # - there are in edges to the head node, or
        # - there are more than one end nodes

        head_inedges = list(graph.in_edges(head))
        if head_inedges:
            # we need a copy of the graph to remove edges coming into the head
            graph_copy = networkx.DiGraph(graph)
            # remove any in-edge to the head node
            for src, _ in head_inedges:
                graph_copy.remove_edge(src, head)
        else:
            graph_copy = graph

        endnodes = [node for node in graph_copy.nodes() if graph_copy.out_degree(node) == 0]
        if len(endnodes) == 0:
            # sanity check: there should be at least one end node
            l.critical("No end node is found in a supposedly acyclic graph. Is it really acyclic?")
            return False

        if len(endnodes) > 1:
            # we need a copy of the graph!
            graph_copy = networkx.DiGraph(graph_copy)

            # if this graph has multiple end nodes: create a single end node
            dummy_endnode = None
            if len(endnodes) > 1:
                dummy_endnode = "DUMMY_ENDNODE"
                for endnode in endnodes:
                    graph_copy.add_edge(endnode, dummy_endnode)
                endnodes = [ dummy_endnode ]
        else:
            dummy_endnode = None

        # compute dominator tree
        doms = networkx.immediate_dominators(graph_copy, head)

        # compute post-dominator tree
        inverted_graph = shallow_reverse(graph_copy)
        postdoms = networkx.immediate_dominators(inverted_graph, endnodes[0])

        # dominance frontiers
        df = networkx.algorithms.dominance_frontiers(graph_copy, head)

        # visit the nodes in post-order
        for node in networkx.dfs_postorder_nodes(graph_copy, source=head):
            if node is dummy_endnode:
                # skip the dummy endnode
                continue
            if cyclic and node is head:
                continue

            out_degree = graph_copy.out_degree[node]
            if out_degree == 0:
                # the root element of the region hierarchy should always be a GraphRegion,
                # so we transform it into one, if necessary
                if graph_copy.in_degree(node) == 0 and not isinstance(node, GraphRegion):
                    subgraph = networkx.DiGraph()
                    subgraph.add_node(node)
                    self._abstract_acyclic_region(graph, GraphRegion(node, subgraph, None, None, False), [],
                                                  secondary_graph=secondary_graph)
                continue

            # test if this node is an entry to a single-entry, single-successor region
            levels = 0
            postdom_node = postdoms.get(node, None)
            while postdom_node is not None:
                if (node, postdom_node) not in failed_region_attempts:
                    if self._check_region(graph_copy, node, postdom_node, doms, df):
                        frontier = [ postdom_node ]
                        region = self._compute_region(graph_copy, node, frontier, dummy_endnode=dummy_endnode)
                        if region is not None:
                            # l.debug("Walked back %d levels in postdom tree.", levels)
                            l.debug("Node %r, frontier %r.", node, frontier)
                            # l.debug("Identified an acyclic region %s.", self._dbg_block_list(region.graph.nodes()))
                            self._abstract_acyclic_region(graph, region, frontier, dummy_endnode=dummy_endnode,
                                                          secondary_graph=secondary_graph)
                            # assert dummy_endnode not in graph
                            return True

                failed_region_attempts.add((node, postdom_node))
                if not dominates(doms, node, postdom_node):
                    break
                if postdom_node is postdoms.get(postdom_node, None):
                    break
                postdom_node = postdoms.get(postdom_node, None)
                levels += 1
            # l.debug("Walked back %d levels in postdom tree and did not find anything for %r. Next.", levels, node)

        return False

    @staticmethod
    def _check_region(graph, start_node, end_node, doms, df):
        """

        :param graph:
        :param start_node:
        :param end_node:
        :param doms:
        :param df:
        :return:
        """

        # if the exit node is the header of a loop that contains the start node, the dominance frontier should only
        # contain the exit node.
        if not dominates(doms, start_node, end_node):
            frontier = df.get(start_node, set())
            for node in frontier:
                if node is not start_node and node is not end_node:
                    return False

        # no edges should enter the region.
        for node in df.get(end_node, set()):
            if dominates(doms, start_node, node) and node is not end_node:
                return False

        # no edges should leave the region.
        for node in df.get(start_node, set()):
            if node is start_node or node is end_node:
                continue
            if node not in df.get(end_node, set()):
                return False
            for pred in graph.predecessors(node):
                if dominates(doms, start_node, pred) and not dominates(doms, end_node, pred):
                    return False

        return True

    @staticmethod
    def _compute_region(graph, node, frontier, include_frontier=False, dummy_endnode=None):

        subgraph = networkx.DiGraph()
        frontier_edges = [ ]
        queue = [ node ]
        traversed = set()

        while queue:
            node_ = queue.pop()
            if node_ in frontier:
                continue
            traversed.add(node_)
            subgraph.add_node(node_)

            for succ in graph.successors(node_):
                edge_data = graph.get_edge_data(node_, succ)

                if node_ in frontier and succ in traversed:
                    if include_frontier:
                        # if frontier nodes are included, do not keep traversing their successors
                        # however, if it has an edge to an already traversed node, we should add that edge
                        subgraph.add_edge(node_, succ, **edge_data)
                    else:
                        frontier_edges.append((node_, succ, edge_data))
                    continue

                if succ is dummy_endnode:
                    continue

                if succ in frontier:
                    if not include_frontier:
                        # skip all frontier nodes
                        frontier_edges.append((node_, succ, edge_data))
                        continue
                subgraph.add_edge(node_, succ, **edge_data)
                if succ in traversed:
                    continue
                queue.append(succ)

        if dummy_endnode is not None:
            frontier = { n for n in frontier if n is not dummy_endnode }

        if subgraph.number_of_nodes() > 1:
            subgraph_with_frontier = networkx.DiGraph(subgraph)
            for src, dst, edge_data in frontier_edges:
                if dst is not dummy_endnode:
                    subgraph_with_frontier.add_edge(src, dst, **edge_data)
            # assert dummy_endnode not in frontier
            # assert dummy_endnode not in subgraph_with_frontier
            return GraphRegion(node, subgraph, frontier, subgraph_with_frontier, False)
        else:
            return None

    def _abstract_acyclic_region(self, graph, region, frontier, dummy_endnode=None, secondary_graph=None):

        in_edges = self._region_in_edges(graph, region, data=True)
        out_edges = self._region_out_edges(graph, region, data=True)

        nodes_set = set()
        for node_ in list(region.graph.nodes()):
            nodes_set.add(node_)
            if node_ is not dummy_endnode:
                graph.remove_node(node_)

        graph.add_node(region)

        for src, _, data in in_edges:
            if src not in nodes_set:
                graph.add_edge(src, region, **data)

        for _, dst, data in out_edges:
            if dst not in nodes_set:
                graph.add_edge(region, dst, **data)

        if frontier:
            for frontier_node in frontier:
                if frontier_node is not dummy_endnode:
                    graph.add_edge(region, frontier_node)

        if secondary_graph is not None:
            self._abstract_acyclic_region(secondary_graph, region, { })

    @staticmethod
    def _abstract_cyclic_region(graph, loop_nodes, head, normal_entries, abnormal_entries, normal_exit_node,
                                abnormal_exit_nodes):
        region = GraphRegion(head, None, None, None, True)

        subgraph = networkx.DiGraph()
        region_outedges = [ ]

        graph.add_node(region)
        for node in loop_nodes:
            subgraph.add_node(node)
            in_edges = list(graph.in_edges(node, data=True))
            out_edges = list(graph.out_edges(node, data=True))

            for src, dst, data in in_edges:
                if src in normal_entries:
                    graph.add_edge(src, region, **data)
                elif src in abnormal_entries:
                    data['region_dst_node'] = dst
                    graph.add_edge(src, region, **data)
                elif src in loop_nodes:
                    subgraph.add_edge(src, dst, **data)
                elif src is region:
                    subgraph.add_edge(head, dst, **data)
                else:
                    assert 0

            for src, dst, data in out_edges:
                if dst in loop_nodes:
                    subgraph.add_edge(src, dst, **data)
                elif dst is region:
                    subgraph.add_edge(src, head, **data)
                elif dst is normal_exit_node:
                    region_outedges.append((node, dst))
                    graph.add_edge(region, dst, **data)
                elif dst in abnormal_exit_nodes:
                    region_outedges.append((node, dst))
                    # data['region_src_node'] = src
                    graph.add_edge(region, dst, **data)
                else:
                    assert 0

        subgraph_with_exits = networkx.DiGraph(subgraph)
        for src, dst in region_outedges:
            subgraph_with_exits.add_edge(src, dst)
        region.graph = subgraph
        region.graph_with_successors = subgraph_with_exits
        if normal_exit_node is not None:
            region.successors = [normal_exit_node]
        else:
            region.successors = [ ]
        region.successors += list(abnormal_exit_nodes)

        for node in loop_nodes:
            graph.remove_node(node)

        return region

    @staticmethod
    def _region_in_edges(graph, region, data=False):

        return list(graph.in_edges(region.head, data=data))

    @staticmethod
    def _region_out_edges(graph, region, data=False):

        out_edges = [ ]
        for node in region.graph.nodes():
            out_ = graph.out_edges(node, data=data)
            for _, dst, data_ in out_:
                if dst in region.graph:
                    continue
                out_edges.append((region, dst, data_))
        return out_edges

    def _remove_node(self, graph, node):  # pylint:disable=no-self-use

        in_edges = [ (src, dst, data) for (src, dst, data) in graph.in_edges(node, data=True) if not src is node ]
        out_edges = [ (src, dst, data) for (src, dst, data) in graph.out_edges(node, data=True) if not dst is node ]

        if len(in_edges) <= 1 and len(out_edges) <= 1:
            # it forms a region by itself :-)
            new_node = None

        else:
            new_node = MultiNode([ node ])

        graph.remove_node(node)

        if new_node is not None:
            for src, _, data in in_edges:
                graph.add_edge(src, new_node, **data)

            for _, dst, data in out_edges:
                graph.add_edge(new_node, dst, **data)

    def _merge_nodes(self, graph, node_a, node_b, force_multinode=False):  # pylint:disable=no-self-use

        in_edges = list(graph.in_edges(node_a, data=True))
        out_edges = list(graph.out_edges(node_b, data=True))

        if not force_multinode and len(in_edges) <= 1 and len(out_edges) <= 1:
            # it forms a region by itself :-)
            new_node = None

        else:
            new_node = MultiNode([ node_a, node_b ])

        graph.remove_node(node_a)
        graph.remove_node(node_b)

        if new_node is not None:
            graph.add_node(new_node)

            for src, _, data in in_edges:
                if src is node_b:
                    src = new_node
                graph.add_edge(src, new_node, **data)

            for _, dst, data in out_edges:
                if dst is node_a:
                    dst = new_node
                graph.add_edge(new_node, dst, **data)

        assert not node_a in graph
        assert not node_b in graph

    def _absorb_node(self, graph, node_mommy, node_kiddie, force_multinode=False):  # pylint:disable=no-self-use

        in_edges_mommy = graph.in_edges(node_mommy, data=True)
        out_edges_mommy = graph.out_edges(node_mommy, data=True)
        out_edges_kiddie = graph.out_edges(node_kiddie, data=True)

        if not force_multinode and len(in_edges_mommy) <= 1 and len(out_edges_kiddie) <= 1:
            # it forms a region by itself :-)
            new_node = None

        else:
            new_node = MultiNode([node_mommy, node_kiddie])

        graph.remove_node(node_mommy)
        graph.remove_node(node_kiddie)

        if new_node is not None:
            graph.add_node(new_node)

            for src, _, data in in_edges_mommy:
                if src == node_kiddie:
                    src = new_node
                graph.add_edge(src, new_node, **data)

            for _, dst, data in out_edges_mommy:
                if dst == node_kiddie:
                    continue
                if dst == node_mommy:
                    dst = new_node
                graph.add_edge(new_node, dst, **data)

            for _, dst, data in out_edges_kiddie:
                if dst == node_mommy:
                    dst = new_node
                graph.add_edge(new_node, dst, **data)

        assert not node_mommy in graph
        assert not node_kiddie in graph

    @staticmethod
    def _dbg_block_list(blocks):
        return [(hex(b.addr) if hasattr(b, 'addr') else repr(b)) for b in blocks]


register_analysis(RegionIdentifier, 'RegionIdentifier')
