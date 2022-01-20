from typing import Optional, Tuple, Any
from collections import defaultdict

import networkx

import ailment

from .structurer_nodes import MultiNode, BaseNode, CodeNode, SequenceNode, ConditionNode, SwitchCaseNode, \
    CascadingConditionNode


def remove_last_statement(node):
    stmt = None

    if type(node) is CodeNode:
        stmt = remove_last_statement(node.node)
    elif type(node) is ailment.Block:
        stmt = node.statements[-1]
        node.statements = node.statements[:-1]
    elif type(node) is MultiNode:
        if node.nodes:
            stmt = remove_last_statement(node.nodes[-1])
            if BaseNode.test_empty_node(node.nodes[-1]):
                node.nodes = node.nodes[:-1]
    elif type(node) is SequenceNode:
        if node.nodes:
            stmt = remove_last_statement(node.nodes[-1])
            if BaseNode.test_empty_node(node.nodes[-1]):
                node.nodes = node.nodes[:-1]
    else:
        raise NotImplementedError()

    return stmt


def append_statement(node, stmt):

    if type(node) is CodeNode:
        append_statement(node.node, stmt)
        return
    if type(node) is ailment.Block:
        node.statements.append(stmt)
        return
    if type(node) is MultiNode:
        if node.nodes:
            append_statement(node.nodes[-1], stmt)
        else:
            raise NotImplementedError()
        return
    if type(node) is SequenceNode:
        if node.nodes:
            append_statement(node.nodes[-1], stmt)
        else:
            raise NotImplementedError()
        return

    raise NotImplementedError()


def replace_last_statement(node, old_stmt, new_stmt):

    if type(node) is CodeNode:
        replace_last_statement(node.node, old_stmt, new_stmt)
        return
    if type(node) is ailment.Block:
        if node.statements[-1] is old_stmt:
            node.statements[-1] = new_stmt
        return
    if type(node) is MultiNode:
        if node.nodes:
            replace_last_statement(node.nodes[-1], old_stmt, new_stmt)
        return
    if type(node) is SequenceNode:
        if node.nodes:
            replace_last_statement(node.nodes[-1], old_stmt, new_stmt)
        return
    if type(node) is ConditionNode:
        if node.true_node is not None:
            replace_last_statement(node.true_node, old_stmt, new_stmt)
        if node.false_node is not None:
            replace_last_statement(node.false_node, old_stmt, new_stmt)
        return

    raise NotImplementedError()


def extract_jump_targets(stmt):
    """
    Extract concrete goto targets from a Jump or a ConditionalJump statement.

    :param stmt:    The statement to analyze.
    :return:        A list of known concrete jump targets.
    :rtype:         list
    """

    targets = [ ]

    if isinstance(stmt, ailment.Stmt.Jump):
        if isinstance(stmt.target, ailment.Expr.Const):
            targets.append(stmt.target.value)
    elif isinstance(stmt, ailment.Stmt.ConditionalJump):
        if isinstance(stmt.true_target, ailment.Expr.Const):
            targets.append(stmt.true_target.value)
        if isinstance(stmt.false_target, ailment.Expr.Const):
            targets.append(stmt.false_target.value)

    return targets


def switch_extract_cmp_bounds(last_stmt: ailment.Stmt.ConditionalJump) -> Optional[Tuple[Any,int,int]]:
    """
    Check the last statement of the switch-case header node, and extract lower+upper bounds for the comparison.

    :param last_stmt:   The last statement of the switch-case header node.
    :return:            A tuple of (comparison expression, lower bound, upper bound), or None
    """

    if not isinstance(last_stmt, ailment.Stmt.ConditionalJump):
        return None

    # TODO: Add more operations
    if last_stmt.condition.op == 'CmpLE':
        if not isinstance(last_stmt.condition.operands[1], ailment.Expr.Const):
            return None
        cmp_ub = last_stmt.condition.operands[1].value
        cmp_lb = 0
        cmp = last_stmt.condition.operands[0]
        if isinstance(cmp, ailment.Expr.BinaryOp) and \
                cmp.op == 'Sub' and \
                isinstance(cmp.operands[1], ailment.Expr.Const):
            cmp_ub += cmp.operands[1].value
            cmp_lb += cmp.operands[1].value
            cmp = cmp.operands[0]
        return cmp, cmp_lb, cmp_ub

    return None


def get_ast_subexprs(claripy_ast):

    queue = [ claripy_ast ]
    while queue:
        ast = queue.pop(0)
        if ast.op == "And":
            queue += ast.args[1:]
            yield ast.args[0]
        else:
            yield ast


def insert_node(parent, insert_idx, node, node_idx, label=None, insert_location=None):

    if isinstance(parent, SequenceNode):
        parent.nodes.insert(insert_idx, node)
    elif isinstance(parent, CodeNode):
        # Make a new sequence node
        seq = SequenceNode(parent.addr, nodes=[parent.node, node])
        parent.node = seq
    elif isinstance(parent, MultiNode):
        parent.nodes.insert(insert_idx, node)
    elif isinstance(parent, ConditionNode):
        if node_idx == 0:
            # true node
            if not isinstance(parent.true_node, (SequenceNode, MultiNode)):
                parent.true_node = SequenceNode(parent.true_node.addr, nodes=[parent.true_node])
            insert_node(parent.true_node, insert_idx - node_idx, node, 0)
        else:
            # false node
            if not isinstance(parent.false_node, (SequenceNode, MultiNode)):
                parent.false_node = SequenceNode(parent.false_node.addr, nodes=[parent.false_node])
            insert_node(parent.false_node, insert_idx - node_idx, node, 0)
    elif isinstance(parent, CascadingConditionNode):
        cond, child_node = parent.condition_and_nodes[node_idx]
        if not isinstance(child_node, SequenceNode):
            child_node = SequenceNode(child_node.addr, nodes=[child_node])
            parent.condition_and_nodes[node_idx] = (cond, child_node)
        insert_node(child_node, insert_idx - node_idx, node, 0)
    elif isinstance(parent, SwitchCaseNode):
        # note that this case will be hit only when the parent node is not a container, such as SequenceNode or
        # MultiNode. we always need to create a new SequenceNode and replace the original node in place.
        if label == 'switch_expr':
            raise TypeError("You cannot insert a node after an expression.")
        if label == 'case':
            # node_idx is the case number
            if insert_location == 'after':
                new_nodes = [ parent.cases[node_idx], node ]
            elif insert_location == 'before':
                new_nodes = [ node, parent.cases[node_idx] ]
            else:
                raise TypeError("Unsupported 'insert_location' value %r." % insert_location)
            seq = SequenceNode(new_nodes[0].addr, nodes=new_nodes)
            parent.cases[node_idx] = seq
        elif label == 'default':
            if insert_location == 'after':
                new_nodes = [ parent.default_node, node ]
            elif insert_location == 'before':
                new_nodes = [ node, parent.default_node ]
            else:
                raise TypeError("Unsupported 'insert_location' value %r." % insert_location)
            seq = SequenceNode(new_nodes[0].addr, nodes=new_nodes)
            parent.default_node = seq
    else:
        raise NotImplementedError()

#
# based on grapher from angr-management
#


def to_ail_supergraph(transition_graph: networkx.DiGraph) -> networkx.DiGraph:
    """
    Takes an AIL graph and converts it into a AIL graph that treats calls and redundant jumps
    as parts of a bigger block instead of transitions. Calls to returning functions do not terminate basic blocks.

    :return: A converted super transition graph
    """

    # make a copy of the graph
    transition_graph = networkx.DiGraph(transition_graph)

    # remove all edges that transitions to outside
    for src, dst, data in list(transition_graph.edges(data=True)):
        if data['type'] in ('transition', 'exception') and data.get('outside', False) is True:
            transition_graph.remove_edge(src, dst)
        # remove dead nodes
        if transition_graph.in_degree(dst) == 0:
            transition_graph.remove_node(dst)

    edges_to_shrink = set()

    # Find all edges to remove in the super graph
    for src in transition_graph.nodes():
        edges = transition_graph[src]

        # there are two types of edges we want to remove:
        # - call or fakerets, since we do not want blocks to break at calls
        # - boring jumps that directly transfer the control to the block immediately after the current block.

        if len(edges) == 1 and src.addr + src.original_size == next(iter(edges.keys())).addr:
            dst = next(iter(edges.keys()))
            dst_in_edges = transition_graph.in_edges(dst)
            if len(dst_in_edges) == 1:
                edges_to_shrink.add((src, dst))
                continue

        # skip anything that is not like a call
        if any(iter('type' in data and data['type'] not in ('fake_return', 'call') for data in edges.values())):
            continue

        for dst, data in edges.items():
            if 'type' in data and data['type'] == 'fake_return':
                if all(iter('type' in data and data['type'] in ('fake_return', 'return_from_call')
                            for _, _, data in transition_graph.in_edges(dst, data=True))):
                    edges_to_shrink.add((src, dst))
                break

    # Create the super graph
    super_graph = networkx.DiGraph()
    supernodes_map = {}

    for node in transition_graph.nodes():
        dests_and_data = transition_graph[node]

        # make a super node
        if node in supernodes_map:
            src_supernode = supernodes_map[node]
        else:
            src_supernode = SuperAILNode.from_ailnode(node)
            supernodes_map[node] = src_supernode
            # insert it into the graph
            super_graph.add_node(src_supernode)

        if not dests_and_data:
            # might be an isolated node
            continue

        # Take src_supernode off the graph since we might modify it
        if src_supernode in super_graph:
            existing_in_edges = list(super_graph.in_edges(src_supernode, data=True))
            existing_out_edges = list(super_graph.out_edges(src_supernode, data=True))
            super_graph.remove_node(src_supernode)
        else:
            existing_in_edges = [ ]
            existing_out_edges = [ ]

        for dst, data in dests_and_data.items():
            edge = (node, dst)

            if edge in edges_to_shrink:
                dst_supernode = supernodes_map.get(dst, None)
                src_supernode.insert_ailnode(dst)

                # update supernodes map
                supernodes_map[dst] = src_supernode

                # merge the other supernode
                if dst_supernode is not None:
                    src_supernode.merge(dst_supernode)

                    for src in dst_supernode.nodes:
                        supernodes_map[src] = src_supernode

                    # link all out edges of dst_supernode to src_supernode
                    for dst_, data_ in super_graph[dst_supernode].items():
                        super_graph.add_edge(src_supernode, dst_, **data_)

                    # link all in edges of dst_supernode to src_supernode
                    for src_, _, data_ in super_graph.in_edges(dst_supernode, data=True):
                        super_graph.add_edge(src_, src_supernode, **data_)

                        if 'type' in data_ and data_['type'] in {'transition', 'exception', 'call'}:
                            if not ('ins_addr' in data_ and 'stmt_idx' in data_):
                                # this is a hack to work around the issue in Function.normalize() where ins_addr and
                                # stmt_idx weren't properly set onto edges
                                continue
                            src_supernode.register_out_branch(data_['ins_addr'], data_['stmt_idx'], data_['type'],
                                                              dst_supernode.addr
                                                              )

                    super_graph.remove_node(dst_supernode)

            else:
                # make a super node
                if dst in supernodes_map:
                    dst_supernode = supernodes_map[dst]
                else:
                    dst_supernode = SuperAILNode.from_ailnode(dst)
                    supernodes_map[dst] = dst_supernode

                super_graph.add_edge(src_supernode, dst_supernode, **data)

                if 'type' in data and data['type'] in {'transition', 'exception', 'call'}:
                    if not ('ins_addr' in data and 'stmt_idx' in data):
                        # this is a hack to work around the issue in Function.normalize() where ins_addr and
                        # stmt_idx weren't properly set onto edges
                        continue
                    src_supernode.register_out_branch(data['ins_addr'], data['stmt_idx'], data['type'],
                                                      dst_supernode.addr
                                                      )

        # add back the node (in case there are no edges)
        super_graph.add_node(src_supernode)
        # add back the old edges
        for src, _, data in existing_in_edges:
            super_graph.add_edge(src, src_supernode, **data)
        for _, dst, data in existing_out_edges:
            super_graph.add_edge(src_supernode, dst, **data)

    return super_graph


class OutBranch:
    """
    Represents a branch at the end of a AILSuperNode.
    Note: this is not an edge, but instead a branch.
    """

    def __init__(self, ins_addr, stmt_idx, branch_type):

        self.ins_addr = ins_addr
        self.stmt_idx = stmt_idx
        self.type = branch_type

        self.targets = set()

    def __repr__(self):
        if self.ins_addr is None:
            return "<OutBranch at None, type %s>" % self.type
        return "<OutBranch at %#x, type %s>" % (self.ins_addr, self.type)

    def add_target(self, addr):
        self.targets.add(addr)

    def merge(self, other):
        """
        Merge with the other OutBranch descriptor.

        :param OutBranch other: The other item to merge with.
        :return: None
        """

        assert self.ins_addr == other.ins_addr
        assert self.type == other.type

        o = self.copy()
        o.targets |= other.targets

        return o

    def copy(self):
        o = OutBranch(self.ins_addr, self.stmt_idx, self.type)
        o.targets = self.targets.copy()
        return o

    def __eq__(self, other):
        if not isinstance(other, OutBranch):
            return False

        return self.ins_addr == other.ins_addr and \
               self.stmt_idx == other.stmt_idx and \
               self.type == other.type and \
               self.targets == other.targets

    def __hash__(self):
        return hash((self.ins_addr, self.stmt_idx, self.type))


class SuperAILNode:
    """
    A single node in the SuperGraph, which will include various other ail nodes
    """

    def __init__(self, addr):
        self.addr = addr
        self.nodes = []
        self.out_branches = defaultdict(dict)

    @property
    def size(self):
        if len(self.nodes) == 0:
            return 0

        return sum([node.original_size for node in self.nodes])

    @property
    def statements(self):
        stmts = []
        for node in self.nodes:
            stmts += node.statements

        return stmts

    @classmethod
    def from_ailnode(cls, ail_node):
        s = cls(ail_node.addr)
        s.nodes.append(ail_node)
        return s

    def insert_ailnode(self, ail_node):
        # TODO: Make it binary search/insertion
        for i, n in enumerate(self.nodes):
            if ail_node.addr < n.addr:
                # insert before n
                self.nodes.insert(i, ail_node)
                break

            if ail_node.addr == n.addr:
                break
        else:
            self.nodes.append(ail_node)

        # update addr
        self.addr = self.nodes[0].addr

    def register_out_branch(self, ins_addr, stmt_idx, branch_type, target_addr):
        if ins_addr not in self.out_branches or stmt_idx not in self.out_branches[ins_addr]:
            self.out_branches[ins_addr][stmt_idx] = OutBranch(ins_addr, stmt_idx, branch_type)

        self.out_branches[ins_addr][stmt_idx].add_target(target_addr)

    def merge(self, other):
        """
        Merge another supernode into the current one.

        :param SuperCFGNode other: The supernode to merge with.
        :return: None
        """

        for n in other.nodes:
            self.insert_ailnode(n)

        for ins_addr, outs in other.out_branches.items():
            if ins_addr in self.out_branches:
                for stmt_idx, item in outs.items():
                    if stmt_idx in self.out_branches[ins_addr]:
                        self.out_branches[ins_addr][stmt_idx].merge(item)
                    else:
                        self.out_branches[ins_addr][stmt_idx] = item

            else:
                item = next(iter(outs.values()))
                self.out_branches[ins_addr][item.stmt_idx] = item

    def __repr__(self):
        return "<SuperAILNode %#08x, %d blocks, %d out branches>" % (self.addr, len(self.nodes),
                                                                     len(self.out_branches)
                                                                     )

    def __hash__(self):
        return hash(('superailnode', self.addr))

    def __eq__(self, other):
        if not isinstance(other, SuperAILNode):
            return False

        return self.addr == other.addr
