# pylint:disable=wrong-import-position,broad-exception-caught,ungrouped-imports,import-outside-toplevel
from __future__ import annotations
import pathlib
import copy
from typing import Any
from collections.abc import Iterable
import logging

import networkx
import ailment

import angr
from angr.analyses.decompiler.counters.call_counter import AILBlockCallCounter
from angr.utils.ail import is_phi_assignment
from .seq_to_blocks import SequenceToBlocks

_l = logging.getLogger(__name__)


def remove_last_statement(node):
    stmt = None

    if type(node) is CodeNode:
        stmt = remove_last_statement(node.node)
    elif type(node) is ailment.Block:
        stmt = node.statements[-1]
        node.statements = node.statements[:-1]
    elif type(node) is MultiNode or type(node) is SequenceNode:
        if node.nodes:
            stmt = remove_last_statement(node.nodes[-1])
            if BaseNode.test_empty_node(node.nodes[-1]):
                node.nodes = node.nodes[:-1]
    elif type(node) is ConditionNode:
        if node.true_node is None and node.false_node is not None:
            stmt = remove_last_statement(node.false_node)
        elif node.true_node is not None and node.false_node is None:
            stmt = remove_last_statement(node.true_node)
        else:
            raise NotImplementedError("More than one last statement exist")
    elif type(node) is LoopNode:
        stmt = remove_last_statement(node.sequence_node)
    else:
        raise NotImplementedError

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
            raise NotImplementedError
        return
    if type(node) is SequenceNode:
        if node.nodes:
            append_statement(node.nodes[-1], stmt)
        else:
            raise NotImplementedError
        return

    raise NotImplementedError


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

    raise NotImplementedError


def extract_jump_targets(stmt):
    """
    Extract concrete goto targets from a Jump or a ConditionalJump statement.

    :param stmt:    The statement to analyze.
    :return:        A list of known concrete jump targets.
    :rtype:         list
    """

    targets = []

    if isinstance(stmt, ailment.Stmt.Jump):
        if isinstance(stmt.target, ailment.Expr.Const):
            targets.append(stmt.target.value)
    elif isinstance(stmt, ailment.Stmt.ConditionalJump):
        if isinstance(stmt.true_target, ailment.Expr.Const):
            targets.append(stmt.true_target.value)
        if isinstance(stmt.false_target, ailment.Expr.Const):
            targets.append(stmt.false_target.value)

    return targets


def switch_extract_cmp_bounds(last_stmt: ailment.Stmt.ConditionalJump) -> tuple[Any, int, int] | None:
    """
    Check the last statement of the switch-case header node, and extract lower+upper bounds for the comparison.

    :param last_stmt:   The last statement of the switch-case header node.
    :return:            A tuple of (comparison expression, lower bound, upper bound), or None
    """

    if not isinstance(last_stmt, ailment.Stmt.ConditionalJump):
        return None

    # TODO: Add more operations
    if isinstance(last_stmt.condition, ailment.Expr.BinaryOp) and last_stmt.condition.op == "CmpLE":
        if not isinstance(last_stmt.condition.operands[1], ailment.Expr.Const):
            return None
        cmp_ub = last_stmt.condition.operands[1].value
        cmp_lb = 0
        cmp = last_stmt.condition.operands[0]
        if (
            isinstance(cmp, ailment.Expr.BinaryOp)
            and cmp.op == "Sub"
            and isinstance(cmp.operands[1], ailment.Expr.Const)
        ):
            cmp_ub += cmp.operands[1].value
            cmp_lb += cmp.operands[1].value
            cmp = cmp.operands[0]
        return cmp, cmp_lb, cmp_ub

    return None


def get_ast_subexprs(claripy_ast):
    queue = [claripy_ast]
    while queue:
        ast = queue.pop(0)
        if ast.op == "And":
            queue += ast.args[1:]
            yield ast.args[0]
        else:
            yield ast


def insert_node(parent, insert_location: str, node, node_idx: int | tuple[int] | None, label=None):
    if insert_location not in {"before", "after"}:
        raise ValueError('"insert_location" must be either "before" or "after"')

    if isinstance(parent, SequenceNode):
        if insert_location == "before":
            parent.nodes.insert(node_idx, node)
        else:  # if insert_location == "after":
            parent.nodes.insert(node_idx + 1, node)
    elif isinstance(parent, CodeNode):
        # Make a new sequence node
        if insert_location == "before":
            seq = SequenceNode(parent.addr, nodes=[node, parent.node])
        else:  # if insert_location == "after":
            seq = SequenceNode(parent.addr, nodes=[parent.node, node])
        parent.node = seq
    elif isinstance(parent, MultiNode):
        if insert_location == "before":
            parent.nodes.insert(node_idx, node)
        else:
            parent.nodes.insert(node_idx + 1, node)
    elif isinstance(parent, ConditionNode):
        if node_idx == 0:
            # true node
            if not isinstance(parent.true_node, SequenceNode):
                if parent.true_node is None:
                    parent.true_node = SequenceNode(parent.addr, nodes=[])
                else:
                    parent.true_node = SequenceNode(parent.true_node.addr, nodes=[parent.true_node])
            insert_node(parent.true_node, insert_location, node, 0)
        else:
            # false node
            if not isinstance(parent.false_node, SequenceNode):
                if parent.false_node is None:
                    parent.false_node = SequenceNode(parent.addr, nodes=[])
                else:
                    parent.false_node = SequenceNode(parent.false_node.addr, nodes=[parent.false_node])
            insert_node(parent.false_node, insert_location, node, 0)
    elif isinstance(parent, CascadingConditionNode):
        cond, child_node = parent.condition_and_nodes[node_idx]
        if not isinstance(child_node, SequenceNode):
            child_node = SequenceNode(child_node.addr, nodes=[child_node])
            parent.condition_and_nodes[node_idx] = (cond, child_node)
        insert_node(child_node, insert_location, node, 0)
    elif isinstance(parent, SwitchCaseNode):
        # note that this case will be hit only when the parent node is not a container, such as SequenceNode or
        # MultiNode. we always need to create a new SequenceNode and replace the original node in place.

        if label == "switch_expr":
            raise TypeError("You cannot insert a node after an expression.")
        if label == "case":
            # node_idx is the case number.
            if insert_location == "after":
                new_nodes = [parent.cases[node_idx], node]
            elif insert_location == "before":
                new_nodes = [node, parent.cases[node_idx]]
            else:
                raise TypeError(f'Unsupported insert_location value "{insert_location}".')
            seq = SequenceNode(new_nodes[0].addr, nodes=new_nodes)
            parent.cases[node_idx] = seq
        elif label == "default":
            if insert_location == "after":
                new_nodes = [parent.default_node, node]
            elif insert_location == "before":
                new_nodes = [node, parent.default_node]
            else:
                raise TypeError(f"Unsupported 'insert_location' value {insert_location!r}.")
            seq = SequenceNode(new_nodes[0].addr, nodes=new_nodes)
            parent.default_node = seq
        else:
            raise TypeError(
                f'Unsupported label value "{label}". Must be one of the following: switch_expr, case, ' f"default."
            )
    elif isinstance(parent, LoopNode):
        if label == "condition":
            raise ValueError("Cannot insert nodes into a condition expression.")
        if label == "body":
            if not isinstance(parent.sequence_node, SequenceNode):
                parent.sequence_node = SequenceNode(parent.sequence_node.addr, nodes=[parent.sequence_node])
            insert_node(parent.sequence_node, insert_location, node, node_idx)
        else:
            raise NotImplementedError
    else:
        raise NotImplementedError


def _merge_ail_nodes(graph, node_a: ailment.Block, node_b: ailment.Block) -> ailment.Block:
    in_edges = list(graph.in_edges(node_a, data=True))
    out_edges = list(graph.out_edges(node_b, data=True))

    a_ogs = graph.nodes[node_a].get("original_nodes", set())
    b_ogs = graph.nodes[node_b].get("original_nodes", set())
    new_node = node_a.copy() if node_a.addr <= node_b.addr else node_b.copy()
    old_node = node_b if new_node == node_a else node_a
    # remove jumps in the middle of nodes when merging
    if new_node.statements and isinstance(new_node.statements[-1], ailment.Stmt.Jump):
        new_node.statements = new_node.statements[:-1]
    new_node.statements += old_node.statements
    new_node.original_size += old_node.original_size

    graph.remove_node(node_a)
    graph.remove_node(node_b)

    if new_node is not None:
        graph.add_node(new_node, original_nodes=a_ogs.union(b_ogs))
        for src, _, data in in_edges:
            if src is node_b:
                src = new_node
            graph.add_edge(src, new_node, **data)

        for _, dst, data in out_edges:
            if dst is node_a:
                dst = new_node
            graph.add_edge(new_node, dst, **data)

    return new_node


def to_ail_supergraph(transition_graph: networkx.DiGraph, allow_fake=False) -> networkx.DiGraph:
    """
    Takes an AIL graph and converts it into a AIL graph that treats calls and redundant jumps
    as parts of a bigger block instead of transitions. Calls to returning functions do not terminate basic blocks.

    Based on region_identifier super_graph

    :return: A converted super transition graph
    """
    # make a copy of the graph
    transition_graph = networkx.DiGraph(transition_graph)
    networkx.set_node_attributes(transition_graph, {node: {node} for node in transition_graph.nodes}, "original_nodes")

    while True:
        for src, dst, data in transition_graph.edges(data=True):
            type_ = data.get("type", None)

            if len(list(transition_graph.successors(src))) == 1 and len(list(transition_graph.predecessors(dst))) == 1:
                # calls in the middle of blocks OR boring jumps
                if (type_ == "fake_return") or (src.addr + src.original_size == dst.addr) or allow_fake:
                    _merge_ail_nodes(transition_graph, src, dst)
                    break

            # calls to functions with no return
            elif type_ == "call":
                transition_graph.remove_node(dst)
                break
        else:
            break

    return transition_graph


def is_empty_node(node) -> bool:
    if isinstance(node, ailment.Block):
        return not node.statements
    if isinstance(node, MultiNode):
        return all(is_empty_node(n) for n in node.nodes)
    if isinstance(node, SequenceNode):
        return all(is_empty_node(n) for n in node.nodes)
    return False


def is_empty_or_label_only_node(node) -> bool:
    if isinstance(node, ailment.Block):
        return not has_nonlabel_statements(node)
    if isinstance(node, MultiNode):
        return all(is_empty_or_label_only_node(n) for n in node.nodes)
    if isinstance(node, SequenceNode):
        return all(is_empty_or_label_only_node(n) for n in node.nodes)
    return False


def has_nonlabel_statements(block: ailment.Block) -> bool:
    return block.statements and any(not isinstance(stmt, ailment.Stmt.Label) for stmt in block.statements)


def has_nonlabel_nonphi_statements(block: ailment.Block) -> bool:
    return block.statements and any(
        not (isinstance(stmt, ailment.Stmt.Label) or is_phi_assignment(stmt)) for stmt in block.statements
    )


def first_nonlabel_statement(block: ailment.Block | MultiNode) -> ailment.Stmt.Statement | None:
    if isinstance(block, MultiNode):
        for n in block.nodes:
            stmt = first_nonlabel_statement(n)
            if stmt is not None:
                return stmt
        return None

    for stmt in block.statements:
        if not isinstance(stmt, ailment.Stmt.Label):
            return stmt
    return None


def first_nonlabel_statement_id(block: ailment.Block) -> int | None:
    for idx, stmt in enumerate(block.statements):
        if not isinstance(stmt, ailment.Stmt.Label):
            return idx
    return len(block.statements)


def first_nonlabel_nonphi_statement(block: ailment.Block | MultiNode) -> ailment.Stmt.Statement | None:
    if isinstance(block, MultiNode):
        for n in block.nodes:
            stmt = first_nonlabel_nonphi_statement(n)
            if stmt is not None:
                return stmt
        return None

    for stmt in block.statements:
        if not (isinstance(stmt, ailment.Stmt.Label) or is_phi_assignment(stmt)):
            return stmt
    return None


def last_nonlabel_statement(block: ailment.Block) -> ailment.Stmt.Statement | None:
    for stmt in reversed(block.statements):
        if not isinstance(stmt, ailment.Stmt.Label):
            return stmt
    return None


def first_nonlabel_node(seq: SequenceNode) -> BaseNode | ailment.Block | None:
    for node in seq.nodes:
        inner_node = node.node if isinstance(node, CodeNode) else node
        if isinstance(inner_node, ailment.Block) and not has_nonlabel_statements(inner_node):
            continue
        return node
    return None


def first_nonlabel_nonphi_node(seq: SequenceNode) -> BaseNode | ailment.Block | None:
    for node in seq.nodes:
        inner_node = node.node if isinstance(node, CodeNode) else node
        if isinstance(inner_node, ailment.Block) and not has_nonlabel_nonphi_statements(inner_node):
            continue
        return node
    return None


def remove_labels(graph: networkx.DiGraph):
    new_graph = networkx.DiGraph()
    nodes_map = {}
    for node in graph:
        node_copy = node.copy()
        node_copy.statements = [stmt for stmt in node_copy.statements if not isinstance(stmt, ailment.Stmt.Label)]
        nodes_map[node] = node_copy

    for old_node in graph.nodes:
        new_graph.add_node(nodes_map[old_node])

    for src, dst, data in graph.edges(data=True):
        new_graph.add_edge(nodes_map[src], nodes_map[dst], **data)

    return new_graph


def add_labels(graph: networkx.DiGraph):
    new_graph = networkx.DiGraph()
    nodes_map = {}
    for node in graph:
        lbl = ailment.Stmt.Label(None, f"LABEL_{node.addr:x}", node.addr, block_idx=node.idx)
        node_copy = node.copy()
        node_copy.statements = [lbl, *node_copy.statements]
        nodes_map[node] = node_copy

    for old_node in graph.nodes:
        new_graph.add_node(nodes_map[old_node])

    for src, dst in graph.edges:
        new_graph.add_edge(nodes_map[src], nodes_map[dst])

    return new_graph


def update_labels(graph: networkx.DiGraph):
    """
    A utility function to recreate the labels for every node in an AIL graph. This useful when you are working with
    a graph where only _some_ of the nodes have labels.
    """
    return add_labels(remove_labels(graph))


def structured_node_is_simple_return(
    node: SequenceNode | MultiNode, graph: networkx.DiGraph, use_packed_successors=False
) -> bool:
    """
    Will check if a "simple return" is contained within the node a simple returns looks like this:
    if (cond) {
      // simple return
      ...
      return 0;
    }
    ...

    Returns true on any block ending in linear statements and a return.
    """

    def _flatten_structured_node(packed_node: SequenceNode | MultiNode) -> list[ailment.Block]:
        if not packed_node or not packed_node.nodes:
            return []

        blocks = []
        if packed_node.nodes is not None:
            for _node in packed_node.nodes:
                if isinstance(_node, (SequenceNode, MultiNode)):
                    blocks += _flatten_structured_node(_node)
                else:
                    blocks.append(_node)

        return blocks

    # sanity check: we need a graph to understand returning blocks
    if graph is None:
        return False

    last_block = None
    if isinstance(node, (SequenceNode, MultiNode)) and node.nodes:
        flat_blocks = _flatten_structured_node(node)
        if all(isinstance(block, ailment.Block) for block in flat_blocks):
            last_block = flat_blocks[-1]
    elif isinstance(node, ailment.Block):
        last_block = node

    valid_last_stmt = last_block is not None
    if valid_last_stmt and last_block.statements:
        valid_last_stmt = not isinstance(last_block.statements[-1], (ailment.Stmt.ConditionalJump, ailment.Stmt.Jump))

    if use_packed_successors:
        last_block = node

    if valid_last_stmt:
        # note that the block may not be the same block in the AIL graph post dephication. we must find the block again
        # in the graph.
        for bb in graph:
            if bb.addr == last_block.addr and bb.idx == last_block.idx:
                # found it
                succs = list(graph.successors(bb))
                return not succs or succs == [bb]
    return False


def is_statement_terminating(stmt: ailment.statement.Statement, functions) -> bool:
    if isinstance(stmt, ailment.Stmt.Return):
        return True
    if isinstance(stmt, ailment.Stmt.Call) and isinstance(stmt.target, ailment.Expr.Const):
        # is it calling a non-returning function?
        target_func_addr = stmt.target.value
        try:
            func = functions.get_by_addr(target_func_addr)
            return func.returning is False
        except KeyError:
            pass
    return False


def peephole_optimize_exprs(block, expr_opts):
    class _any_update:
        """
        Local temporary class used as a container for variable `v`.
        """

        v = False

    def _handle_expr(
        expr_idx: int, expr: ailment.Expr.Expression, stmt_idx: int, stmt: ailment.Stmt.Statement | None, block
    ) -> ailment.Expr.Expression | None:
        # process the expr
        processed = ailment.AILBlockWalker._handle_expr(walker, expr_idx, expr, stmt_idx, stmt, block)

        if processed is not None:
            expr = processed
        old_expr = expr

        redo = True
        while redo:
            redo = False
            for expr_opt in expr_opts:
                if isinstance(expr, expr_opt.expr_classes):
                    r = expr_opt.optimize(expr, stmt_idx=stmt_idx, block=block)
                    if r is not None and r is not expr:
                        expr = r
                        redo = True
                        break

        if expr is not old_expr:
            _any_update.v = True

        return expr

    # run expression optimizers
    walker = ailment.AILBlockWalker()
    walker._handle_expr = _handle_expr
    walker.walk(block)

    return _any_update.v


def peephole_optimize_expr(expr, expr_opts):
    def _handle_expr(
        expr_idx: int, expr: ailment.Expr.Expression, stmt_idx: int, stmt: ailment.Stmt.Statement | None, block
    ) -> ailment.Expr.Expression | None:
        old_expr = expr

        redo = True
        while redo:
            redo = False
            for expr_opt in expr_opts:
                if isinstance(expr, expr_opt.expr_classes):
                    r = expr_opt.optimize(expr)
                    if r is not None and r is not expr:
                        expr = r
                        redo = True
                        break

        if expr is not old_expr:
            # continue to process the expr
            r = ailment.AILBlockWalker._handle_expr(walker, expr_idx, expr, stmt_idx, stmt, block)
            return expr if r is None else r

        return ailment.AILBlockWalker._handle_expr(walker, expr_idx, expr, stmt_idx, stmt, block)

    # run expression optimizers
    walker = ailment.AILBlockWalker()
    walker._handle_expr = _handle_expr
    return walker._handle_expr(0, expr, 0, None, None)


def copy_graph(graph: networkx.DiGraph):
    """
    Copy AIL Graph.

    :return: A copy of the AIl graph.
    """
    graph_copy = networkx.DiGraph()
    block_mapping = {}
    # copy all blocks
    for block in graph.nodes():
        new_block = copy.copy(block)
        new_stmts = copy.copy(block.statements)
        new_block.statements = new_stmts
        block_mapping[block] = new_block
        graph_copy.add_node(new_block)

    # copy all edges
    for src, dst, data in graph.edges(data=True):
        new_src = block_mapping[src]
        new_dst = block_mapping[dst]
        graph_copy.add_edge(new_src, new_dst, **data)
    return graph_copy


def peephole_optimize_stmts(block, stmt_opts):
    any_update = False
    statements = []

    # run statement optimizers
    # note that an optimizer may optionally edit or remove statements whose statement IDs are greater than stmt_idx
    stmt_idx = 0
    while stmt_idx < len(block.statements):
        stmt = block.statements[stmt_idx]
        old_stmt = stmt
        redo = True
        while redo:
            redo = False
            for opt in stmt_opts:
                if isinstance(stmt, opt.stmt_classes):
                    r = opt.optimize(stmt, stmt_idx=stmt_idx, block=block)
                    if r is not None and r is not stmt:
                        stmt = r
                        redo = True
                        break

        if stmt is not None and stmt is not old_stmt:
            statements.append(stmt)
            any_update = True
        else:
            statements.append(old_stmt)
        stmt_idx += 1

    return statements, any_update


def match_stmt_classes(all_stmts: list, idx: int, stmt_class_seq: Iterable[type]) -> bool:
    for i, cls in enumerate(stmt_class_seq):
        if idx + i >= len(all_stmts):
            return False
        if not isinstance(all_stmts[idx + i], cls):
            return False
    return True


def peephole_optimize_multistmts(block, stmt_opts):
    any_update = False
    statements = block.statements[::]

    # run multi-statement optimizers
    stmt_idx = 0
    while stmt_idx < len(statements):
        redo = True
        while redo and stmt_idx < len(statements):
            redo = False
            for opt in stmt_opts:
                matched = False
                stmt_seq_len = None
                for stmt_class_seq in opt.stmt_classes:
                    if match_stmt_classes(statements, stmt_idx, stmt_class_seq):
                        stmt_seq_len = len(stmt_class_seq)
                        matched = True
                        break

                if matched:
                    matched_stmts = statements[stmt_idx : stmt_idx + stmt_seq_len]
                    r = opt.optimize(matched_stmts, stmt_idx=stmt_idx, block=block)
                    if r is not None:
                        # update statements
                        statements = statements[:stmt_idx] + r + statements[stmt_idx + stmt_seq_len :]
                        any_update = True
                        redo = True
                        break

        # move on to the next statement
        stmt_idx += 1

    return statements, any_update


def decompile_functions(
    path,
    functions: list[int | str] | None = None,
    structurer: str | None = None,
    catch_errors: bool = False,
    show_casts: bool = True,
    base_address: int | None = None,
) -> str | None:
    """
    Decompile a binary into a set of functions.

    :param path:            The path to the binary to decompile.
    :param functions:       The functions to decompile. If None, all functions will be decompiled.
    :param structurer:      The structuring algorithms to use.
    :param catch_errors:    The structuring algorithms to use.
    :param show_casts:      Whether to show casts in the decompiled output.
    :param base_address:    The base address of the binary.
    :return:                The decompilation of all functions appended in order.
    """
    # delayed imports to avoid circular imports
    from angr.analyses.decompiler.decompilation_options import PARAM_TO_OPTION
    from angr.analyses.decompiler.structuring import DEFAULT_STRUCTURER

    structurer = structurer or DEFAULT_STRUCTURER.NAME

    path = pathlib.Path(path).resolve().absolute()
    # resolve loader args
    loader_main_opts_kwargs = {}
    if base_address is not None:
        loader_main_opts_kwargs["base_addr"] = base_address
    proj = angr.Project(path, auto_load_libs=False, main_opts=loader_main_opts_kwargs)
    cfg = proj.analyses.CFG(normalize=True, data_references=True)
    proj.analyses.CompleteCallingConventions(recover_variables=True, analyze_callsites=True)

    # collect all functions when None are provided
    if functions is None:
        functions = sorted(cfg.kb.functions)

    # normalize the functions that could be ints as names
    normalized_functions: list[int | str] = []
    for func in functions:
        try:
            normalized_name = int(func, 0) if isinstance(func, str) else func
        except ValueError:
            normalized_name = func
        normalized_functions.append(normalized_name)
    functions = normalized_functions

    # verify that all functions exist
    for func in list(functions):
        if func not in cfg.functions:
            if catch_errors:
                _l.warning("Function %s does not exist in the CFG.", str(func))
                functions.remove(func)
            else:
                raise ValueError(f"Function {func} does not exist in the CFG.")

    # decompile all functions
    decompilation = ""
    dec_options = [
        (PARAM_TO_OPTION["structurer_cls"], structurer),
        (PARAM_TO_OPTION["show_casts"], show_casts),
    ]
    for func in functions:
        f = cfg.functions[func]
        if f is None or f.is_plt or f.is_syscall or f.is_alignment or f.is_simprocedure:
            continue

        exception_string = ""
        if not catch_errors:
            dec = proj.analyses.Decompiler(f, cfg=cfg, options=dec_options)
        else:
            try:
                # TODO: add a timeout
                dec = proj.analyses.Decompiler(f, cfg=cfg, options=dec_options)
            except Exception as e:
                exception_string = str(e).replace("\n", " ")
                dec = None

        # do sanity checks on decompilation, skip checks if we already errored
        if not exception_string:
            if dec is None or not dec.codegen or not dec.codegen.text:
                exception_string = "Decompilation had no code output (failed in decompilation)"
            elif "{\n}" in dec.codegen.text:
                exception_string = "Decompilation outputted an empty function (failed in structuring)"
            elif structurer in ["dream", "combing"] and "goto" in dec.codegen.text:
                exception_string = "Decompilation outputted a goto for a Gotoless algorithm (failed in structuring)"

        if exception_string:
            _l.critical("Failed to decompile %s because %s", repr(f), exception_string)
            decompilation += f"// [error: {func} | {exception_string}]\n"
        else:
            decompilation += dec.codegen.text + "\n"

    return decompilation


def calls_in_graph(graph: networkx.DiGraph) -> int:
    """
    Counts the number of calls in an graph full of AIL Blocks
    """
    counter = AILBlockCallCounter()
    for node in graph.nodes:
        counter.walk(node)

    return counter.calls


def find_block_by_addr(graph: networkx.DiGraph, addr, insn_addr=False):
    for block in graph.nodes():
        if insn_addr:
            for stmt in block.statements:
                if "ins_addr" in stmt.tags and stmt.ins_addr == addr:
                    return block
        else:
            if block.addr == addr:
                return block

    raise ValueError("The block is not in the graph!")


def sequence_to_blocks(seq: BaseNode) -> list[ailment.Block]:
    """
    Converts a sequence node (BaseNode) to a list of ailment blocks contained in it and all its children.
    """
    walker = SequenceToBlocks()
    walker.walk(seq)
    return walker.blocks


def sequence_to_statements(
    seq: BaseNode, exclude=(ailment.statement.Jump, ailment.statement.Jump)
) -> list[ailment.statement.Statement]:
    """
    Converts a sequence node (BaseNode) to a list of ailment Statements contained in it and all its children.
    May exclude certain types of statements.
    """
    statements = []
    blocks = sequence_to_blocks(seq)
    block: ailment.Block
    for block in blocks:
        if not block.statements:
            continue

        for stmt in block.statements:
            if isinstance(stmt, exclude):
                continue
            statements.append(stmt)

    return statements


# delayed import
from .structuring.structurer_nodes import (
    MultiNode,
    BaseNode,
    CodeNode,
    SequenceNode,
    ConditionNode,
    SwitchCaseNode,
    CascadingConditionNode,
    LoopNode,
)
