from __future__ import annotations

import logging
from collections import defaultdict

import networkx

from angr.ailment import Address, Block
from angr.ailment.expression import BinaryOp, Call, Const, Phi, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, ConditionalJump, Jump, Return
from angr.analyses.analysis import AnalysesHub, Analysis
from angr.analyses.s_liveness import SLivenessAnalysis
from angr.analyses.s_reaching_definitions import SReachingDefinitions
from angr.knowledge_plugins.functions import Function
from angr.utils.graph import Dominators, compute_dominance_frontier, subgraph_between_nodes
from angr.utils.ssa import is_phi_assignment

_l = logging.getLogger(__name__)


class Outliner(Analysis):
    """
    Outliner takes a function and some locations and attempts to outline the blocks within these locations into a
    separate function.
    """

    def __init__(
        self,
        func,
        ail_graph: networkx.DiGraph[Block],
        src_loc: Address,
        func_entry_loc: Address | None = None,
        frontier: set[Address] | None = None,
        vvar_id_start: int = 0xBEEF,
        block_addr_start: int = 0xAABB_0000,
        min_step: int = 1,
        liveness: SLivenessAnalysis | None = None,
    ):
        self.parent_func = func
        self.parent_graph = ail_graph
        self.vvar_id_start = vvar_id_start
        self.block_addr_start = block_addr_start
        self.min_step = min_step
        self.nodes_dict = {(node.addr, node.idx): node for node in self.parent_graph}

        self.src_loc = src_loc

        if func_entry_loc:
            self.parent_entry_loc = func_entry_loc
        else:
            func_entry_locs = [(bb.addr, bb.idx) for bb in self.parent_graph if self.parent_graph.in_degree[bb] == 0]
            if len(func_entry_locs) != 1:
                _l.warning("Graph has no obvious entry point")
            self.parent_entry_loc = min(func_entry_locs)

        self.parent_liveness = liveness or self.project.analyses[SLivenessAnalysis].prep()(
            self.parent_func,
            func_graph=self.parent_graph,
            entry=self.nodes_dict[self.parent_entry_loc],
            arg_vvars=[],  # TODO: FIXME
        )

        if frontier:
            self.frontier_locs = frontier
            self.frontier_vars = self._determine_frontier_vars()
        else:
            self.frontier_locs = self._determine_frontier_locs()
            self.frontier_vars = set()

        self.child_func, self.child_graph, self.child_funcargs = self._analyze()

    def _next_vvar_id(self) -> int:
        vvar_id = self.vvar_id_start
        self.vvar_id_start += 1
        return vvar_id

    def _next_block_addr(self) -> int:
        block_addr = self.block_addr_start
        self.block_addr_start += 1
        return block_addr

    def cleanup_callee_graph(self, g: networkx.DiGraph, func: Function):
        """
        Remove all phi assignments whose all source variables are undefined in the graph.
        """

        srda = SReachingDefinitions(self.project, func, func_graph=g).model

        to_kill = defaultdict(set)
        for phi_var_id, src_var_ids in srda.phivarid_to_varids.items():
            if all(srda.all_vvar_definitions[src_varid].is_extern for src_varid in src_var_ids):
                # remove the phi assignment
                phi_def_loc = srda.all_vvar_definitions[phi_var_id]
                assert phi_def_loc.block_addr is not None
                assert phi_def_loc.stmt_idx is not None
                phi_def_node = self.nodes_dict[(phi_def_loc.block_addr, phi_def_loc.block_idx)]
                to_kill[phi_def_node].add(phi_def_loc.stmt_idx)

        for node, kills in to_kill.items():
            node.statements = [stmt for i, stmt in enumerate(node.statements) if i not in kills]

    def get_interface(self, g: networkx.DiGraph[Block], func: Function) -> list[VirtualVariable]:
        """
        Recover the interface from a function AIL graph.
        """

        srda = SReachingDefinitions(self.project, func, func_graph=g).model

        blocks: dict[tuple[int, int | None], Block] = {(node.addr, node.idx): node for node in g}

        # find undefined vvars
        undef_vvars = []
        for vvar_id, defloc in srda.all_vvar_definitions.items():
            if defloc.is_extern:
                # remove undefined vvars that are only ever used in phi assignments
                use_locs = srda.all_vvar_uses[vvar_id]
                use_stmts = [
                    blocks[loc.addr, loc.block_idx].statements[loc.stmt_idx] for _, loc in use_locs if not loc.is_extern
                ]
                if not all(is_phi_assignment(stmt) for stmt in use_stmts):
                    undef_vvars.append(vvar_id)

        return [srda.varid_to_vvar[varid] for varid in undef_vvars]

    def _analyze(self):
        node_dict: dict[tuple[int, int | None], Block] = {
            (node.addr, node.idx): node for node in self.parent_graph.nodes
        }
        try:
            src_node = node_dict[self.src_loc]
        except KeyError as e:
            raise KeyError(f"Source location {self.src_loc} is not valid in the given graph.") from e

        frontier: list[Block] = []
        # ensure locs is valid
        for loc in self.frontier_locs:
            try:
                frontier.append(node_dict[loc])
            except KeyError as e:
                raise KeyError(f"Frontier location {loc} is not valid in the given graph.") from e

        # generate a subgraph
        subgraph = subgraph_between_nodes(
            self.parent_graph, src_node, frontier, include_frontier=False
        )  # FISHME: why was this True?

        in_edges = [(node, src_node) for node in self.parent_graph.pred[src_node]]
        out_edges = [
            (node, frontier_node)
            for frontier_node in frontier
            for node in self.parent_graph.pred[frontier_node]
            if node in subgraph and node not in frontier
        ]

        # remove the subgraph from the original graph
        for node in subgraph:
            self.parent_graph.remove_node(node)

        callee_func = Function(self.kb.functions, src_node.addr)
        callee_func.normalized = True
        # clean up the subgraph
        self.cleanup_callee_graph(subgraph, callee_func)
        # figure out the interface of the new callee
        callee_arg_vvars = self.get_interface(subgraph, callee_func)

        # rewrite the callsite
        vvar_id = self._next_vvar_id()
        callee_arg_vvars_copy = [arg_vvar.copy() for arg_vvar in callee_arg_vvars]
        call_expr = Call(
            None,
            f"outlined_func_{src_node.addr:x}",
            # Const(None, None, src_node.addr, 64),
            args=callee_arg_vvars_copy,
            bits=self.project.arch.bits,
            ins_addr=src_node.addr,
        )
        switch_vvar = VirtualVariable(
            None, vvar_id, self.project.arch.bits, VirtualVariableCategory.REGISTER, oident=self.project.arch.ret_offset
        )
        call_stmt = Assignment(None, switch_vvar, call_expr, ins_addr=src_node.addr)
        new_src_node = Block(src_node.addr, src_node.original_size, statements=[call_stmt], idx=src_node.idx)
        for pred, _ in in_edges:
            self.parent_graph.add_edge(pred, new_src_node)

        # build the return statement if needed
        # a frontier variable whose definition reaches the frontier from outside the
        # region is not ours to return; claiming it would define it a second time
        defined_in_region = {
            stmt.dst.varid
            for node in subgraph
            for stmt in node.statements
            if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable)
        }
        owned_frontier_vars = self.frontier_vars & defined_in_region
        if owned_frontier_vars:
            srda = SReachingDefinitions(self.project, self.parent_func, func_graph=self.parent_graph).model
            ret_exprs = [srda.varid_to_vvar[idx] for idx in owned_frontier_vars]
        else:
            ret_exprs = []

        retval_to_target: dict[int, tuple[int, int | None]] = {}
        if len(frontier) > 1:
            # there are multiple successors; this means the function must return to different locations. let's build
            # the dispatcher structure (at the return site in the caller) and the return nodes (in the callee)
            for succ in sorted(frontier, key=lambda node: (node.addr, node.idx)):
                retval_to_target[succ.addr] = succ.addr, succ.idx
            ret_exprs.append(switch_vvar)

        for ret_node, frontier_node in out_edges:
            if retval_to_target:
                new_ret_exprs = [*ret_exprs[:-1], Const(None, frontier_node.addr, self.project.arch.bits)]
            else:
                new_ret_exprs = ret_exprs
            ret_stmt = Return(None, new_ret_exprs, ins_addr=max(stmt.tags["ins_addr"] for stmt in ret_node.statements))

            ret_node_succs = list(subgraph.successors(ret_node))
            if len(ret_node_succs) == 0:
                # we can modify the ret_node directly
                if ret_node.statements and isinstance(ret_node.statements[-1], (ConditionalJump, Jump)):
                    del ret_node.statements[-1]
                ret_node.statements.append(ret_stmt)
            else:
                # we will have to create a new node and act as the successor of ret_node
                new_ret_node = Block(self._next_block_addr(), 0, statements=[ret_stmt])
                if ret_node.statements and isinstance(ret_node.statements[-1], ConditionalJump):
                    cond_jump = ret_node.statements[-1]
                    if isinstance(cond_jump.true_target, Const) and cond_jump.true_target.value == frontier_node.addr:
                        _, cond_jump = cond_jump.replace(
                            cond_jump.true_target, Const(None, new_ret_node.addr, self.project.arch.bits)
                        )
                    assert isinstance(cond_jump, ConditionalJump)
                    if isinstance(cond_jump.false_target, Const) and cond_jump.false_target.value == frontier_node.addr:
                        _, cond_jump = cond_jump.replace(
                            cond_jump.false_target, Const(None, new_ret_node.addr, self.project.arch.bits)
                        )
                    ret_node.statements[-1] = cond_jump
                    subgraph.add_edge(ret_node, new_ret_node)

        if frontier:
            if retval_to_target:
                # build the dispatcher structure
                parent = new_src_node
                next_dispatcher_node_addr = self._next_block_addr(), None
                retval_to_target_items = sorted(retval_to_target.items())
                last_retval_to_target_item = retval_to_target_items.pop()
                for retval, jump_target in retval_to_target_items:
                    dispatcher_node_addr = next_dispatcher_node_addr
                    next_dispatcher_node_addr = self._next_block_addr(), None

                    retval_const = Const(None, retval, self.project.arch.bits)
                    cmp = BinaryOp(None, "CmpEQ", [switch_vvar, retval_const])
                    stmt = ConditionalJump(
                        None,
                        cmp,
                        Const(None, jump_target[0], self.project.arch.bits),
                        Const(None, next_dispatcher_node_addr[0], self.project.arch.bits),
                        true_target_idx=jump_target[1],
                        false_target_idx=next_dispatcher_node_addr[1],
                        ins_addr=dispatcher_node_addr[0],
                    )
                    dispatcher_node = Block(dispatcher_node_addr[0], 0, statements=[stmt], idx=dispatcher_node_addr[1])
                    self.parent_graph.add_edge(parent, dispatcher_node)
                    self.parent_graph.add_edge(dispatcher_node, node_dict[jump_target])

                    self._update_phi_stmts(
                        node_dict[jump_target],
                        collapsed_loc=(dispatcher_node.addr, dispatcher_node.idx),
                        ret_vvar=ret_exprs[0] if ret_exprs else None,
                    )

                    parent = dispatcher_node

                self.parent_graph.add_edge(parent, node_dict[last_retval_to_target_item[1]])
                self._update_phi_stmts(
                    node_dict[last_retval_to_target_item[1]],
                    collapsed_loc=(parent.addr, parent.idx),
                    ret_vvar=ret_exprs[0] if ret_exprs else None,
                )

            else:
                (frontier_node,) = frontier
                self.parent_graph.add_edge(new_src_node, frontier_node)
                self._update_phi_stmts(
                    frontier_node,
                    collapsed_loc=(new_src_node.addr, new_src_node.idx),
                    ret_vvar=ret_exprs[0] if ret_exprs else None,
                )

        if ret_exprs:
            if len(ret_exprs) > 1:
                _l.error("Outlined region seems to have multiple return values. Can't represent this correctly.")
            call_stmt.dst = ret_exprs[0]

        return callee_func, subgraph, callee_arg_vvars

    def _update_phi_stmts(self, block: Block, collapsed_loc=None, ret_vvar=None):
        srcs = list(self.parent_graph.predecessors(block))
        src_addrs = [(src.addr, src.idx) for src in srcs]
        for i, stmt in enumerate(block.statements):
            if not is_phi_assignment(stmt):
                continue
            assert isinstance(stmt, Assignment) and isinstance(stmt.src, Phi)
            # NOTE: Phi.src_and_vvars returns a fresh copy on every read (the AIL is
            # backed by immutable Rust objects), so in-place mutation is a no-op; the
            # phi must be rebuilt and the statement replaced.
            pairs = list(stmt.src.src_and_vvars)
            all_stmt_srcs = [src for src, _ in pairs]
            new_addrs = set(src_addrs) - set(all_stmt_srcs)
            old_addrs = set(all_stmt_srcs) - set(src_addrs)
            new_pairs = None
            if len(old_addrs) == 1 and len(new_addrs) == 1:
                # a single source block was replaced by a single new one (block split)
                old_addr = next(iter(old_addrs))
                new_addr = next(iter(new_addrs))
                new_pairs = [((new_addr if src == old_addr else src), vvar) for src, vvar in pairs]
            elif (
                old_addrs
                and collapsed_loc is not None
                and set(src_addrs) == {collapsed_loc}
                and set(all_stmt_srcs) <= (old_addrs | {collapsed_loc})
            ):
                # a whole outlined region collapsed into the single new call block:
                # every phi source now arrives through that one block. If all merged
                # operands are the same variable it is a pass-through; otherwise the
                # region *selected* between them (e.g. an SSO ``a ? *p : p``) and the
                # merged value is exactly what the synthesized call returns.
                vvars = [vvar for _, vvar in pairs]
                distinct = {v.varid for v in vvars if v is not None}
                value = vvars[0] if len(distinct) == 1 else ret_vvar
                if value is not None:
                    new_pairs = [(collapsed_loc, value)]
            # else: multiple distinct source blocks replaced — unsupported, leave as-is
            if new_pairs is not None:
                new_phi = Phi(stmt.src.idx, stmt.src.bits, new_pairs, **stmt.src.tags)
                block.statements[i] = Assignment(stmt.idx, stmt.dst, new_phi, **stmt.tags)

    @staticmethod
    def _node_addr_to_str(addr: tuple[int, int | None]) -> str:
        """
        Convert a node address to a string representation.
        """
        return f"{addr[0]:#x}.{addr[1]}" if addr[1] is not None else f"{addr[0]:#x}"

    def _determine_frontier_vars(self) -> set[int]:
        """
        Given that the loc frontier has already been set, determine which variables are live when leaving that region.
        """

        return (
            set().union(*(self.parent_liveness.model.live_ins[f] for f in self.frontier_locs))
            - self.parent_liveness.model.live_ins[self.src_loc]
        )

    def _determine_frontier_locs(self) -> set[tuple[int, int | None]]:
        _l.debug("Determining the outlining frontier starting at (%#x, %s)", self.src_loc[0], self.src_loc[1])

        live_vars_dict = self.parent_liveness.live_vars_by_stmt()
        assert self.src_loc in live_vars_dict

        # find its dominance frontier
        doms = Dominators(self.parent_graph, self.nodes_dict[self.parent_entry_loc])
        dom_frontiers = compute_dominance_frontier(self.parent_graph, doms.dom)

        start = next(iter(bb for bb in self.parent_graph if (bb.addr, bb.idx) == self.src_loc))

        if start not in dom_frontiers:
            return set()

        queue = [start]
        frontiers = set()
        while queue:
            node = queue.pop(0)
            max_frontier = dom_frontiers[node]

            # for all nodes between `node` and frontier, see when new live variables are no longer live
            new_frontier = self._variable_life_frontier(node, max_frontier, min_step=self.min_step)
            _l.debug(
                "New frontier for node (%#x, %s): %s",
                node.addr,
                node.idx,
                [self._node_addr_to_str(x) for x in new_frontier],
            )

            frontiers |= new_frontier

        return frontiers

    def _variable_life_frontier(
        self, start: Block, max_frontier: set[Block], min_step=1
    ) -> set[tuple[int, int | None]]:
        """
        Find the frontier of blocks at which every variable defined in the start block dies.

        min_step will force the frontier to be at least that many steps away from the start block.
        """

        initial_live_vars = self.parent_liveness.model.live_ins[start.addr, start.idx]
        queue = [
            {
                "node": start,
                "live_vars": set(),
                "step": 0,
            }
        ]
        visited = {start}

        frontier = set()

        while queue:
            info = queue.pop(0)
            node = info["node"]
            step = info["step"]

            live_outs = self.parent_liveness.model.live_outs[node.addr, node.idx] - initial_live_vars
            _l.debug("Visiting node %#x[%s] (step %d). Live outs: %s", node.addr, node.idx, step, live_outs)
            if step >= min_step and not live_outs:
                frontier.add((node.addr, node.idx))
                continue

            for succ in self.parent_graph.successors(node):
                if succ in visited:
                    continue
                if succ in max_frontier:
                    frontier.add((succ.addr, succ.idx))
                    continue
                visited.add(succ)

                # continue to the next node
                queue.append(
                    {
                        "node": succ,
                        "live_vars": live_outs,
                        "step": step + 1,
                    }
                )

        return frontier


AnalysesHub.register_default("Outliner", Outliner)
