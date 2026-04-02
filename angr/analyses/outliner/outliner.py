from __future__ import annotations
from collections import defaultdict
import logging
from typing import TypeVar

from archinfo import Endness
import networkx

from angr.ailment import Block, Address
from angr.ailment.statement import Assignment, ConditionalJump, Return, Jump
from angr.ailment.expression import (
    Call,
    Const,
    BinaryOp,
    Extract,
    Insert,
    Phi,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.analyses.s_liveness import SLivenessAnalysis
from angr.sim_variable import SimRegisterVariable, SimStackVariable, SimVariable
from angr.utils.ssa import is_phi_assignment
from angr.analyses import Analysis, AnalysesHub
from angr.analyses.s_reaching_definitions import SReachingDefinitionsAnalysis
from angr.knowledge_plugins.functions import Function
from angr.utils.graph import subgraph_between_nodes, Dominators, compute_dominance_frontier

_l = logging.getLogger(__name__)

T = TypeVar("T")


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
        frontier: set[tuple[Address, bool]] | None = None,
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

    @property
    def child_vvars_for_clinic(self) -> dict[int, tuple[VirtualVariable, SimVariable]]:
        out_funcargs = {}
        for arg_idx, arg_vvar in enumerate(self.child_funcargs):
            if arg_vvar.was_parameter:
                if arg_vvar.parameter_category == VirtualVariableCategory.REGISTER:
                    simvar = SimRegisterVariable(arg_vvar.reg_offset, arg_vvar.size, ident=f"arg_{arg_idx}")
                elif arg_vvar.parameter_category == VirtualVariableCategory.STACK:
                    simvar = SimStackVariable(arg_vvar.stack_offset, arg_vvar.size, ident=f"arg_{arg_idx}")
                else:
                    raise NotImplementedError
            elif arg_vvar.was_reg:
                simvar = SimRegisterVariable(arg_vvar.reg_offset, arg_vvar.size, ident=f"arg_{arg_idx}")
            elif arg_vvar.was_stack:
                simvar = SimStackVariable(arg_vvar.stack_offset, arg_vvar.size, ident=f"arg_{arg_idx}")
            else:
                raise NotImplementedError
            out_funcargs[arg_idx] = arg_vvar, simvar
        return out_funcargs

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

        srda = self.project.analyses[SReachingDefinitionsAnalysis].prep()(func, func_graph=g).model

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

        srda = self.project.analyses[SReachingDefinitionsAnalysis].prep()(func, func_graph=g).model

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
        node_dict: dict[Address, Block] = {(node.addr, node.idx): node for node in self.parent_graph.nodes}
        try:
            src_node = node_dict[self.src_loc]
        except KeyError as e:
            raise KeyError(f"Source location {self.src_loc} is not valid in the given graph.") from e

        frontier: set[Block] = set()
        exclusive_frontier: set[Block] = set()
        # ensure locs is valid
        for loc, inclusive in self.frontier_locs:
            try:
                blk = node_dict[loc]
            except KeyError as e:
                raise KeyError(f"Frontier location {loc} is not valid in the given graph.") from e
            else:
                frontier.add(blk)
                if not inclusive:
                    exclusive_frontier.add(blk)

        # generate a subgraph
        subgraph = subgraph_between_nodes(self.parent_graph, src_node, frontier, include_frontier=True)
        subgraph.remove_nodes_from(exclusive_frontier)

        # normalize the frontier, making it so that we only use an inclusive node if we reach the end of the function
        for blk in list(frontier):
            if blk in exclusive_frontier:
                continue
            if self.parent_graph.out_degree(blk) == 0:
                continue
            # this node is inclusive but has successors. convert it to an exclusive frontier.
            frontier.remove(blk)
            exclusive_frontier.update(n2 for n2 in self.parent_graph.succ[blk] if n2 not in subgraph)
        inclusive_frontier = frontier - exclusive_frontier

        # "reaching the end of the function" for an inclusive frontier can either be a return statement or a noret call.
        # separate these and also generate a full list of out edges
        in_edges = [(node, src_node) for node in self.parent_graph.pred[src_node]]
        out_edges: list[tuple[Block, Block | None]] = [
            (node, frontier_node)
            for frontier_node in exclusive_frontier
            for node in self.parent_graph.pred[frontier_node]
            if node in subgraph and node not in frontier
        ]
        inclusive_frontier_returns: set[Block] = set()
        inclusive_frontier_noreturns: set[Block] = set()
        for blk in inclusive_frontier:
            if isinstance(blk.statements[-1], Return):
                out_edges.append((blk, None))
                inclusive_frontier_returns.add(blk)
            else:
                inclusive_frontier_noreturns.add(blk)

        # begin mutation!
        self.parent_graph.remove_nodes_from(subgraph)

        callee_func = Function(self.kb.functions, src_node.addr)
        callee_func.normalized = True
        # clean up the subgraph
        self.cleanup_callee_graph(subgraph, callee_func)
        # figure out the interface of the new callee
        callee_arg_vvars = self.get_interface(subgraph, callee_func)

        switch_vvar = VirtualVariable(
            None,
            self._next_vvar_id(),
            self.project.arch.bits,
            VirtualVariableCategory.REGISTER,
            oident=self.project.arch.ret_offset,
        )

        # figure out which if any expressions are returned
        if self.frontier_vars:
            srda = (
                self.project.analyses[SReachingDefinitionsAnalysis]
                .prep()(self.parent_func, func_graph=self.parent_graph)
                .model
            )
            ret_vars = [srda.varid_to_vvar[idx] for idx in self.frontier_vars]
        else:
            ret_vars = []
        ret_exprs = list(ret_vars)

        # if there are multiple successors; this means the function must return to different locations. let's build
        # the dispatcher structure (at the return site in the caller) and the return nodes (in the callee)
        ctr = 1  # ctr=0 represents tail calls
        # retval_to_target: dict[int, tuple[int, int | None]] = {}
        target_to_retval: dict[tuple[int, int | None], int] = {}
        if len(frontier) > 1:
            ret_vars.append(switch_vvar)
            for node in sorted(exclusive_frontier):
                # retval_to_target[ctr] = node.addr, node.idx
                target_to_retval[node.addr, node.idx] = ctr
                ctr += 1

        tuple_vvar = VirtualVariable(
            None,
            self._next_vvar_id(),
            sum(v.bits for v in ret_vars),
            VirtualVariableCategory.REGISTER,
            oident=self.project.arch.ret_offset,
        )
        # create the callsite in the caller
        call_expr = Call(
            None,
            f"outlined_func_{src_node.addr:x}",
            # Const(None, None, src_node.addr, 64),
            args=callee_arg_vvars,
            bits=self.project.arch.bits,
            ins_addr=src_node.addr,
        )
        call_stmt = Assignment(None, tuple_vvar, call_expr, ins_addr=src_node.addr)
        new_src_node = Block(src_node.addr, src_node.original_size, [call_stmt], idx=src_node.idx)
        bit_sum = 0
        for ret_var in ret_vars:
            new_src_node.statements.append(
                Assignment(
                    None,
                    ret_var,
                    Extract(
                        None,
                        ret_var.bits,
                        tuple_vvar,
                        Const(None, None, bit_sum // 8, self.project.arch.bits),
                        Endness.BE,
                    ),
                    ins_addr=src_node.addr,
                )
            )
            bit_sum += ret_var.bits
        for pred, _ in in_edges:
            self.parent_graph.add_edge(pred, new_src_node)

        # create the callee return statement(s)
        for ret_node, frontier_node in out_edges:
            if len(frontier) > 1:
                novel_ret_value = (
                    0 if frontier_node is None else target_to_retval[frontier_node.addr, frontier_node.idx]
                )
                new_ret_exprs = [*ret_exprs, Const(None, None, novel_ret_value, self.project.arch.bits)]
            else:
                new_ret_exprs = ret_exprs
            new_ret_expr = Const(None, None, 0, tuple_vvar.bits, uninitialized=True)
            bit_sum = 0
            for new_ret_subexpr in new_ret_exprs:
                new_ret_expr = Insert(
                    None,
                    new_ret_expr,
                    Const(None, None, bit_sum // 8, self.project.arch.bits),
                    new_ret_subexpr,
                    Endness.BE,
                )
                bit_sum += new_ret_subexpr.bits
            ret_stmt = Return(
                None, [new_ret_expr], ins_addr=max(stmt.tags.get("ins_addr", -1) for stmt in ret_node.statements)
            )

            if frontier_node is None:
                # we can modify the ret_node directly
                assert ret_node.statements and isinstance(ret_node.statements[-1], Return)
                del ret_node.statements[-1]
                ret_node.statements.append(ret_stmt)
            elif ret_node.statements and isinstance(ret_node.statements[-1], ConditionalJump):
                # we will have to create a new node and act as the successor of ret_node
                new_ret_node = Block(self._next_block_addr(), 0, [ret_stmt])
                cond_jump = ret_node.statements[-1]
                if (
                    isinstance(cond_jump.true_target, Const)
                    and cond_jump.true_target.value == frontier_node.addr
                    and cond_jump.true_target_idx == frontier_node.idx
                ):
                    _, cond_jump = cond_jump.replace(
                        cond_jump.true_target, Const(None, None, new_ret_node.addr, self.project.arch.bits)
                    )
                    cond_jump.true_target_idx = new_ret_node.idx
                if (
                    isinstance(cond_jump.false_target, Const)
                    and cond_jump.false_target.value == frontier_node.addr
                    and cond_jump.false_target_idx == frontier_node.idx
                ):
                    _, cond_jump = cond_jump.replace(
                        cond_jump.false_target, Const(None, None, new_ret_node.addr, self.project.arch.bits)
                    )
                    cond_jump.false_target_idx = new_ret_node.idx
                ret_node.statements[-1] = cond_jump
                subgraph.add_edge(ret_node, new_ret_node)
            else:
                if ret_node.statements and isinstance(ret_node.statements[-1], Jump):
                    del ret_node.statements[-1]
                ret_node.statements.append(ret_stmt)

        # create the caller return site
        if len(frontier) > 1:
            # build the dispatcher structure in the caller
            parent = new_src_node
            next_dispatcher_node_addr = self._next_block_addr(), None
            retval_to_target_items = sorted((b, a) for a, b in target_to_retval.items())
            last_jump_target = None if inclusive_frontier_returns else retval_to_target_items.pop()[1]
            for retval, jump_target in retval_to_target_items:
                dispatcher_node_addr = next_dispatcher_node_addr
                next_dispatcher_node_addr = self._next_block_addr(), None

                retval_const = Const(None, None, retval, self.project.arch.bits)
                cmp = BinaryOp(None, "CmpEQ", [switch_vvar, retval_const])
                stmt = ConditionalJump(
                    None,
                    cmp,
                    Const(None, None, jump_target[0], self.project.arch.bits),
                    Const(None, None, next_dispatcher_node_addr[0], self.project.arch.bits),
                    true_target_idx=jump_target[1],
                    false_target_idx=next_dispatcher_node_addr[1],
                    ins_addr=dispatcher_node_addr[0],
                )
                dispatcher_node = Block(dispatcher_node_addr[0], 0, [stmt], dispatcher_node_addr[1])
                self.parent_graph.add_edge(parent, dispatcher_node)
                self.parent_graph.add_edge(dispatcher_node, node_dict[jump_target])

                self._update_phi_stmts(node_dict[jump_target])

                parent = dispatcher_node

            final_node = Block(next_dispatcher_node_addr[0], 0, [], next_dispatcher_node_addr[1])
            self.parent_graph.add_edge(parent, final_node)
            if last_jump_target:
                final_node.statements.append(
                    Jump(
                        None,
                        Const(None, None, last_jump_target[0], self.project.arch.bits),
                        last_jump_target[1],
                        ins_addr=final_node.addr,
                    )
                )
                self.parent_graph.add_edge(final_node, node_dict[last_jump_target])
                self._update_phi_stmts(node_dict[last_jump_target])
            else:
                final_node.statements.append(Return(None, [switch_vvar], ins_addr=final_node.addr))

        elif frontier:
            # simple return value. just stitch the callsite to the return site.
            (frontier_node,) = frontier
            self.parent_graph.add_edge(new_src_node, frontier_node)
            self._update_phi_stmts(frontier_node)

        return callee_func, subgraph, callee_arg_vvars

    def _update_phi_stmts(self, block: Block):
        srcs = list(self.parent_graph.predecessors(block))
        src_addrs = [(src.addr, src.idx) for src in srcs]
        for stmt in block.statements:
            if is_phi_assignment(stmt):
                assert isinstance(stmt, Assignment)
                assert isinstance(stmt.src, Phi)
                all_stmt_srcs = [src for src, _ in stmt.src.src_and_vvars]
                new_addrs = set(src_addrs) - set(all_stmt_srcs)
                old_addrs = set(all_stmt_srcs) - set(src_addrs)
                if len(old_addrs) == 1 and len(new_addrs) == 1:
                    # only source block is replaced by a new one
                    old_addr = next(iter(old_addrs))
                    new_addr = next(iter(new_addrs))
                    for idx, _ in enumerate(stmt.src.src_and_vvars):
                        src, vvars = stmt.src.src_and_vvars[idx]
                        if src == old_addr:
                            stmt.src.src_and_vvars[idx] = new_addr, vvars
                else:
                    _l.error("multiple source blocks have been replaced... it's bad")
                    continue

    @staticmethod
    def _node_addr_to_str(addr: tuple[int, int | None], inclusive: bool) -> str:
        """
        Convert a node address to a string representation.
        """
        incl = "inclusive" if inclusive else "exclusive"
        return f"{addr[0]:#x}.{addr[1]} {incl}" if addr[1] is not None else f"{addr[0]:#x} {incl}"

    def _determine_frontier_vars(self) -> set[int]:
        """
        Given that the loc frontier has already been set, determine which variables are live when leaving that region.
        """

        return (
            set().union(
                *(
                    self.parent_liveness.model.live_outs[f] if incl else self.parent_liveness.model.live_ins[f]
                    for f, incl in self.frontier_locs
                )
            )
            - self.parent_liveness.model.live_ins[self.src_loc]
        )

    def _determine_frontier_locs(self) -> set[tuple[Address, bool]]:
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
                [self._node_addr_to_str(x, y) for x, y in new_frontier],
            )

            frontiers |= new_frontier

        return frontiers

    def _variable_life_frontier(self, start: Block, max_frontier: set[Block], min_step=1) -> set[tuple[Address, bool]]:
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

        frontier: set[tuple[Address, bool]] = set()

        while queue:
            info = queue.pop(0)
            node: Block = info["node"]
            step: int = info["step"]

            live_outs = self.parent_liveness.model.live_outs[node.addr, node.idx] - initial_live_vars
            _l.debug("Visiting node %#x[%s] (step %d). Live outs: %s", node.addr, node.idx, step, live_outs)
            if step >= min_step and not live_outs:
                frontier.add(((node.addr, node.idx), False))
                continue

            for succ in self.parent_graph.successors(node):
                if succ in visited:
                    continue
                if succ in max_frontier:
                    frontier.add(((succ.addr, succ.idx), False))
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
            if not self.parent_graph.out_degree(node):
                frontier.add(((node.addr, node.idx), True))

        return frontier


AnalysesHub.register_default("Outliner", Outliner)
