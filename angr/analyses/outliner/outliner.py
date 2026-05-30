from __future__ import annotations

import logging
from collections import defaultdict
from typing import cast

from angr.code_location import AILCodeLocation
from archinfo import Endness
import networkx

from angr.ailment import Block, Address, Manager
from angr.ailment.statement import Assignment, ConditionalJump, Label, Return, Jump, Statement
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
from angr.analyses.analysis import AnalysesHub, Analysis
from angr.analyses.s_liveness import SLivenessAnalysis
from angr.analyses.s_reaching_definitions import SReachingDefinitionsAnalysis
from angr.errors import AngrOutlinerEmptySubgraphError, AngrOutlinerMultiEntranceError
from angr.sim_variable import SimRegisterVariable, SimStackVariable, SimTemporaryVariable, SimVariable
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
        *,
        func_entry_loc: Address | None = None,
        frontier: set[tuple[Address, bool]] | None = None,
        child_name: str | None = None,
        vvar_id_start: int = 0xBEEF,
        block_addr_start: int = 0xAABB_0000,
        min_step: int = 1,
        liveness: SLivenessAnalysis | None = None,
        duplicate_outliner: Outliner | None = None,
        ail_manager: Manager,
    ):
        self.parent_func = func
        self.parent_graph = ail_graph
        self.blocks: dict[Address, Block] = {(node.addr, node.idx): node for node in ail_graph}
        self.vvar_id_start = vvar_id_start
        self.block_addr_start = block_addr_start
        self.min_step = min_step
        self.child_name = (
            child_name
            or (duplicate_outliner.child_name if duplicate_outliner is not None else None)
            or f"outlined_func_{src_loc[0]:x}"
        )
        self.novel_parent_addrs: set[Address] = set()
        self.novel_child_addrs: set[Address] = set()
        self.child_retvars: set[VirtualVariable] = set()
        self.duplicate = duplicate_outliner
        self.stmt_updates: dict[AILCodeLocation, AILCodeLocation] = {}
        self._manager = ail_manager
        self._vars_defined_in_parent = set()

        self.src_loc = src_loc
        self.child_function_start: Address = src_loc

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
            entry=self.blocks[self.parent_entry_loc],
            arg_vvars=[],  # TODO: FIXME
        )

        if frontier:
            self.frontier_locs = frontier
        else:
            self.frontier_locs = self._determine_frontier_locs()
        self.frontier_vars: set[int] = set()

        self.child_func, self.child_graph, self.child_funcargs = self._analyze()

        def render_addr(addr: tuple[int, int | None]) -> str:
            return f"{addr[0]:#x}{f'.{addr[1]}' if addr[1] is not None else ''}"

        _l.debug(
            "Outlining success: parent blocks %s child blocks %s",
            ",".join(render_addr(x) for x in self.novel_parent_addrs),
            ",".join(render_addr(x) for x in self.novel_child_addrs),
        )

    @property
    def child_vvars_for_clinic(self) -> dict[int, tuple[VirtualVariable, SimVariable]]:
        out_funcargs = {}
        for arg_idx, arg_vvar in enumerate(self.child_funcargs):
            if arg_vvar.was_parameter:
                if arg_vvar.parameter_category == VirtualVariableCategory.REGISTER:
                    simvar = SimRegisterVariable(arg_vvar.reg_offset, arg_vvar.size, ident=f"arg_{arg_idx}")
                elif arg_vvar.parameter_category == VirtualVariableCategory.STACK:
                    simvar = SimStackVariable(arg_vvar.stack_offset, arg_vvar.size, ident=f"arg_{arg_idx}")
                elif arg_vvar.parameter_category == VirtualVariableCategory.TMP:
                    assert arg_vvar.tmp_idx is not None
                    simvar = SimTemporaryVariable(arg_vvar.tmp_idx, arg_vvar.size, ident=f"arg_{arg_idx}")
                else:
                    raise NotImplementedError
            elif arg_vvar.was_reg:
                simvar = SimRegisterVariable(arg_vvar.reg_offset, arg_vvar.size, ident=f"arg_{arg_idx}")
            elif arg_vvar.was_stack:
                simvar = SimStackVariable(arg_vvar.stack_offset, arg_vvar.size, ident=f"arg_{arg_idx}")
            elif arg_vvar.was_tmp:
                assert arg_vvar.tmp_idx is not None
                simvar = SimTemporaryVariable(arg_vvar.tmp_idx, arg_vvar.size, ident=f"arg_{arg_idx}")
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

    def _next_atom(self) -> int:
        return self._manager.next_atom()

    def cleanup_interface(
        self, g: networkx.DiGraph[Block], func: Function
    ) -> tuple[list[VirtualVariable], list[Assignment]]:
        """
        Recover the and clean interface from a function AIL graph.

        If the head of the function has a Phi which wants variables from outside the function, we will
        note this in the return value so it can be fixed at the callsite, and also add a new head block
        so the Phi has a correct predecessor address for the argument.
        """

        srda = self.project.analyses[SReachingDefinitionsAnalysis].prep()(func, func_graph=g).model

        # find undefined vvars
        undef_vvars: set[int] = set()
        new_head: Block | None = None
        new_src: Address | None = None
        child_locs = {(blk.addr, blk.idx) for blk in g}
        external_phis: defaultdict[AILCodeLocation, set[int]] = defaultdict(set)
        for vvar_id, defloc in srda.all_vvar_definitions.items():
            if defloc.is_extern:
                # handle separately undefined vvars that are only ever used in phi
                # ...we also have to handle separately undefined vvars used in any phi in the first block
                use_locs = srda.all_vvar_uses[vvar_id]
                use_stmts = {
                    (loc, self.blocks[loc.addr, loc.block_idx].statements[loc.stmt_idx])
                    for _, loc in use_locs
                    if not loc.is_extern
                }
                phi_stmts = [(loc, stmt) for loc, stmt in use_stmts if is_phi_assignment(stmt)]
                start_loc_phis = [(loc, stmt) for loc, stmt in phi_stmts if (loc.addr, loc.block_idx) == self.src_loc]
                if start_loc_phis:
                    assert len(start_loc_phis) == 1, "Why is a given variable used in two phis in the same block?"
                    external_phis[start_loc_phis[0][0]].add(vvar_id)
                elif len(phi_stmts) == len(use_stmts):
                    assert False, "Why does src_loc not dominate all blocks of the child function?"
                    (use_loc,) = {l for _, l in use_locs}
                    assert self.src_loc == (
                        use_loc.block_addr,
                        use_loc.block_idx,
                    ), "Why does src_loc not dominate all blocks of the child function?"
                    external_phis[use_loc].add(vvar_id)
                else:
                    undef_vvars.add(vvar_id)

        new_callsite_phis: list[Assignment] = []
        new_vvars: list[VirtualVariable] = []
        new_blocks: dict[Address, Block] = {}
        for loc, external_vvars in external_phis.items():
            phi_block = new_blocks.get((loc.block_addr, loc.block_idx))
            if phi_block is None:
                phi_block = self.blocks[loc.block_addr, loc.block_idx].copy()
                new_blocks[loc.block_addr, loc.block_idx] = phi_block
            phi_assignment = phi_block.statements[loc.stmt_idx]
            assert (
                isinstance(phi_assignment, Assignment)
                and isinstance(phi_assignment.src, Phi)
                and isinstance(phi_assignment.dst, VirtualVariable)
            )

            if not srda.all_vvar_uses[phi_assignment.dst.varid]:
                # this var skips the function entirely! it is not actually an argument!
                phi_block.statements[loc.stmt_idx] = Label(
                    self._next_atom(), "placeholder", ins_addr=phi_assignment.tags.get("ins_addr", None)
                )  # problematic...
                # if there are any edges from the function anyway, make sure they are no-op copies and then remove them
                assert all(
                    src not in child_locs or vvar is None or vvar.varid == phi_assignment.dst.varid
                    for src, vvar in phi_assignment.src.src_and_vvars
                )
                src_and_vvars = [(src, vvar) for src, vvar in phi_assignment.src.src_and_vvars if src not in child_locs]
                if len(src_and_vvars) == 1:
                    assert False, (
                        "Why is there a phi which is not used in the function but only consumes one variable from before the function?"
                    )
                phi_assignment = Assignment(
                    phi_assignment.idx,
                    phi_assignment.dst,
                    Phi(phi_assignment.src.idx, phi_assignment.src.bits, src_and_vvars, **phi_assignment.src.tags),
                    **phi_assignment.tags,
                )
                phi_block.statements[loc.stmt_idx] = Label(self._next_atom(), "placeholder", ins_addr=loc.ins_addr)
                new_callsite_phis.append(phi_assignment)
                continue

            new_varid = self._next_vvar_id()
            new_vvar = VirtualVariable(
                self._next_atom(),
                new_varid,
                phi_assignment.dst.bits,
                phi_assignment.dst.category,
                phi_assignment.dst.oident,
            )
            new_vvars.append(new_vvar)

            # update callsite
            if len(external_vvars) == 1:
                # ... or not
                new_callsite_src = srda.varid_to_vvar[max(external_vvars)]
            else:
                new_callsite_src = Phi(
                    self._next_atom(),
                    new_vvar.bits,
                    [(src, vvar) for src, vvar in phi_assignment.src.src_and_vvars if src not in child_locs],
                )
            new_callsite_phi = Assignment(self._next_atom(), new_vvar, new_callsite_src)
            new_callsite_phis.append(new_callsite_phi)

            # update callee head
            if external_vvars == {vvar for _, vvar in phi_assignment.src.src_and_vvars if vvar is not None}:
                # all predecessors are external - this is the actual arg
                # n.b. for outlining paper we cannot change any given (block_addr, block_idx, stmt_idx)'s actual semantics
                # ...but "just do a phi" or "just do an assignment" are equivalent
                phi_assignment = Assignment(phi_assignment.idx, phi_assignment.dst, new_vvar, **phi_assignment.tags)
            else:
                # some predecessors are not external - need to adjust the head
                if new_head is None or new_src is None:
                    new_src = self._next_block_addr(), None
                    new_head = Block(
                        new_src[0],
                        0,
                        cast(list[Statement], [
                            Jump(
                                self._next_atom(),
                                Const(self._next_atom(), new_src[0], self.project.arch.bits),
                                new_src[1],
                                ins_addr=new_src[0],
                            )
                        ]),
                        new_src[1],
                    )
                    self.blocks[new_src] = new_head
                    child_locs.add(new_src)
                    g.add_edge(new_head, self.blocks[self.src_loc])
                    self.novel_child_addrs.add(new_src)
                    self.child_function_start = new_src
                src_and_vvars = [
                    (src, vvar)
                    for src, vvar in phi_assignment.src.src_and_vvars
                    if src in child_locs and vvar not in external_vvars
                ]
                src_and_vvars.append((new_src, new_vvar))
                if len(src_and_vvars) == 1:
                    src = src_and_vvars[0][1]
                    assert src is not None
                    phi_assignment = Assignment(phi_assignment.idx, phi_assignment.dst, src, **phi_assignment.tags)
                else:
                    phi_assignment = Assignment(
                        phi_assignment.idx,
                        phi_assignment.dst,
                        Phi(self._next_atom(), phi_assignment.src.bits, src_and_vvars, **phi_assignment.src.tags),
                        **phi_assignment.tags,
                    )
            phi_block.statements[loc.stmt_idx] = phi_assignment

        networkx.relabel_nodes(g, {self.blocks[addr]: id(new) for addr, new in new_blocks.items()}, copy=False)
        networkx.relabel_nodes(
            self.parent_graph, {self.blocks[addr]: id(new) for addr, new in new_blocks.items()}, copy=False
        )
        networkx.relabel_nodes(g, {id(new): new for new in new_blocks.values()}, copy=False)  # type: ignore
        networkx.relabel_nodes(self.parent_graph, {id(new): new for new in new_blocks.values()}, copy=False)  # type: ignore
        self.blocks.update(new_blocks)

        return [srda.varid_to_vvar[varid] for varid in sorted(undef_vvars)] + new_vvars, new_callsite_phis

    def _analyze(self):
        if self.src_loc not in self.blocks:
            raise KeyError(f"Source location {self.src_loc} is not valid in the given graph.")

        frontier: set[Address] = set()
        exclusive_frontier: set[Address] = set()
        # ensure locs is valid
        for loc, inclusive in self.frontier_locs:
            if loc not in self.blocks:
                raise KeyError(f"Frontier location {loc} is not valid in the given graph.")
            frontier.add(loc)
            if not inclusive:
                exclusive_frontier.add(loc)

        # generate a subgraph
        subgraph = subgraph_between_nodes(
            self.parent_graph, self.blocks[self.src_loc], (self.blocks[loc] for loc in frontier), include_frontier=True
        )
        for loc in list(frontier):
            node = self.blocks[loc]
            if node not in subgraph:
                _l.warning("Requested an frontier of %s but it was not reached", node)
                frontier.remove(loc)
                exclusive_frontier.discard(loc)

        subgraph.remove_nodes_from(self.blocks[loc] for loc in exclusive_frontier)
        if not subgraph:
            raise AngrOutlinerEmptySubgraphError("Trying to outline an empty subgraph")

        # normalize the frontier, making it so that we only use an inclusive node if we reach the end of the function
        for loc in list(frontier):
            if loc in exclusive_frontier:
                continue
            blk = self.blocks[loc]
            if self.parent_graph.out_degree(blk) == 0:
                continue
            # this node is inclusive but has successors. convert it to an exclusive frontier.
            frontier.remove(loc)
            exclusive_frontier.update((n2.addr, n2.idx) for n2 in self.parent_graph.succ[blk] if n2 not in subgraph)

            # also handle a silly case - we have an inclusive frontier but one of its successors goes back into the subgraph
            # these edges are omitted by default
            for n2 in self.parent_graph.succ[blk]:
                if n2 in subgraph:
                    subgraph.add_edge(blk, n2)

        inclusive_frontier = frontier - exclusive_frontier
        frontier.update(exclusive_frontier)

        # "reaching the end of the function" for an inclusive frontier can either be a return statement or a noret call.
        # separate these and also generate a full list of out edges
        in_edges = [((node.addr, node.idx), self.src_loc) for node in self.parent_graph.pred[self.blocks[self.src_loc]]]
        out_edges: list[tuple[Address, Address | None]] = [
            ((node.addr, node.idx), frontier_loc)
            for frontier_loc in exclusive_frontier
            for node in self.parent_graph.pred[self.blocks[frontier_loc]]
            if node in subgraph and (node.addr, node.idx) not in frontier
        ]
        inclusive_frontier_returns: set[Address] = set()
        inclusive_frontier_noreturns: set[Address] = set()
        for loc in inclusive_frontier:
            blk = self.blocks[loc]
            if isinstance(blk.statements[-1], Return):
                out_edges.append((loc, None))
                inclusive_frontier_returns.add(loc)
            else:
                inclusive_frontier_noreturns.add(loc)

        # identify return vars
        for loc in exclusive_frontier:
            node = self.blocks[loc]
            for pred in self.parent_graph.pred[node]:
                if pred not in subgraph:
                    continue
                self.frontier_vars.update(
                    self.parent_liveness.model.live_outs[(pred.addr, pred.idx)]
                    & self.parent_liveness.model.live_ins[loc]
                )
        for loc in inclusive_frontier:
            self.frontier_vars.update(self.parent_liveness.model.live_outs[loc])
        self.frontier_vars -= self.parent_liveness.model.live_ins[self.src_loc]

        for u, v in self.parent_graph.edges:
            if v in subgraph and u not in subgraph and (v.addr, v.idx) != self.src_loc:
                raise AngrOutlinerMultiEntranceError("Request for outlining function with multiple entrances")

        # begin mutation!
        self.parent_graph.remove_nodes_from(subgraph)
        self.novel_child_addrs.update((b.addr, b.idx) for b in subgraph)

        # generate or reuse the child's Function object
        if self.duplicate:
            callee_func = self.duplicate.child_func
        else:
            callee_func = Function(self.kb.functions, self.src_loc[0], name=self.child_name)
            callee_func.normalized = True

        # figure out the interface of the new callee
        callee_arg_vvars, new_assignments = self.cleanup_interface(subgraph, callee_func)
        for stmt in new_assignments:
            stmt.tags["ins_addr"] = self.src_loc[0]
        self.frontier_vars -= {cast(VirtualVariable, stmt.dst).varid for stmt in new_assignments}

        # generate return vvar expressions
        if self.frontier_vars:
            srda = (
                self.project.analyses[SReachingDefinitionsAnalysis]
                .prep()(self.parent_func, func_graph=self.parent_graph)
                .model
            )
            ret_vars = [srda.varid_to_vvar[idx] for idx in self.frontier_vars]
            self._vars_defined_in_parent = {
                varid for varid, defn in srda.all_vvar_definitions.items() if not defn.is_extern
            }
        else:
            ret_vars = []
        self.child_retvars = set(ret_vars)
        ret_exprs = list(ret_vars)

        # rewrite the callsite
        switch_varid = self._next_vvar_id()
        switch_vvar = VirtualVariable(
            None,
            switch_varid,
            self.project.arch.bits,
            VirtualVariableCategory.TMP,
            oident=switch_varid,
        )

        # if there are multiple successors; this means the function must return to different locations. let's build
        # the dispatcher structure (at the return site in the caller) and the return nodes (in the callee)
        ctr = 1  # ctr=0 represents tail calls
        target_to_retval: dict[Address, int] = {}
        if len(frontier) > 1:
            ret_vars.append(switch_vvar)
            for loc in sorted(exclusive_frontier):
                target_to_retval[loc] = ctr
                ctr += 1

        tuple_varid = self._next_vvar_id()
        tuple_vvar = VirtualVariable(
            None,
            tuple_varid,
            sum(v.bits for v in ret_vars),
            VirtualVariableCategory.TMP,
            oident=tuple_varid,
        )
        callee_arg_vvars_copy = [arg_vvar.copy() for arg_vvar in callee_arg_vvars]
        # create the callsite in the caller
        call_expr = Call(
            self._next_atom(),
            self.child_name,
            # Const(self._next_atom(), None, src_node.addr, 64),
            args=callee_arg_vvars_copy,
            bits=self.project.arch.bits,
            ins_addr=self.src_loc[0],
        )
        call_stmt = Assignment(self._next_atom(), tuple_vvar, call_expr, ins_addr=self.src_loc[0])
        new_src_node = Block(
            self._next_block_addr(),
            0,
            [*cast("list[Statement]", new_assignments), call_stmt],
        )
        self.blocks[new_src_node.addr, new_src_node.idx] = new_src_node
        self.novel_parent_addrs.add((new_src_node.addr, new_src_node.idx))
        if self.parent_entry_loc in self.novel_child_addrs:
            self.parent_entry_loc = (new_src_node.addr, new_src_node.idx)

        bit_sum = 0
        for ret_var in ret_vars:
            # safe: mutating a fresh block
            new_src_node.statements.append(
                Assignment(
                    self._next_atom(),
                    ret_var,
                    Extract(
                        self._next_atom(),
                        ret_var.bits,
                        tuple_vvar,
                        Const(self._next_atom(), bit_sum // 8, self.project.arch.bits),
                        Endness.BE,
                    ),
                    ins_addr=self.src_loc[0],
                )
            )
            bit_sum += ret_var.bits
        for pred_loc, _ in in_edges:
            pred = self.blocks[pred_loc]
            if pred in subgraph:
                continue
            self.parent_graph.add_edge(pred, new_src_node)

        # create the callee return statement(s)
        for ret_loc, frontier_loc in out_edges:
            if len(exclusive_frontier) > 1:
                novel_ret_value = 0 if frontier_loc is None else target_to_retval[frontier_loc]
                new_ret_exprs = [*ret_exprs, Const(self._next_atom(), novel_ret_value, self.project.arch.bits)]
            else:
                new_ret_exprs = ret_exprs
            new_ret_expr = Const(self._next_atom(), 0, tuple_vvar.bits, uninitialized=True)
            bit_sum = 0
            for new_ret_subexpr in new_ret_exprs:
                new_ret_expr = Insert(
                    self._next_atom(),
                    new_ret_expr,
                    Const(self._next_atom(), bit_sum // 8, self.project.arch.bits),
                    new_ret_subexpr,
                    Endness.BE,
                )
                bit_sum += new_ret_subexpr.bits
            old_ret_node = self.blocks[ret_loc]
            ret_node = old_ret_node.copy()
            self.blocks[ret_loc] = ret_node
            networkx.relabel_nodes(subgraph, {old_ret_node: id(ret_node)}, copy=False)
            networkx.relabel_nodes(subgraph, {id(ret_node): ret_node}, copy=False)  # type: ignore
            ret_stmt = Return(
                self._next_atom(), [new_ret_expr], ins_addr=max(stmt.tags.get("ins_addr", -1) for stmt in ret_node.statements)
            )

            # safe: we copied ret_node
            if frontier_loc is None:
                # we can modify the ret_node directly
                assert ret_node.statements and isinstance(ret_node.statements[-1], Return)
                del ret_node.statements[-1]
                ret_node.statements.append(ret_stmt)
            elif ret_node.statements and isinstance(ret_node.statements[-1], ConditionalJump):
                # we will have to create a new node and act as the successor of ret_node
                new_ret_node = Block(self._next_block_addr(), 0, [ret_stmt])
                self.blocks[new_ret_node.addr, new_ret_node.idx] = new_ret_node
                self.novel_parent_addrs.add((new_ret_node.addr, new_ret_node.idx))
                cond_jump = ret_node.statements[-1]
                if (
                    isinstance(cond_jump.true_target, Const)
                    and cond_jump.true_target.value == frontier_loc[0]
                    and cond_jump.true_target_idx == frontier_loc[1]
                ):
                    _, cond_jump = cond_jump.replace(
                        cond_jump.true_target, Const(self._next_atom(), new_ret_node.addr, self.project.arch.bits)
                    )
                    cond_jump.true_target_idx = new_ret_node.idx
                elif (
                    isinstance(cond_jump.false_target, Const)
                    and cond_jump.false_target.value == frontier_loc[0]
                    and cond_jump.false_target_idx == frontier_loc[1]
                ):
                    _, cond_jump = cond_jump.replace(
                        cond_jump.false_target,
                        Const(self._next_atom(), new_ret_node.addr, self.project.arch.bits),
                    )
                    cond_jump.false_target_idx = new_ret_node.idx
                else:
                    assert False, "Conditional jump targets do not match graph structure"
                ret_node.statements[-1] = cond_jump
                subgraph.add_edge(ret_node, new_ret_node)
            else:
                if ret_node.statements and isinstance(ret_node.statements[-1], Jump):
                    del ret_node.statements[-1]
                ret_node.statements.append(ret_stmt)

        # create the caller return site
        if len(exclusive_frontier) > 1:
            # build the dispatcher structure in the caller
            parent = new_src_node
            next_dispatcher_node_addr = self._next_block_addr(), None
            retval_to_target_items = sorted((b, a) for a, b in target_to_retval.items())
            last_jump_target = None if inclusive_frontier_returns else retval_to_target_items.pop()[1]
            for retval, jump_target in retval_to_target_items:
                dispatcher_node_addr = next_dispatcher_node_addr
                next_dispatcher_node_addr = self._next_block_addr(), None

                retval_const = Const(self._next_atom(), retval, self.project.arch.bits)
                cmp = BinaryOp(self._next_atom(), "CmpEQ", [switch_vvar, retval_const])
                stmt = ConditionalJump(
                    self._next_atom(),
                    cmp,
                    Const(self._next_atom(), jump_target[0], self.project.arch.bits),
                    Const(self._next_atom(), next_dispatcher_node_addr[0], self.project.arch.bits),
                    true_target_idx=jump_target[1],
                    false_target_idx=next_dispatcher_node_addr[1],
                    ins_addr=dispatcher_node_addr[0],
                )
                dispatcher_node = Block(dispatcher_node_addr[0], 0, [stmt], dispatcher_node_addr[1])
                self.blocks[dispatcher_node_addr] = dispatcher_node
                self.novel_parent_addrs.add(dispatcher_node_addr)
                self.parent_graph.add_edge(parent, dispatcher_node)
                self.parent_graph.add_edge(dispatcher_node, self.blocks[jump_target])

                self._update_phi_stmts(self.blocks[jump_target])

                parent = dispatcher_node

            final_node = Block(next_dispatcher_node_addr[0], 0, [], next_dispatcher_node_addr[1])
            self.blocks[next_dispatcher_node_addr] = final_node
            self.novel_parent_addrs.add(next_dispatcher_node_addr)
            self.parent_graph.add_edge(parent, final_node)
            # safe: this is fresh
            if last_jump_target:
                final_node.statements.append(
                    Jump(
                        self._next_atom(),
                        Const(self._next_atom(), last_jump_target[0], self.project.arch.bits),
                        last_jump_target[1],
                        ins_addr=final_node.addr,
                    )
                )
                self.parent_graph.add_edge(final_node, self.blocks[last_jump_target])
                self._update_phi_stmts(self.blocks[last_jump_target])
            else:
                final_node.statements.append(Return(self._next_atom(), [switch_vvar], ins_addr=final_node.addr))

        elif exclusive_frontier:
            # simple return value. just stitch the callsite to the return site.
            (frontier_loc,) = frontier
            frontier_node = self.blocks[frontier_loc]
            self.parent_graph.add_edge(new_src_node, frontier_node)
            self._update_phi_stmts(frontier_node)

        self._update_phi_stmts(new_src_node)

        return callee_func, subgraph, callee_arg_vvars

    def _update_phi_stmts(self, block: Block):
        srcs = list(self.parent_graph.predecessors(block))
        src_addrs = [(src.addr, src.idx) for src in srcs]
        edits: defaultdict[Block, dict[int, list[tuple[Address, VirtualVariable | None]]]] = defaultdict(dict)
        for stmt_idx, stmt in enumerate(block.statements):
            if (
                not isinstance(stmt, Assignment)
                or not isinstance(stmt.src, Phi)
                or not isinstance(stmt.dst, VirtualVariable)
            ):
                continue

            return_vars = {v for _, v in stmt.src.src_and_vvars if v in self.child_retvars}
            assert len(return_vars) <= 1, "This retsite runs Phi on multiple return values"
            exemplar_return_var = next(iter(return_vars), None)
            passthru_vars = {
                v
                for s, v in stmt.src.src_and_vvars
                if (v is not None and v not in self.child_retvars and s in self.novel_parent_addrs)
                or s in self.novel_child_addrs
            }
            assert len(passthru_vars) <= 1, (
                "This retsite runs Phi on multiple vars coming through the child function which are NOT defined in the function"
            )
            exemplar_passthru_var = next(iter(passthru_vars), None)

            old_mapping = dict(stmt.src.src_and_vvars)
            novel_preds = set(src_addrs) & (self.novel_parent_addrs | self.novel_child_addrs)
            new_mapping: dict[Address, VirtualVariable | None] = {}

            for pred in src_addrs:
                if pred in novel_preds:
                    if pred in self.child_retvars:
                        assert exemplar_return_var is not None, (
                            "This retsite wants a var defined in the child but it's none of the ret values?"
                        )
                        new_mapping[pred] = exemplar_return_var
                    else:
                        new_mapping[pred] = exemplar_passthru_var
                else:
                    assert pred in old_mapping, "Untouched predecessor was not previously available in Phi?"
                    new_mapping[pred] = old_mapping[pred]

            assert any(vvar is not None for vvar in new_mapping.values())
            edits[block][stmt_idx] = sorted(new_mapping.items(), key=lambda x: (x[0][0], x[0][1] is not None, x[0][1]))

        new_blocks: dict[Address, Block] = {}
        for old, stmts in edits.items():
            new = old.copy()
            new_blocks[new.addr, new.idx] = new
            for stmt_idx, src_and_vvars in stmts.items():
                old_assignment = old.statements[stmt_idx]
                assert isinstance(old_assignment, Assignment)
                assert isinstance(old_assignment.src, Phi)
                new.statements[stmt_idx] = Assignment(
                    old_assignment.idx,
                    old_assignment.dst,
                    Phi(old_assignment.src.idx, old_assignment.src.bits, src_and_vvars, **old_assignment.src.tags),
                    **old_assignment.tags,
                )

        networkx.relabel_nodes(
            self.parent_graph, {self.blocks[addr]: id(new) for addr, new in new_blocks.items()}, copy=False
        )
        networkx.relabel_nodes(self.parent_graph, {id(new): new for new in new_blocks.values()}, copy=False)  # type: ignore
        self.blocks.update(new_blocks)

    @staticmethod
    def _node_addr_to_str(addr: tuple[int, int | None], inclusive: bool) -> str:
        """
        Convert a node address to a string representation.
        """
        incl = "inclusive" if inclusive else "exclusive"
        return f"{addr[0]:#x}.{addr[1]} {incl}" if addr[1] is not None else f"{addr[0]:#x} {incl}"

    def _determine_frontier_locs(self) -> set[tuple[Address, bool]]:
        _l.debug("Determining the outlining frontier starting at (%#x, %s)", self.src_loc[0], self.src_loc[1])

        live_vars_dict = self.parent_liveness.live_vars_by_stmt()
        assert self.src_loc in live_vars_dict

        # find its dominance frontier
        doms = Dominators(self.parent_graph, self.blocks[self.parent_entry_loc])
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
