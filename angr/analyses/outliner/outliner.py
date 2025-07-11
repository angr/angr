from __future__ import annotations
import networkx

from angr.ailment import Block
from angr.ailment.statement import Call, Assignment, ConditionalJump
from angr.ailment.expression import Const, BinaryOp, VirtualVariable, VirtualVariableCategory

from angr.utils.ssa import is_phi_assignment
from angr.analyses import Analysis, AnalysesHub
from angr.analyses.s_reaching_definitions import SReachingDefinitionsAnalysis
from angr.code_location import ExternalCodeLocation
from angr.knowledge_plugins.functions import Function
from angr.utils.graph import subgraph_between_nodes


class Outliner(Analysis):
    """
    Outliner takes a function and some locations and attempts to outline the blocks within these locations into a
    separate function.
    """

    def __init__(
        self,
        func,
        ail_graph: networkx.DiGraph,
        src_loc: tuple[int, int | None],
        frontier: set[tuple[int, int | None]],
        vvar_id_start: int = 0xBEEF,
        block_addr_start: int = 0xAABB_0000,
    ):
        self.func = func
        self.graph = ail_graph
        self.src_loc = src_loc
        self.frontier_locs = frontier
        self.vvar_id_start = vvar_id_start
        self.block_addr_start = block_addr_start

        self.out_func = None
        self.out_graph = None
        self.out_funcargs = None

        self._analyze()

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
        nodes_dict = {(node.addr, node.idx): node for node in g}

        for phi_var_id, src_var_ids in srda.phivarid_to_varids.items():
            if all(isinstance(srda.all_vvar_definitions[src_varid], ExternalCodeLocation) for src_varid in src_var_ids):
                # remove the phi assignment
                phi_def_loc = srda.all_vvar_definitions[phi_var_id]
                phi_def_node = nodes_dict[(phi_def_loc.block_addr, phi_def_loc.block_idx)]
                phi_def_node.statements[phi_def_loc.stmt_idx] = None

        # remove None statements
        for node in nodes_dict.values():
            if None in node.statements:
                node.statements = [stmt for stmt in node.statements if stmt is not None]

    def get_interface(self, g: networkx.DiGraph, func: Function, start: Block) -> list[VirtualVariable]:
        """
        Recover the interface from a function AIL graph.
        """

        srda = self.project.analyses[SReachingDefinitionsAnalysis].prep()(func, func_graph=g).model

        blocks = {(node.addr, node.idx): node for node in g}

        # find undefined vvars
        undef_vvars = []
        for vvar_id, defloc in srda.all_vvar_definitions.items():
            if isinstance(defloc, ExternalCodeLocation):
                # remove undefined vvars that are only ever used in phi assignments
                use_locs = srda.all_vvar_uses[vvar_id]
                use_stmts = [
                    blocks[loc.block_addr, loc.block_idx].statements[loc.stmt_idx]
                    for _, loc in use_locs
                    if not isinstance(loc, ExternalCodeLocation)
                ]
                if not all(is_phi_assignment(stmt) for stmt in use_stmts):
                    undef_vvars.append(vvar_id)

        func_arg_vvars = [srda.varid_to_vvar[varid] for varid in undef_vvars]
        return func_arg_vvars

    def _analyze(self):
        node_dict: dict[tuple[int, int | None], Block] = {(node.addr, node.idx): node for node in self.graph.nodes}
        try:
            src_node = node_dict[self.src_loc]
        except KeyError:
            raise KeyError(f"Source location {self.src_loc} is not valid in the given graph.")

        frontier = []
        # ensure locs is valid
        for loc in self.frontier_locs:
            try:
                frontier.append(node_dict[loc])
            except KeyError:
                raise KeyError(f"Location {loc} is not valid in the given graph.")

        retval_to_target: dict[int, tuple[int, int | None]] = {}
        if len(frontier) > 1:
            # there are multiple successors; this means the function must return to different locations. let's build
            # the dispatcher structure (at the return site in the caller) and the return nodes (in the callee)
            for succ in sorted(frontier, key=lambda node: (node.addr, node.idx)):
                retval_to_target[succ.addr] = succ.addr, succ.idx

            # TODO: Return nodes

        # generate a subgraph
        subgraph = subgraph_between_nodes(self.graph, src_node, frontier, include_frontier=True)

        # remove the subgraph from the original graph
        for src, dst in subgraph.edges:
            self.graph.remove_edge(src, dst)
        for node in subgraph:
            if node is src_node or node in frontier:
                pass
            elif self.graph.in_degree[node] == 0 and self.graph.out_degree[node] == 0:
                # orphaned nodes
                self.graph.remove_node(node)
            else:
                self.graph.remove_node(node)

        callee_func = Function(self.kb.functions, src_node.addr)
        callee_func.normalized = True
        # clean up the subgraph
        self.cleanup_callee_graph(subgraph, callee_func)
        # figure out the interface of the new callee
        callee_arg_vvars = self.get_interface(subgraph, callee_func, src_node)

        # rewrite the callsite
        vvar_id = self._next_vvar_id()
        call_expr = Call(
            None,
            Const(None, None, src_node.addr, 64),
            args=callee_arg_vvars,
            bits=self.project.arch.bits,
            ins_addr=src_node.addr,
        )
        vvar = VirtualVariable(
            None, vvar_id, self.project.arch.bits, VirtualVariableCategory.REGISTER, oident=self.project.arch.ret_offset
        )
        call_stmt = Assignment(None, vvar, call_expr, ins_addr=src_node.addr)
        new_src_node = Block(src_node.addr, src_node.original_size, [call_stmt], idx=src_node.idx)
        for pred in list(self.graph.predecessors(src_node)):
            self.graph.add_edge(pred, new_src_node)
        self.graph.remove_node(src_node)

        if frontier:
            if retval_to_target:
                # build the dispatcher structure
                parent = new_src_node
                next_dispatcher_node_addr = self._next_block_addr(), None
                retval_to_target_items = list(retval_to_target.items())[:-1]
                last_retval_to_target_item = list(retval_to_target.items())[-1]
                for retval, jump_target in retval_to_target_items:
                    dispatcher_node_addr = next_dispatcher_node_addr
                    next_dispatcher_node_addr = dispatcher_node_addr[0] + 1, None

                    retval_const = Const(None, None, retval, self.project.arch.bits)
                    vvar = VirtualVariable(
                        None,
                        vvar_id,
                        self.project.arch.bits,
                        VirtualVariableCategory.REGISTER,
                        oident=self.project.arch.ret_offset,
                    )
                    cmp = BinaryOp(None, "CmpEQ", [vvar, retval_const])
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
                    self.graph.add_edge(parent, dispatcher_node)
                    self.graph.add_edge(dispatcher_node, node_dict[jump_target])

                    self._update_phi_stmts(node_dict[jump_target])

                    parent = dispatcher_node

                self.graph.add_edge(parent, node_dict[last_retval_to_target_item[1]])

            else:
                frontier_node = next(iter(frontier))
                self.graph.add_edge(new_src_node, frontier_node)
                self._update_phi_stmts(frontier_node)

        self.out_func = callee_func
        self.out_funcargs = callee_arg_vvars
        self.out_graph = subgraph

    def _update_phi_stmts(self, block: Block):
        srcs = list(self.graph.predecessors(block))
        src_addrs = [(src.addr, src.idx) for src in srcs]
        for stmt in block.statements:
            if is_phi_assignment(stmt):
                all_stmt_srcs = [src for src, _ in stmt.src.src_and_vvars]
                old_addrs = set(src_addrs) - set(all_stmt_srcs)
                new_addrs = set(all_stmt_srcs) - set(src_addrs)
                if len(old_addrs) == 1 and len(new_addrs) == 1:
                    # only source block is replaced by a new one
                    old_addr = next(iter(old_addrs))
                    new_addr = next(iter(new_addrs))
                    for idx in range(len(stmt.src.src_and_vvars)):
                        src, vvars = stmt.src.src_and_vvars[idx]
                        if src == old_addr:
                            stmt.src.src_and_vvars[idx] = new_addr, vvars
                else:
                    # multiple source blocks have been replaced... it's bad
                    raise NotImplementedError

    def execute(self):
        """
        Execute the outlined function.
        """

        # TODO: switch to AIL-based execution

        base_state = self.project.factory.blank_state(addr=self.out_func.addr)
        base_state.regs._r12 = 0
        base_state.regs._rdi = 0xFFFF_FFFF

        callable = self.project.factory.callable(
            self.out_func.addr, avoid_addrs={addr for addr, _ in self.frontier_locs}, base_state=base_state
        )
        callable()
        print(callable.result_path_group.active)
        state = callable.result_path_group.active[0]

        heap_addr = 0xC000_0000
        buffer = state.solver.eval(state.memory.load(heap_addr, 824), cast_to=bytes)
        return state, buffer


AnalysesHub.register_default("Outliner", Outliner)
