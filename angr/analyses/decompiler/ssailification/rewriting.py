from __future__ import annotations
from typing import Any
from collections.abc import Callable
from functools import partial
import logging

import networkx

import ailment
from ailment import Block
from ailment.expression import Expression, Phi, VirtualVariable, VirtualVariableCategory
from ailment.statement import Assignment, Label

from angr.code_location import CodeLocation
from angr.analyses import ForwardAnalysis
from angr.analyses.forward_analysis.visitors.graph import NodeType
from angr.analyses.forward_analysis import FunctionGraphVisitor
from .rewriting_engine import SimEngineSSARewriting
from .rewriting_state import RewritingState


l = logging.getLogger(__name__)


class RewritingAnalysis(ForwardAnalysis[RewritingState, NodeType, object, object]):
    """
    RewritingAnalysis traverses the AIL graph, inserts phi nodes, and rewrites all expression uses to virtual variables
    when necessary.
    """

    def __init__(
        self,
        project,
        func,
        ail_graph,
        sp_tracker,
        bp_as_gpr: bool,
        udef_to_phiid: dict[tuple, set[int]],
        phiid_to_loc: dict[int, tuple[int, int | None]],
        stackvar_locs: dict[int, int],
        ail_manager,
        vvar_id_start: int = 0,
    ):
        self.project = project
        self._function = func
        self._graph_visitor = FunctionGraphVisitor(self._function, ail_graph)

        ForwardAnalysis.__init__(
            self, order_jobs=True, allow_merging=False, allow_widening=False, graph_visitor=self._graph_visitor
        )
        self._graph = ail_graph
        self._udef_to_phiid = udef_to_phiid
        self._phiid_to_loc = phiid_to_loc
        self._stackvar_locs = stackvar_locs
        self._ail_manager = ail_manager
        self._engine_ail = SimEngineSSARewriting(
            self.project.arch,
            project=self.project,
            sp_tracker=sp_tracker,
            bp_as_gpr=bp_as_gpr,
            udef_to_phiid=self._udef_to_phiid,
            phiid_to_loc=self._phiid_to_loc,
            stackvar_locs=self._stackvar_locs,
            ail_manager=ail_manager,
            vvar_id_start=vvar_id_start,
        )

        self._visited_blocks: set[Any] = set()
        self.out_blocks = {}
        self.out_states = {}

        self._analyze()

        self.def_to_vvid: dict[Expression, int] = self._engine_ail.def_to_vvid
        self.out_graph = self._make_new_graph(ail_graph)

    @property
    def max_vvar_id(self) -> int | None:
        return self._engine_ail.current_vvar_id

    def _make_new_graph(self, old_graph: networkx.DiGraph) -> networkx.DiGraph:
        new_graph = networkx.DiGraph()
        for node in old_graph:
            new_graph.add_node(self.out_blocks.get((node.addr, node.idx), node))

        for src, dst, data in old_graph.edges(data=True):
            new_graph.add_edge(
                self.out_blocks.get((src.addr, src.idx), src),
                self.out_blocks.get((dst.addr, dst.idx), dst),
                **data,
            )

        return new_graph

    def create_phi_statements(self, node, udef_to_phiid: dict, phiid_to_loc: dict) -> list[Assignment]:
        phi_ids = []
        for phiid, (block_addr, block_idx) in phiid_to_loc.items():
            if block_addr == node.addr and block_idx == node.idx:
                phi_ids.append(phiid)

        phiid_to_udef = {}
        for udef, phiids in udef_to_phiid.items():
            for phiid in phiids:
                phiid_to_udef[phiid] = udef

        phi_stmts = []
        for phi_id in phi_ids:
            udef = phiid_to_udef[phi_id]
            category = udef[0]

            match category:
                case "reg":
                    _, reg_offset, reg_bits = udef

                    phi_var = Phi(
                        self._ail_manager.next_atom(),
                        reg_bits,
                        src_and_vvars=[],  # back patch later
                    )
                    phi_dst = VirtualVariable(
                        self._ail_manager.next_atom(),
                        self._engine_ail.next_vvar_id(),
                        reg_bits,
                        VirtualVariableCategory.REGISTER,
                        oident=reg_offset,
                    )

                case "stack":
                    _, stack_offset, stack_size = udef

                    phi_var = Phi(
                        self._ail_manager.next_atom(),
                        stack_size * self.project.arch.byte_width,
                        src_and_vvars=[],  # back patch later
                    )
                    phi_dst = VirtualVariable(
                        self._ail_manager.next_atom(),
                        self._engine_ail.next_vvar_id(),
                        stack_size * self.project.arch.byte_width,
                        VirtualVariableCategory.STACK,
                        oident=stack_offset,
                    )
                case _:
                    raise NotImplementedError

            phi_stmt = Assignment(
                None,
                phi_dst,
                phi_var,
                ins_addr=node.addr,
            )
            phi_stmts.append(phi_stmt)

        return phi_stmts

    @staticmethod
    def insert_phi_statements(node: Block, phi_stmts: list[Assignment]):
        idx = 0
        while idx < len(node.statements):
            if not isinstance(node.statements[idx], Label):
                break
            idx += 1

        if idx >= len(node.statements):
            node.statements += phi_stmts
        else:
            node.statements = node.statements[:idx] + phi_stmts + node.statements[idx:]

    def _reg_predicate(self, node_, *, reg_offset: int, reg_size: int) -> tuple[bool, Any]:
        out_state: RewritingState = self.out_states[(node_.addr, node_.idx)]
        if reg_offset in out_state.registers and reg_size in out_state.registers[reg_offset]:
            if out_state.registers[reg_offset][reg_size] is None:
                # the vvar is not set. it should never be referenced
                return True, None
            vvar = out_state.registers[reg_offset][reg_size].copy()
            vvar.idx = self._ail_manager.next_atom()
            return True, vvar
        return False, None

    def _stack_predicate(self, node_, *, stack_offset: int, stackvar_size: int) -> tuple[bool, Any]:
        out_state: RewritingState = self.out_states[(node_.addr, node_.idx)]
        if stack_offset in out_state.stackvars and stackvar_size in out_state.stackvars[stack_offset]:
            if out_state.stackvars[stack_offset][stackvar_size] is None:
                # the vvar is not set. it should never be referenced
                return True, None
            vvar = out_state.stackvars[stack_offset][stackvar_size].copy()
            vvar.idx = self._ail_manager.next_atom()
            return True, vvar
        return False, None

    #
    # Main analysis routines
    #

    def _pre_analysis(self):
        for node in self.graph:
            phi_stmts = self.create_phi_statements(node, self._udef_to_phiid, self._phiid_to_loc)
            if phi_stmts:
                self.insert_phi_statements(node, phi_stmts)

    def _initial_abstract_state(self, node) -> RewritingState:
        return RewritingState(
            CodeLocation(node.addr, stmt_idx=0, ins_addr=node.addr, block_idx=node.idx),
            self.project.arch,
            self._function,
            node,
        )

    def _run_on_node(self, node, state: RewritingState):
        """

        :param node:    The current node.
        :param state:   The analysis state.
        :return:        A tuple: (any changes occur, successor state)
        """

        if isinstance(node, ailment.Block):
            block = node
            block_key = (node.addr, node.idx)
            engine = self._engine_ail
        else:
            l.warning("Unsupported node type %s.", node.__class__)
            return False, state

        if block_key in self._visited_blocks:
            return False, state

        engine: SimEngineSSARewriting

        old_state = state
        state = old_state.copy()
        state.loc = CodeLocation(block.addr, stmt_idx=0, ins_addr=block.addr, block_idx=block.idx)
        state.original_block = node

        engine.process(
            state,
            block=block,
        )

        self._visited_blocks.add(block_key)
        self.out_states[block_key] = state

        if state.out_block is not None:
            assert state.out_block.addr == block.addr

            if self.out_blocks.get(block_key, None) == state.out_block:
                return True, state
            self.out_blocks[block_key] = state.out_block
            state.out_block = None
            return True, state

        return True, state

    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        # update phi nodes
        for original_node in self.graph:
            node_key = original_node.addr, original_node.idx
            node = self.out_blocks.get(node_key, original_node)

            if any(
                isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and isinstance(stmt.src, Phi)
                for stmt in node.statements
            ):
                # there we go
                new_stmts = []
                for stmt in node.statements:
                    if not (
                        isinstance(stmt, Assignment)
                        and isinstance(stmt.dst, VirtualVariable)
                        and isinstance(stmt.src, Phi)
                        and len(stmt.src.src_and_vvars) == 0  # avoid re-assignment
                    ):
                        new_stmts.append(stmt)
                        continue

                    src_and_vvars = []
                    if stmt.dst.was_reg:
                        for pred in self.graph.predecessors(original_node):
                            vvar = self._follow_one_path_backward(
                                self.graph,
                                pred,
                                partial(self._reg_predicate, reg_offset=stmt.dst.reg_offset, reg_size=stmt.dst.size),
                            )
                            src_and_vvars.append(((pred.addr, pred.idx), vvar))
                    elif stmt.dst.was_stack:
                        for pred in self.graph.predecessors(original_node):
                            vvar = self._follow_one_path_backward(
                                self.graph,
                                pred,
                                partial(
                                    self._stack_predicate,
                                    stack_offset=stmt.dst.stack_offset,
                                    stackvar_size=stmt.dst.size,
                                ),
                            )
                            src_and_vvars.append(((pred.addr, pred.idx), vvar))
                    else:
                        raise NotImplementedError

                    phi_var = Phi(stmt.src.idx, stmt.src.bits, src_and_vvars=src_and_vvars)
                    new_stmt = Assignment(stmt.idx, stmt.dst, phi_var, **stmt.tags)
                    new_stmts.append(new_stmt)
                node = node.copy(statements=new_stmts)
                self.out_blocks[node_key] = node

    @staticmethod
    def _follow_one_path_backward(graph: networkx.DiGraph, src, predicate: Callable) -> Any:
        visited = set()
        return_value = None
        the_node = src
        while the_node not in visited:
            visited.add(the_node)
            stop, return_value = predicate(the_node)
            if stop:
                break
            # keep going
            more_preds = list(graph.predecessors(the_node))
            if len(more_preds) != 1:
                # no longer a single path back
                break
            the_node = more_preds[0]
        return return_value
