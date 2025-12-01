from __future__ import annotations
from typing import Any
from collections.abc import Callable
from functools import partial
import logging

import networkx

import angr.ailment as ailment
from angr.ailment import Block
from angr.ailment.expression import Phi, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, Label, Statement

from angr.code_location import CodeLocation
from angr.analyses import ForwardAnalysis
from angr.analyses.forward_analysis import FunctionGraphVisitor
from angr.utils.ail import is_head_controlled_loop_block, extract_partial_expr
from angr.utils.ssa import get_reg_offset_base_and_size, is_phi_assignment
from .rewriting_engine import SimEngineSSARewriting, DefExprType, AT
from .rewriting_state import RewritingState

l = logging.getLogger(__name__)


class RewritingAnalysis(ForwardAnalysis[RewritingState, ailment.Block, object, object]):
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
        stackvar_locs: dict[int, set[int]],
        rewrite_tmps: bool,
        ail_manager,
        func_args: set[VirtualVariable],
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
        self._rewrite_tmps = rewrite_tmps
        self._ail_manager = ail_manager
        self._func_args = func_args
        self._engine_ail = SimEngineSSARewriting(
            self.project,
            sp_tracker=sp_tracker,
            bp_as_gpr=bp_as_gpr,
            udef_to_phiid=self._udef_to_phiid,
            phiid_to_loc=self._phiid_to_loc,
            stackvar_locs=self._stackvar_locs,
            rewrite_tmps=self._rewrite_tmps,
            ail_manager=ail_manager,
            vvar_id_start=vvar_id_start,
        )

        self._visited_blocks: set[Any] = set()
        self.out_blocks = {}
        self.out_states = {}
        # loop_states stores states at the beginning of a loop block *after a loop iteration*, where the block is the
        # following:
        #    0x4036df | t4 = (rcx<8> == 0x0<64>)
        #    0x4036df | if (t4) { Goto 0x4036e2<64> } else { Goto 0x4036df<64> }
        #    0x4036df | STORE(addr=t3, data=t2, size=8, endness=Iend_LE, guard=None)
        #    0x4036df | rdi<8> = t8
        #
        self.head_controlled_loop_outstates = {}

        self._analyze()

        self.def_to_vvid: dict[tuple[int, int | None, int, DefExprType, AT], int] = self._engine_ail.def_to_vvid
        # during SSA conversion, we create secondary stack variables because they overlap and are larger than the
        # actual stack variables. these secondary stack variables can be safely eliminated during dead assignment
        # elimination if not used by anything else.
        self.secondary_stackvars: set[int] = self._engine_ail.secondary_stackvars
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
                        ins_addr=node.addr,
                    )
                    phi_dst = VirtualVariable(
                        self._ail_manager.next_atom(),
                        self._engine_ail.next_vvar_id(),
                        reg_bits,
                        VirtualVariableCategory.REGISTER,
                        oident=reg_offset,
                        ins_addr=node.addr,
                    )

                case "stack":
                    _, stack_offset, stack_size = udef

                    phi_var = Phi(
                        self._ail_manager.next_atom(),
                        stack_size * self.project.arch.byte_width,
                        src_and_vvars=[],  # back patch later
                        ins_addr=node.addr,
                    )
                    phi_dst = VirtualVariable(
                        self._ail_manager.next_atom(),
                        self._engine_ail.next_vvar_id(),
                        stack_size * self.project.arch.byte_width,
                        VirtualVariableCategory.STACK,
                        oident=stack_offset,
                        ins_addr=node.addr,
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

    def _reg_predicate(self, node_: Block, *, reg_offset: int, reg_size: int) -> tuple[bool, Any]:
        out_state: RewritingState = (
            self.head_controlled_loop_outstates[(node_.addr, node_.idx)]
            if is_head_controlled_loop_block(node_) and (node_.addr, node_.idx) in self.head_controlled_loop_outstates
            else self.out_states[(node_.addr, node_.idx)]
        )
        if reg_offset in out_state.registers and reg_size in out_state.registers[reg_offset]:
            # we found a perfect hit
            existing_var = out_state.registers[reg_offset][reg_size]
            if existing_var is None:
                # the vvar is not set. it should never be referenced
                return True, None
            vvar = existing_var.copy()
            vvar.idx = self._ail_manager.next_atom()
            return True, vvar

        # try to see if any register writes overlap with the requested one
        # note that we only support full overlaps for now...
        for off in out_state.registers:
            if reg_offset + reg_size <= off or (
                out_state.registers[off] and reg_offset > off + max(out_state.registers[off])
            ):
                continue
            for sz in sorted(out_state.registers[off], reverse=True):
                if reg_offset >= off and reg_offset + reg_size <= off + sz:
                    existing_var = out_state.registers[off][sz]
                    if existing_var is None:
                        # the vvar is not set.
                        return True, None

                    # return the base vvar
                    base_vvar = existing_var.copy()
                    base_vvar.idx = self._ail_manager.next_atom()
                    return True, base_vvar
        return False, None

    def _stack_predicate(self, node_: Block, *, stack_offset: int, stackvar_size: int) -> tuple[bool, Any]:
        out_state: RewritingState = (
            self.head_controlled_loop_outstates[(node_.addr, node_.idx)]
            if is_head_controlled_loop_block(node_)
            else self.out_states[(node_.addr, node_.idx)]
        )
        if stack_offset in out_state.stackvars and stackvar_size in out_state.stackvars[stack_offset]:
            existing_var = out_state.stackvars[stack_offset][stackvar_size]
            if existing_var is None:
                # the vvar is not set. it should never be referenced
                return True, None
            vvar = existing_var.copy()
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
        state = RewritingState(
            CodeLocation(node.addr, stmt_idx=0, ins_addr=node.addr, block_idx=node.idx),
            self.project.arch,
            self._function,
            node,
        )
        # update state with function arguments
        for func_arg in self._func_args:
            if func_arg.parameter_category == VirtualVariableCategory.REGISTER:
                reg_offset, reg_size = func_arg.parameter_reg_offset, func_arg.size
                assert reg_offset is not None and reg_size is not None
                state.registers[reg_offset][reg_size] = func_arg
            elif func_arg.parameter_category == VirtualVariableCategory.STACK:
                parameter_stack_offset: int = func_arg.oident[1]  # type: ignore
                assert parameter_stack_offset is not None and func_arg.size is not None
                state.stackvars[parameter_stack_offset][func_arg.size] = func_arg
        return state

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
        # get the output state (which is the input state for the successor node)
        # if head_controlled_loop_outstate is set, then it is the output state of the successor node; in this case, the
        # input state for the head-controlled loop block itself is out.state.
        # otherwise (if head_controlled_loop_outstate is not set), engine.state is the input state of the successor
        # node.
        if engine.head_controlled_loop_outstate is None:
            # this is a normal block
            out_state = state
        else:
            # this is a head-controlled loop block
            out_state = engine.head_controlled_loop_outstate
            self.head_controlled_loop_outstates[block_key] = state
        self.out_states[block_key] = out_state
        # the final block is always in state
        out_block = state.out_block

        if out_block is not None:
            assert out_block.addr == block.addr

            if self.out_blocks.get(block_key, None) == out_block:
                return True, out_state
            self.out_blocks[block_key] = out_block
            out_state.out_block = None
            return True, out_state

        return True, out_state

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
                phi_stmts = []
                phi_extraction_stmts = []
                other_stmts = []
                for stmt in node.statements:
                    if (
                        isinstance(stmt, Assignment)
                        and isinstance(stmt.dst, VirtualVariable)
                        and isinstance(stmt.src, Phi)
                        and len(stmt.src.src_and_vvars) > 0
                    ):
                        # avoid re-assignment
                        phi_stmts.append(stmt)
                        continue
                    if not is_phi_assignment(stmt):
                        other_stmts.append(stmt)
                        continue

                    src_and_vvars = []
                    if stmt.dst.was_reg:
                        perfect_matches = []
                        for pred in self.graph.predecessors(original_node):
                            vvar = self._follow_one_path_backward(
                                self.graph,
                                pred,
                                partial(self._reg_predicate, reg_offset=stmt.dst.reg_offset, reg_size=stmt.dst.size),
                            )
                            src_and_vvars.append(((pred.addr, pred.idx), vvar))
                            perfect_matches.append(
                                (vvar.reg_offset == stmt.dst.reg_offset and vvar.size == stmt.dst.size)
                                if vvar is not None
                                else True
                            )
                        if all(perfect_matches):
                            phi_var = Phi(stmt.src.idx, stmt.src.bits, src_and_vvars=src_and_vvars)
                            phi_stmt = Assignment(stmt.idx, stmt.dst, phi_var, **stmt.tags)
                            phi_stmts.append(phi_stmt)
                        else:
                            # different sizes of vvars found; we need to resort to the base register and extract the
                            # requested register out of the base register
                            # here we rely on the fact that the larger register vvar must be created in this block when
                            # the smaller register has been created
                            base_reg_offset, max_reg_size = get_reg_offset_base_and_size(
                                stmt.dst.reg_offset, self.project.arch, size=stmt.dst.size
                            )
                            # find the phi assignment statement of the larger base register
                            base_vvar = self._find_phi_vvar_for_reg(base_reg_offset, max_reg_size, node.statements)
                            assert base_vvar is not None
                            partial_base_vvar = extract_partial_expr(
                                base_vvar,
                                stmt.dst.reg_offset - base_reg_offset,
                                stmt.dst.size,
                                self._ail_manager,
                                byte_width=self.project.arch.byte_width,
                            )
                            new_stmt = Assignment(stmt.idx, stmt.dst, partial_base_vvar, **base_vvar.tags)
                            phi_extraction_stmts.append(new_stmt)

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

                        phi_var = Phi(stmt.src.idx, stmt.src.bits, src_and_vvars=src_and_vvars)
                        phi_stmt = Assignment(stmt.idx, stmt.dst, phi_var, **stmt.tags)
                        phi_stmts.append(phi_stmt)
                    else:
                        raise NotImplementedError

                node = node.copy(statements=phi_stmts + phi_extraction_stmts + other_stmts)
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

    @staticmethod
    def _find_phi_vvar_for_reg(reg_offset: int, reg_size: int, stmts: list[Statement]) -> VirtualVariable | None:
        for stmt in stmts:
            if (
                is_phi_assignment(stmt)
                and isinstance(stmt.dst, VirtualVariable)
                and stmt.dst.was_reg
                and stmt.dst.reg_offset == reg_offset
                and stmt.dst.size == reg_size
            ):
                return stmt.dst
        return None
