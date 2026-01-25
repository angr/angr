from __future__ import annotations
from itertools import chain
from typing import TYPE_CHECKING, Any, TypeVar
from collections.abc import MutableMapping
from collections.abc import Callable
from functools import partial
import logging

import networkx

import angr.ailment as ailment
from angr.ailment import Block
from angr.ailment.expression import Phi, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, Label, Statement

from angr.analyses.decompiler.ailgraph_walker import traverse_in_order
from angr.code_location import AILCodeLocation
from angr.knowledge_plugins.functions.function import Function
from angr.utils.ail import is_head_controlled_loop_block, extract_partial_expr
from angr.utils.ssa import get_reg_offset_base_and_size, is_phi_assignment
from .rewriting_engine import SimEngineSSARewriting
from .rewriting_state import RewritingState

if TYPE_CHECKING:
    from angr.analyses.decompiler.ssailification.ssailification import Def, UDef
    from angr.project import Project

l = logging.getLogger(__name__)
T = TypeVar("T")
U = TypeVar("U")


class RewritingAnalysis:
    """
    RewritingAnalysis traverses the AIL graph, inserts phi nodes, and rewrites all expression uses to virtual variables
    when necessary.
    """

    def __init__(
        self,
        project: Project,
        func: Function,
        ail_graph: networkx.DiGraph[Block],
        udef_to_phiid: dict[tuple, set[int]],
        phiid_to_loc: dict[int, tuple[int, int | None]],
        rewrite_tmps: bool,
        ail_manager,
        func_args: set[VirtualVariable],
        def_to_udef: MutableMapping[Def, UDef],
        extern_defs: set[UDef],
        incomplete_defs: set[Def],
        vvar_id_start: int = 0,
        stackvars: bool = False,
    ):
        self.project = project
        self._function = func

        self._graph = ail_graph
        self._udef_to_phiid = udef_to_phiid
        self._phiid_to_loc = phiid_to_loc
        self._rewrite_tmps = rewrite_tmps
        self._ail_manager = ail_manager
        self._func_args = func_args
        self._extern_defs = extern_defs
        self._engine_ail = SimEngineSSARewriting(
            self.project,
            rewrite_tmps=self._rewrite_tmps,
            incomplete_defs=incomplete_defs,
            ail_manager=ail_manager,
            vvar_id_start=vvar_id_start,
            def_to_udef=def_to_udef,
            stackvars=stackvars,
        )

        self._pending_states: dict[ailment.Block, RewritingState] = {}
        self.out_blocks = {}
        self.out_states = {}
        self.resized_func_args: dict[VirtualVariable, VirtualVariable] = {}
        # loop_states stores states at the beginning of a loop block *after a loop iteration*, where the block is the
        # following:
        #    0x4036df | t4 = (rcx<8> == 0x0<64>)
        #    0x4036df | if (t4) { Goto 0x4036e2<64> } else { Goto 0x4036df<64> }
        #    0x4036df | STORE(addr=t3, data=t2, size=8, endness=Iend_LE, guard=None)
        #    0x4036df | rdi<8> = t8
        #
        self.head_controlled_loop_outstates = {}

        self._analyze()

        self.out_graph = self._make_new_graph(ail_graph)

    def _analyze(self):
        self._pre_analysis()
        entry_block = next((n for n in self._graph if n.addr == self._function.addr), None)
        entry_blocks = {n for n in self._graph if not self._graph.pred[n]}
        if entry_block is not None:
            entry_blocks.add(entry_block)
        traverse_in_order(self._graph, sorted(entry_blocks), self._run_on_node)
        self._post_analysis()

    @property
    def max_vvar_id(self) -> int | None:
        return self._engine_ail.current_vvar_id

    def _make_new_graph(self, old_graph: networkx.DiGraph[ailment.Block]) -> networkx.DiGraph[ailment.Block]:
        new_graph: networkx.DiGraph[ailment.Block] = networkx.DiGraph()
        for node in old_graph:
            new_graph.add_node(self.out_blocks.get((node.addr, node.idx), node))

        for src, dst, data in old_graph.edges(data=True):
            new_graph.add_edge(
                self.out_blocks.get((src.addr, src.idx), src),
                self.out_blocks.get((dst.addr, dst.idx), dst),
                **data,
            )

        return new_graph

    def create_phi_statements(self, node, phiid_to_udef: dict, phi_ids: list[int]) -> list[Assignment]:
        phi_stmts = []
        seen: set[tuple[str, int]] = set()
        for phi_id in phi_ids:
            udef = phiid_to_udef[phi_id]
            category = udef[0]
            for suboffset in range(udef[1], udef[1] + udef[2]):
                key = (udef[0], suboffset)
                assert key not in seen, "Overlapping phis in a single block"
                seen.add(key)

            match category:
                case "reg":
                    _, reg_offset, reg_bytes = udef

                    phi_var = Phi(
                        self._ail_manager.next_atom(),
                        reg_bytes * self.project.arch.byte_width,
                        src_and_vvars=[],  # back patch later
                        ins_addr=node.addr,
                    )
                    phi_dst = VirtualVariable(
                        self._ail_manager.next_atom(),
                        self._engine_ail._current_vvar_id,
                        reg_bytes * self.project.arch.byte_width,
                        VirtualVariableCategory.REGISTER,
                        oident=reg_offset,
                        ins_addr=node.addr,
                    )
                    self._engine_ail._current_vvar_id += 1

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
                        self._engine_ail._current_vvar_id,
                        stack_size * self.project.arch.byte_width,
                        VirtualVariableCategory.STACK,
                        oident=stack_offset,
                        ins_addr=node.addr,
                    )
                    self._engine_ail._current_vvar_id += 1
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
        if reg_offset in out_state.registers:
            # we found a perfect hit
            existing_var = out_state.registers[reg_offset]
            if existing_var is None:
                # the vvar is not set. it should never be referenced
                return True, None
            vvar = existing_var.deep_copy(self._ail_manager)
            return True, vvar

        return False, None

    def _stack_predicate(self, node_: Block, *, stack_offset: int, stackvar_size: int) -> tuple[bool, Any]:
        out_state: RewritingState = (
            self.head_controlled_loop_outstates[(node_.addr, node_.idx)]
            if is_head_controlled_loop_block(node_)
            else self.out_states[(node_.addr, node_.idx)]
        )
        if stack_offset in out_state.stackvars:
            existing_var = out_state.stackvars[stack_offset]
            if existing_var is None:
                # the vvar is not set. it should never be referenced
                return True, None
            vvar = existing_var.deep_copy(self._ail_manager)
            return True, vvar
        return False, None

    #
    # Main analysis routines
    #

    def _pre_analysis(self):
        for node in self._graph:
            phi_stmts = self.create_phi_statements(node, self._udef_to_phiid, self._phiid_to_loc)
            if phi_stmts:
                self.insert_phi_statements(node, phi_stmts)

    def _initial_abstract_state(self, node) -> RewritingState:
        func_args_map = {}
        # we may identify args that are not identified by Traversal. make sure these still get used
        unused_func_args = set(self._func_args)
        for arg_vvar in self._func_args:
            offset = (
                arg_vvar.parameter_reg_offset
                if arg_vvar.parameter_category == VirtualVariableCategory.REGISTER
                else arg_vvar.parameter_stack_offset
            )
            assert offset is not None
            for suboffset in range(offset, offset + arg_vvar.size):
                func_args_map[(arg_vvar.parameter_category, suboffset)] = arg_vvar

        state = RewritingState(
            AILCodeLocation(node.addr, node.idx, 0, node.addr),
            self.project.arch,
            self._function,
            node,
        )
        more_args: list[VirtualVariable] = []
        for kind, offset, size in sorted(self._extern_defs):
            category = VirtualVariableCategory.REGISTER if kind == "reg" else VirtualVariableCategory.STACK
            if (arg_vvar := func_args_map.get((category, offset), None)) is not None:
                unused_func_args.discard(arg_vvar)
                if arg_vvar.size == size:
                    vvar = arg_vvar
                elif arg_vvar in self.resized_func_args:
                    vvar = self.resized_func_args[arg_vvar]
                else:
                    # rewriting the size the arg
                    vvar = VirtualVariable(
                        arg_vvar.idx,
                        arg_vvar.varid,
                        size * 8,
                        VirtualVariableCategory.PARAMETER,
                        (category, offset),
                        **arg_vvar.tags,
                    )
                    self.resized_func_args[arg_vvar] = vvar
            else:
                varid = self._engine_ail._current_vvar_id
                self._engine_ail._current_vvar_id += 1
                vvar = VirtualVariable(self._engine_ail.ail_manager.next_atom(), varid, size * 8, category, offset)
            more_args.append(vvar)

        # update state with function arguments
        for func_arg in chain(more_args, unused_func_args):
            if func_arg.category == VirtualVariableCategory.REGISTER:
                reg_offset = func_arg.reg_offset
                for suboff in range(reg_offset, reg_offset + func_arg.size):
                    state.registers[suboff] = func_arg
            elif func_arg.category == VirtualVariableCategory.STACK:
                stack_offset = func_arg.stack_offset
                for suboff in range(stack_offset, stack_offset + func_arg.size):
                    state.stackvars[suboff] = func_arg
            elif func_arg.parameter_category == VirtualVariableCategory.REGISTER:
                reg_offset = func_arg.parameter_reg_offset
                assert reg_offset is not None
                for suboff in range(reg_offset, reg_offset + func_arg.size):
                    state.registers[suboff] = func_arg
            elif func_arg.parameter_category == VirtualVariableCategory.STACK:
                stack_offset = func_arg.parameter_stack_offset
                assert stack_offset is not None
                for suboff in range(stack_offset, stack_offset + func_arg.size):
                    state.stackvars[suboff] = func_arg

        return state

    def _run_on_node(self, node: Block):
        """

        :param node:    The current node.
        :param state:   The analysis state.
        :return:        A tuple: (any changes occur, successor state)
        """

        state = self._pending_states.get(node, None)
        state = self._initial_abstract_state(node) if state is None else state.copy()
        block_key = (node.addr, node.idx)

        state.loc = AILCodeLocation(node.addr, node.idx, 0, node.addr)

        self._engine_ail.process(
            state,
            block=node,
        )

        if self._engine_ail.hclb_side_exit_state is not None:
            self.head_controlled_loop_outstates[block_key] = state
            state = self._engine_ail.hclb_side_exit_state
            self._engine_ail.hclb_side_exit_state = None
        self.out_states[block_key] = state
        self.out_blocks[block_key] = self._engine_ail.out_block
        for succ in self._graph.succ[node]:
            self._pending_states[succ] = state

    def _post_analysis(self):
        # update phi nodes
        for original_node in self._graph:
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
                        for pred in self._graph.predecessors(original_node):
                            vvar = self._follow_one_path_backward(
                                self._graph,
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
                        for pred in self._graph.predecessors(original_node):
                            vvar = self._follow_one_path_backward(
                                self._graph,
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
    def _follow_one_path_backward(
        graph: networkx.DiGraph[T], src: T, predicate: Callable[[T], tuple[bool, U]]
    ) -> U | None:
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
