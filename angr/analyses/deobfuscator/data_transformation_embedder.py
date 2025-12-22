from __future__ import annotations
from typing import Any, TYPE_CHECKING
import logging

import networkx

import claripy
from angr import sim_options
from angr.ailment import Block
from angr.ailment.statement import Assignment, Call
from angr.ailment.expression import VirtualVariable, VirtualVariableCategory, Const, UnaryOp
from angr.sim_type import SimTypeBottom, SimTypePointer, SimTypeChar
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr.analyses import Analysis
from angr.analyses.purity import AILPurityAnalysis, AILPurityResultType
from angr.analyses.decompiler.clinic import ClinicStage
from angr.ail_callable import AILCallable
from angr.analyses.decompiler.utils import call_stmts_in_graph
from angr.knowledge_plugins.cfg.memory_data import MemoryDataSort
from angr.calling_conventions import PointerWrapper
from .scope_ops_analyzer import ScopeOpsAnalyzer

if TYPE_CHECKING:
    from angr.knowledge_plugins.functions import Function
    from angr.analyses.decompiler.clinic import Clinic
    from angr.analyses.decompiler.structured_codegen.c import CFunction


_l = logging.getLogger(__name__)


class DataTransformationEmbedder(Analysis):
    """
    An analysis that finds potentially inlined static data transformation logic and embeds the transformed data in
    decompilation whenever possible.

    Some current limitations:
    - We assume the data transformation logic is inlined completely within a single function.
    """

    def __init__(
        self,
        func: Function,
        clinic: Clinic,
        cfunc: CFunction | None,
        outlining_max_args: int = 1,
        preset: str = "malware",
    ):
        self.func = func
        self.clinic = clinic
        self.cfunc = cfunc
        self._outlining_max_args = outlining_max_args
        self._preset = preset

        # intermediate state
        self._outliner_vvar_id = 0xD000
        self._outliner_block_addr = 0xABCD0000

        self.result = []

        self._analyze()

    def _analyze(self):

        _l.debug("Look for partially evaluatable calls that are likely data transformation functions.")
        r = self._analyze_concrete_calls_to_data_transformation_functions()
        if r:
            return

        encryption_scope_addrs = self._find_encryption_scope_addrs()
        _l.debug("Found %d encryption routine block candidates.", len(encryption_scope_addrs))
        for enc_addr in encryption_scope_addrs:
            r = self._analyze_one_inlined_encryption_scope(enc_addr)
            _l.debug("Inlining transformation scope at block %#x: %s", enc_addr, "Succeeded" if r else "Failed")
            if r:
                break

    #
    # Static calls to pure data transformation functions
    #

    def _analyze_concrete_calls_to_data_transformation_functions(self) -> bool:
        candidates = self._find_constant_data_transformation_call_candidates()
        _l.debug("Found %d constant data transformation call candidates.", len(candidates))
        if not candidates:
            return False

        r = False
        for candidate in candidates:
            ret = self._apply_data_transformation_candidate(candidate)
            _l.debug(
                "Apply data transformation candidate at callsite %#x: %s",
                candidate["callsite_insaddr"],
                "Succeeded" if ret else "Failed",
            )
            r |= ret
        return r

    def _find_constant_data_transformation_call_candidates(self):
        cfg = self.project.kb.cfgs.get_most_accurate()

        # we use .graph instead of .cc_graph for better constant propagation results
        # TODO: it really shouldn't have been the case; debug it later
        call_stmts, call_exprs = call_stmts_in_graph(self.clinic.graph)

        str_trans = []

        for loc, call in call_stmts + call_exprs:
            if not isinstance(call.target, Const):
                continue
            callee = self.project.kb.functions.get_by_addr(call.target.value_int)
            if callee.is_plt or callee.is_simprocedure or callee.is_alignment:
                continue

            # what arguments are passed to the callee?
            args = call.args
            if not args:
                continue

            # one of the args must be a constant bytestring
            has_constant_string_arg = False
            arg_sort = []
            for arg in args:
                if isinstance(arg, Const):
                    if arg.tags.get("custom_string", False):
                        has_constant_string_arg = True
                    if arg.value_int in cfg.memory_data:
                        md = cfg.memory_data[arg.value_int]
                        if md.sort in {MemoryDataSort.String, MemoryDataSort.Unknown}:
                            has_constant_string_arg = True
                    arg_sort.append("const")
                elif isinstance(arg, UnaryOp) and arg.op == "Reference" and isinstance(arg.operand, VirtualVariable):
                    arg_sort.append("varptr")
                else:
                    arg_sort.append("unknown")

            if not has_constant_string_arg:
                continue

            # decompile the callee and test it
            callee_dec = self.project.analyses.Decompiler(callee, preset="malware")
            try:
                purity = self.project.analyses[AILPurityAnalysis].prep()(callee_dec.clinic)
            except Exception:  # pylint:disable=broad-exception-caught
                continue

            # checks:
            # - the callee should not update any global memory
            # - all const args should be read-only
            # - all pointer args should be write-only
            failed = False
            for source, use in purity.result.uses.items():
                if source.function_arg is not None:
                    # function args
                    if use.ptr_store and use.ptr_load:
                        # both read and write; unsupported for now
                        failed = True
                        break
                    if use.ptr_store and arg_sort[source.function_arg] != "varptr":
                        # write-only use is not a pointer argument
                        failed = True
                        break
                    if use.ptr_load and arg_sort[source.function_arg] != "const":
                        # read-only use is not a constant argument
                        failed = True
                        break
                elif source.constant_value is not None:
                    # global reads or writes?
                    if use.ptr_store:
                        # writes to global memory; unsupported for now
                        failed = True
                        break

            if failed:
                continue

            d = {
                "args": args,
                "arg_sort": arg_sort,
                "callee": callee.addr,
                "callsite_insaddr": call.tags["ins_addr"],
                "callsite_block_loc": loc[0],
                "callsite_stmt_idx": loc[1],
                "purity": purity.result,
            }
            str_trans.append(d)

        return str_trans

    def _apply_data_transformation_candidate(self, trans_desc: dict) -> bool:
        callee_addr = trans_desc["callee"]
        callsite_insaddr = trans_desc["callsite_insaddr"]
        callsite_block_loc = trans_desc["callsite_block_loc"]
        callsite_stmt_idx = trans_desc["callsite_stmt_idx"]

        # do we support the statement?
        nodes_dict = {(b.addr, b.idx): b for b in self.clinic.cc_graph}
        block = nodes_dict[callsite_block_loc]

        # FIXME: We are only doing this because we were using clinic.graph instead of clinic.cc_graph above
        for stmt_idx, call_stmt in enumerate(block.statements):
            call_stmt = block.statements[stmt_idx]
            if isinstance(call_stmt, Call):
                dst = None
                callsite_stmt_idx = stmt_idx
                break
            if isinstance(call_stmt, Assignment) and isinstance(call_stmt.src, Call):
                dst = call_stmt.dst
                callsite_stmt_idx = stmt_idx
                break
        else:
            # unsupported
            return False

        # decompile it to identify the prototype (in case we don't already have it)
        callee_func = self.project.kb.functions[callee_addr]
        _callee_dec = self.project.analyses.Decompiler(callee_func, preset="malware")

        call = self.project.factory.callable(
            trans_desc["callee"],
            concrete_only=True,
            prototype=callee_func.prototype,
            add_options=sim_options.unicorn
            | {sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY, sim_options.ZERO_FILL_UNCONSTRAINED_REGISTERS},
        )

        # prepare the arguments
        concrete_args = []
        starting_ptr = 0x9_000000
        current_ptr = starting_ptr
        for arg_idx, arg_sort in enumerate(trans_desc["arg_sort"]):
            arg = trans_desc["args"][arg_idx]
            if arg_sort == "const":
                if isinstance(arg, Const):
                    if arg.tags.get("custom_string", False):
                        s = self.project.kb.custom_strings[arg.value_int]
                        # FIXME: we force the first argument to be a uint8_t* here
                        callee_func.prototype.args = (
                            SimTypePointer(SimTypeChar()).with_arch(self.project.arch),
                            *callee_func.prototype.args[1:],
                        )

                        concrete_args.append(PointerWrapper(s, buffer=True))
                    else:
                        concrete_args.append(claripy.BVV(arg.value_int, arg.bits))
                else:
                    raise NotImplementedError
            elif arg_sort == "varptr":
                concrete_args.append(claripy.BVV(current_ptr, self.project.arch.bits))
                current_ptr += 0x100000
            else:
                return False

        try:
            ret = call(*concrete_args)
            final_state = call.result_state
        except Exception:  # pylint:disable=broad-exception-caught
            return False

        # execution succeeded! extract the result and then embed it into the block
        new_stmts = []

        returnty = callee_func.prototype.returnty
        if not isinstance(returnty, SimTypeBottom):
            # it returns something
            if dst is None:
                # huh?
                return False
            if isinstance(returnty, SimTypePointer) or self._has_pointer_retval(trans_desc["purity"].ret_vals):
                # TODO: Figure out the size of the buffer of the returned pointer
                buf_addr = ret.concrete_value
                data = final_state.solver.eval(final_state.memory.load(buf_addr, 0x100000), cast_to=bytes).rstrip(
                    b"\x00"
                )
                buf_size = len(data)
                # TODO: Ensure the source of the return value is from malloc
                alloc_expr = Call(
                    None,
                    "malloc",
                    args=[Const(None, None, buf_size, self.project.arch.bits)],
                    bits=self.project.arch.bits,
                    ins_addr=callsite_insaddr,
                )
                alloc_stmt = Assignment(None, dst, alloc_expr, ins_addr=callsite_insaddr)

                str_id = self.project.kb.custom_strings.allocate(data)
                src_expr = Const(
                    None, None, str_id, self.project.arch.bits, ins_addr=callsite_insaddr, custom_string=True
                )
                assign_stmt = Call(
                    None,
                    "memcpy",
                    args=[dst, src_expr, Const(None, None, len(data), self.project.arch.bits)],
                    ins_addr=callsite_insaddr,
                )
                new_stmts += [alloc_stmt, assign_stmt]

        for arg_idx, arg_sort in enumerate(trans_desc["arg_sort"]):
            arg = trans_desc["args"][arg_idx]
            concrete_arg = concrete_args[arg_idx]
            if arg_sort == "varptr":
                if isinstance(arg, UnaryOp) and arg.op == "Reference" and isinstance(arg.operand, VirtualVariable):
                    # write back the buffer
                    value = final_state.memory.load(
                        concrete_arg, arg.operand.size, endness=self.project.arch.memory_endness
                    )
                    if value.symbolic:
                        return False
                    value_expr = Const(None, None, value.concrete_value, arg.operand.bits)
                    alloc_stmt = Assignment(
                        None,
                        arg.operand,
                        value_expr,
                        ins_addr=callsite_insaddr,
                    )
                    new_stmts.append(alloc_stmt)
                else:
                    return False

        # replace the old call statement with new statements
        stmts = block.statements[::]
        new_block = Block(
            block.addr,
            block.original_size,
            statements=stmts[:callsite_stmt_idx] + new_stmts + stmts[callsite_stmt_idx + 1 :],
            idx=block.idx,
        )
        new_graph = self._build_graph_with_replaced_block({block}, new_block)
        if new_graph is not None:
            self.result.append(new_graph)
            return True

        return False

    #
    # Inlined data transformation loops
    #

    def _analyze_one_inlined_encryption_scope(self, enc_block_addr: int) -> bool:
        nodes_dict = {(b.addr, b.idx): b for b in self.clinic.cc_graph}

        block = nodes_dict[(enc_block_addr, None)]
        outliner = None
        dec_outlined = None
        start = None

        for _step in range(6):
            _l.debug("Attempt %d: Attempting outlining at block %#x, ", _step + 1, block.addr)
            r, o, d = self._attempt_outlining((block.addr, block.idx))

            if r and not self._has_reg_vvars(o.child_funcargs) and len(o.child_funcargs) <= self._outlining_max_args:
                _l.debug(
                    "Outlining at block %#x produced a function without too many arguments (%d).",
                    block.addr,
                    len(o.child_funcargs),
                )
                _l.debug("%s", d.codegen.text)

                outliner = o
                dec_outlined = d
                start = block.addr, block.idx
                break

            # has arguments - can't partial evaluate
            _l.debug("Outlining at block %#x produced too many arguments, backtracking...", block.addr)

            preds = [
                pred
                for pred in self.clinic.cc_graph.predecessors(block)
                if pred is not block and not networkx.has_path(self.clinic.cc_graph, block, pred)
            ]
            if len(preds) != 1:
                break
            block = preds[0]

        if outliner is None or dec_outlined is None or start is None:
            return False

        r = False

        # run loop analysis
        _l.debug("Running loop analysis on outlined function...")
        loop_analysis = self.project.analyses.LoopAnalysis(dec_outlined.codegen.cfunc)

        for _loop_key, loop_meta in loop_analysis.result.items():
            if loop_meta.get("fixed_iterations", False) and loop_meta.get("max_iterations", None) > 1:
                loop_blocks = {nodes_dict[(loop_block_addr, None)] for loop_block_addr in loop_meta["block_addrs"]}
                succs = set()
                for lb in loop_blocks:
                    for succ in self.clinic.cc_graph.successors(lb):
                        if succ not in loop_blocks:
                            succs.add(succ)
                if len(succs) != 1:
                    continue
                succ = next(iter(succs))
                loop_header_addr: int = min(loop_meta["block_addrs"])
                frontier_blocks = {succ}
                frontier = [(frontier_block.addr, frontier_block.idx) for frontier_block in frontier_blocks]

                r, o, d = self._attempt_outlining(start, frontier=frontier)
                if not r:
                    continue

                # get frontier variables and their assignments
                frontier_var_assignments = self._frontier_var_initial_assignments(o.frontier_vars, d.clinic.cc_graph)
                frontier_var_values = {}
                known_buffers = {}

                # can we partially evaluate this outlined function?
                can_pe, _result = self._can_partially_evaluate(d.clinic)
                if can_pe:
                    # looks like we can partially evaluate the loop and embed the results
                    def lifter(_addr: int):
                        return d.clinic  # noqa:B023

                    # very much a hack for now
                    d.clinic.arg_vvars = {}

                    call = AILCallable(
                        self.project,
                        start,
                        lifter,
                        boundary=set(frontier),
                        add_options={
                            sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                            sim_options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                        },
                    )
                    try:
                        call()
                    except Exception:  # pylint:disable=broad-exception-caught
                        continue

                    # update frontier variable assignments with values post-execution if needed
                    new_vvars_list = call.result_state.globals["vvars"].get(start, [])
                    if not new_vvars_list or len(new_vvars_list) > 1:
                        # no vvars exist or there are more than one
                        continue

                    new_vvars = new_vvars_list[0]
                    bad = False
                    for vvar_id, (_, initial_assignment) in list(frontier_var_assignments.items()):
                        if isinstance(initial_assignment, Call) and vvar_id in new_vvars:
                            # TODO: Check if it's a supported call
                            frontier_var_values[vvar_id] = new_vvars[vvar_id]
                            if isinstance(initial_assignment.args[-1], Const):
                                heap_buffer_size = initial_assignment.args[-1].value_int
                                data = call.result_state.solver.eval(
                                    call.result_state.memory.load(
                                        new_vvars[vvar_id].concrete_value, heap_buffer_size, endness="Iend_BE"
                                    ),
                                    cast_to=bytes,
                                )
                                known_buffers[frontier_var_values[vvar_id].concrete_value] = data
                        elif isinstance(initial_assignment, Const):
                            # sanity check
                            if vvar_id in new_vvars:
                                new_value = new_vvars[vvar_id]
                                if new_value.concrete_value != initial_assignment.value:
                                    bad = True
                                    break
                                frontier_var_values[vvar_id] = new_value
                        elif vvar_id in new_vvars:
                            frontier_var_values[vvar_id] = new_vvars[vvar_id]

                    if bad:
                        continue

                    # generate a block that assigns these variables
                    new_block = self._create_block_setting_frontier_vars(
                        loop_header_addr, frontier_var_assignments, frontier_var_values, known_buffers
                    )
                    # replace the outlined blocks with the new block
                    new_graph = self._build_graph_with_replaced_block(loop_blocks, new_block)
                    if new_graph is not None:
                        self.result.append(new_graph)
                        r = True
                        break

        return r

    def _attempt_outlining(
        self, src_loc: tuple[int, int | None], frontier: list[tuple[int, int | None]] | None = None
    ) -> tuple[bool, Any, Any]:
        parent_graph = self.clinic.copy_graph(self.clinic.cc_graph)
        outliner = self.project.analyses.Outliner(
            self.func,
            parent_graph,
            src_loc=src_loc,
            frontier=frontier,
            vvar_id_start=self._outliner_vvar_id,
            block_addr_start=self._outliner_block_addr,
            min_step=2,
        )
        self._outliner_vvar_id = outliner.vvar_id_start
        self._outliner_block_addr = outliner.block_addr_start

        func_args = self._create_function_arguments(outliner.child_funcargs)

        dec_inner = self.project.analyses.Decompiler(
            outliner.child_func,
            preset="malware",
            clinic_graph=outliner.child_graph,
            clinic_arg_vvars=func_args,
            clinic_start_stage=ClinicStage.POST_CALLSITES,
            fail_fast=True,
        )
        # print(dec_inner.codegen.text)

        return True, outliner, dec_inner

    def _can_partially_evaluate(self, clinic: Clinic) -> tuple[bool, AILPurityResultType]:
        purity = self.project.analyses[AILPurityAnalysis].prep()(clinic)
        for source, use in purity.result.uses.items():
            if use.ptr_store and source.constant_value is not None:
                return False, purity.result
        return True, purity.result

    #
    # Utility methods
    #

    def _find_encryption_scope_addrs(self):
        if self.cfunc is None:
            return []
        analyzer = self.project.analyses[ScopeOpsAnalyzer].prep()(self.cfunc)
        return analyzer.crypto_scopes()

    @staticmethod
    def _create_function_arguments(child_funcargs):
        funcargs = {}
        for arg_idx, arg_vvar in enumerate(child_funcargs):
            if arg_vvar.was_parameter:
                if arg_vvar.parameter_category == VirtualVariableCategory.REGISTER:
                    simvar = SimRegisterVariable(
                        arg_vvar.reg_offset, arg_vvar.size, ident=f"arg_{arg_idx}", name=f"a{arg_idx}"
                    )
                elif arg_vvar.parameter_category == VirtualVariableCategory.STACK:
                    simvar = SimStackVariable(
                        arg_vvar.stack_offset, arg_vvar.size, ident=f"arg_{arg_idx}", name=f"a{arg_idx}"
                    )
                else:
                    raise NotImplementedError
            elif arg_vvar.was_reg:
                simvar = SimRegisterVariable(
                    arg_vvar.reg_offset, arg_vvar.size, ident=f"arg_{arg_idx}", name=f"a{arg_idx}"
                )
            elif arg_vvar.was_stack:
                simvar = SimStackVariable(
                    arg_vvar.stack_offset, arg_vvar.size, ident=f"arg_{arg_idx}", name=f"a{arg_idx}"
                )
            else:
                raise NotImplementedError
            funcargs[arg_vvar.varid] = arg_vvar, simvar

        return funcargs

    @staticmethod
    def _frontier_var_initial_assignments(frontier_varids: set[int], cc_graph: networkx.DiGraph):

        var_assignments = {}
        for block in cc_graph.nodes:
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and stmt.dst.varid in frontier_varids:
                    var_assignments[stmt.dst.varid] = (stmt.dst, stmt.src)

        return var_assignments

    @staticmethod
    def _has_pointer_retval(ret_vals: dict[int, Any]) -> bool:
        for retval_set in ret_vals.values():
            for retval in retval_set:
                if retval.callee_return is not None and retval.callee_return.name in {
                    "malloc",
                    "calloc",
                    "realloc",
                    "VirtualAlloc",
                    "VirtualAllocEx",
                }:
                    return True
        return False

    def _create_block_setting_frontier_vars(
        self, addr: int, var_assignments: dict, var_values: dict[int, claripy.Bits], known_buffers: dict[int, bytes]
    ) -> Block:
        stmts = []
        for vvar_id, v in var_values.items():
            old_vvar, old_assignment = var_assignments[vvar_id]
            if isinstance(old_assignment, Call):  # TODO: Ensure it's a buffer-allocating call
                assign_stmt = Assignment(None, old_vvar, old_assignment, ins_addr=addr)
                stmts.append(assign_stmt)
                buffer_addr = v.concrete_value
                str_id = self.project.kb.custom_strings.allocate(known_buffers[buffer_addr])
                src_expr = Const(None, None, str_id, v.size(), ins_addr=addr, custom_string=True)
                size_expr = Const(None, None, len(known_buffers[buffer_addr]), v.size(), ins_addr=addr)
                memcpy_stmt = Call(None, "memcpy", args=[old_vvar, src_expr, size_expr], ins_addr=addr)
                stmts.append(memcpy_stmt)
            else:
                const_expr = Const(None, None, v.concrete_value, v.size(), ins_addr=addr)
                assign_stmt = Assignment(None, old_vvar, const_expr, ins_addr=addr)
                stmts.append(assign_stmt)

        return Block(addr, 0, statements=stmts)

    def _build_graph_with_replaced_block(self, blocks_to_replace: set[Block], new_block: Block):
        new_graph = self.clinic.copy_graph(self.clinic.cc_graph)

        preds = []
        for block in blocks_to_replace:
            preds.extend([pred for pred in new_graph.predecessors(block) if pred not in blocks_to_replace])
        succs = []
        for block in blocks_to_replace:
            succs.extend([succ for succ in new_graph.successors(block) if succ not in blocks_to_replace])

        if len(preds) > 1 or len(succs) > 1:
            return None

        # remove old blocks
        for block in blocks_to_replace:
            new_graph.remove_node(block)

        # add the new block
        new_graph.add_node(new_block)

        # reconnect edges
        new_graph.add_edge(preds[0], new_block)
        new_graph.add_edge(new_block, succs[0])

        return new_graph

    @staticmethod
    def _has_reg_vvars(vvars: list[VirtualVariable]) -> bool:
        return any(vvar.parameter_category == VirtualVariableCategory.REGISTER for vvar in vvars)
