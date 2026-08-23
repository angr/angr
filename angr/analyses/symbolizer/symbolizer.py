import weakref
from collections import defaultdict
from functools import reduce
import copy
import logging
import networkx

from angr import ailment
import claripy
import pyvex
from angr.utils.graph import GraphUtils
from claripy.errors import ClaripyZ3Error
from ..vm_deobfuscation.vm_deobfuscation import DataSensitiveU64, DataSensitiveU32
from pyvex.expr import DataSensitiveRdTmp
from ...errors import SimUnsatError, SimValueError, SimSolverError
from ...code_location import CodeLocation
from ...engines import HeavyVEXMixin

from ...engines.successors import SimSuccessors
from ...engines.vex import TrackActionsMixin, SimInspectMixin, HeavyResilienceMixin, SuperFastpathMixin
from ...engines.unicorn import SimEngineUnicorn
from ...engines.failure import SimEngineFailure
from ...engines.syscall import SimEngineSyscall
from ...engines.hook import HooksMixin
from ...engines.soot import SootMixin
from .. import register_analysis
from ..analysis import Analysis
from ..cfg.cfg_vm_deobfuscation import StackTouchedAnnotation, DataRegionAnnotation, VMStackVariableAnnotation
from ..forward_analysis.visitors.graph import GraphVisitor
from ..forward_analysis import ForwardAnalysis
from .values import TOP
from ...storage import SimMemoryObject

import time

debug=False
l = logging.getLogger(name=__name__)

def cur_time():
    return time.perf_counter_ns() / 1000000

# class PropagatorEmulatedEngine(SimEngineFailure, SimEngineSyscall, HooksMixin, SimEngineUnicorn, SuperFastpathMixin, TrackActionsMixin, SimInspectMixin, HeavyResilienceMixin, SootMixin, HeavyVEXMixin):
class PropagatorEmulatedEngine(SimEngineFailure, SimEngineSyscall, HooksMixin, SimEngineUnicorn, SuperFastpathMixin,
                               SimInspectMixin, HeavyResilienceMixin, SootMixin, HeavyVEXMixin):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _handle_vex_expr_DataSensitiveRdTmp(self, expr):
        return self._handle_vex_expr_RdTmp(expr)

    def is_symbolized(self, expr):
        if 'symbolified_expr' in expr.variables:
            return True
        else:
            return False
    def _handle_vex_expr(self, expr: pyvex.expr.IRExpr):
        # if self.state.scratch.ins_addr == 0x1400d2186 and self.state.scratch.stmt_idx == 5 and self.state.globals['cur_block_id'].vm_vpc == 5368832359:
        #     import ipdb;ipdb.set_trace()
        result = super()._handle_vex_expr(expr)
        simp_result = result
        code_loc = CodeLocation(self.irsb.addr, self.stmt_idx, block_id=self.state.globals['cur_block_id'])

        cur_abstract_state = self.state.globals['abstract_state']()

        if self.state.globals['is_symbolizer']:
            pass


        elif self.state.globals['is_constant_propagation']:
            skip_prop = False
            # this is to prevent concretization of wo same ip indirect jmp branches for vmp
            if "skip_same_ip_constant_prop" in self.state.globals and self.state.globals[
                "last_added_state_split_cond"] is not None:
                skip_prop = True

            if not skip_prop:
                if expr in cur_abstract_state._replacements[code_loc] and (cur_abstract_state._replacements[code_loc][expr] == "TOP"):
                    #if the location is already symbolic then return without trying to simplify
                    return result

                if self.state.globals['constant_prop_level'] == 1:
                    # this tries to solve every expression with a solver that doesn't have anyh contraints
                    # only use this with Themida since the mba replacements don't get added here
                    if self.state.solver.symbolic(simp_result) and simp_result not in self.state.globals['no_one_soln_cache']:
                        try:
                            # Only for Themida, for VMP we need to use the partial_sym solver because it has the replacements
                            eval_result = self.state.globals['no_constraints_solver'].eval(simp_result, 2)
                            if len(eval_result) == 1:
                                simp_result = claripy.BVV(eval_result[0], simp_result.size())

                                # store the evaluated value back into memory
                                cur_stmt = self.state.scratch.irsb.statements[self.stmt_idx]
                                if isinstance(cur_stmt, pyvex.stmt.WrTmp) and isinstance(cur_stmt.data,
                                                                                         pyvex.expr.Load) and isinstance(expr,
                                                                                                                         pyvex.expr.Load):
                                    if isinstance(cur_stmt.data.addr, pyvex.expr.RdTmp):
                                        if not self.state.solver.symbolic(self.state.scratch.temps[cur_stmt.data.addr.tmp]):
                                            self.state.memory.store(self.state.scratch.temps[cur_stmt.data.addr.tmp], simp_result, endness=self.project.arch.memory_endness)
                                        else:
                                            addr = self.state.partial_symbolic_constraint_solver.eval_one(self.state.scratch.temps[cur_stmt.data.addr.tmp])
                                            self.state.memory.store(addr, simp_result, endness=self.project.arch.memory_endness)
                                    elif isinstance(cur_stmt.data.addr, pyvex.expr.Const):
                                        self.state.memory.store(cur_stmt.data.addr.con.value, simp_result, endness=self.project.arch.memory_endness)
                                elif isinstance(cur_stmt, pyvex.stmt.WrTmp) and isinstance(cur_stmt.data,
                                                                                           pyvex.expr.Get) and isinstance(expr,
                                                                                                                          pyvex.expr.Get):
                                    self.state.registers.store(cur_stmt.data.offset, simp_result)
                            else:
                                self.state.globals['no_one_soln_cache'][simp_result] = True
                        except:
                            self.state.globals['no_one_soln_cache'][simp_result] = True

                elif self.state.globals['constant_prop_level'] == 0:
                    if self.state.solver.symbolic(result):
                        skip = False
                        for var in result.variables:
                            if var.startswith('precon_sp'):
                                skip = True

                        if skip:
                            # do additional simplification and verify that it's not the stack pointer
                            if self.state.globals['is_constant_propagation']:
                                #     # we use simplifier for vm protect because there are, mba replacements in the replacement solver, so we cannot use
                                #     # a solver without those.
                                tmp_simp_result = self.state.solver.simplify(result)
                                if not self.state.solver.symbolic(tmp_simp_result):
                                    simp_result = tmp_simp_result
                                else:
                                    simp_result = result

                            # additional check to see if the eval value is actually a stack pointer or not
                            # only for 1 bit results specifically in a condition check
                            # conditional jumps that aalways evaluate to the same jump, but somehow depend on sp
                            # also make sure thats there's more than one variable other than sp
                            if isinstance(self.state.scratch.irsb.statements[self.stmt_idx], pyvex.stmt.Exit) and \
                                    not len(list(simp_result.variables)) == 1:
                                try:
                                    eval_result = self.state.partial_symbolic_constraint_solver.eval_one(simp_result)
                                    if eval_result in [0,1]:
                                        simp_result = claripy.BVV(eval_result, simp_result.size())
                                except (SimValueError):
                                    pass


                        if (not skip) or (expr in cur_abstract_state._replacements[code_loc] and not (cur_abstract_state._replacements[code_loc][expr] == "TOP")):
                            # if it's already been added to constants once, it means precon_sp was not in that old expression, so we try to solve it again
                            try:
                                eval_result = self.state.partial_symbolic_constraint_solver.eval_one(simp_result)
                                simp_result = claripy.BVV(eval_result, simp_result.size())
                            except (SimValueError):
                                pass

            # this is for the new constant propagation that doesn't merge states........... check if its a non constant
            # is this still needed? i think now we merge the states, and use TOP for merged values
            # Yes, this is used for VMProtect samples where late merging is needed
            if not self.state.solver.symbolic(simp_result) and \
                    expr in cur_abstract_state._replacements[code_loc] and \
                    not (cur_abstract_state._replacements[code_loc][expr] == "TOP") and \
                    cur_abstract_state._replacements[code_loc][expr].con.value != simp_result.args[0]:
                cur_abstract_state._replacements[code_loc][expr] = "TOP"

            elif expr not in cur_abstract_state._replacements[code_loc] and not self.state.solver.symbolic(simp_result) \
                    and not(isinstance(expr, pyvex.expr.Const)):
                expr_type = expr.result_type(self.state.scratch.tyenv)
                if expr_type == "Ity_INVALID":
                    cur_abstract_state._replacements[code_loc][expr] = "TOP"
                    return simp_result
                const_class = pyvex.const.ty_to_const_class(expr_type)
                if len(simp_result.args) > 2:
                    print("Hmmm possible need to simplify the expr")
                    import ipdb;ipdb.set_trace()
                if isinstance(expr, DataSensitiveRdTmp):
                    if const_class == pyvex.const.U64:
                        const_class = DataSensitiveU64
                    elif const_class == pyvex.const.U32:
                        const_class = DataSensitiveU32
                    cur_abstract_state.add_replacement(code_loc, expr, pyvex.expr.Const(
                        const_class(simp_result.args[0], expr.block_id)))
                else:
                    cur_abstract_state.add_replacement(code_loc, expr, pyvex.expr.Const(const_class(simp_result.args[0])))
            ### Check if the result is symbolic now, but was constant in some previous iteration and put in the replacements. If so then remove the replacement
            elif self.state.solver.symbolic(simp_result) and expr in cur_abstract_state._replacements[code_loc] and not (cur_abstract_state._replacements[code_loc][expr] == "TOP"):
                cur_abstract_state._replacements[code_loc][expr] = "TOP"

        return simp_result

    def custom_simplify_ast(self, old_ast):
        # this simplification is to deal with add operation with three arguments causes misses in the replacement cache
        # mba clready present in cache is mba_whole => mba_part_a + mba_part_b
        # (0x1000 + mba_part_a + mba_part_b) - 0x1000
        # the above expression is missed in the cache because of the three argument expr
        # we simplify the above to mba_part_a + mba_part_b

        if old_ast.op == '__sub__':
            if len(old_ast.args) == 2:
                if old_ast.args[1].depth == 1:
                    if old_ast.args[0].op == '__add__':
                        if old_ast.args[0].args[0] is old_ast.args[1]:
                            return old_ast.args[0].args[1] +  old_ast.args[0].args[2]
        return old_ast
    def _perform_vex_expr_Load(self, addr, ty, endness, **kwargs):
        simplified_addr = addr
        if self.state.solver.symbolic(addr):
            try:
                simplified_addr = self.state.partial_symbolic_constraint_solver.eval_one(addr)
            except SimValueError:
                pass
            except claripy.ClaripyError as e:
                pass
        result = super()._perform_vex_expr_Load(simplified_addr, ty, endness, **kwargs)

        if isinstance(result.args[0], str) and result.args[0].startswith('symbolic_read_unconstrained_') and result.args[0] not in self.project.symbolic_reads:
            self.project.symbolic_reads[result.args[0]] = simplified_addr


        # Check if the addr is a stack address, if so skip it
        merged_stack_address = None
        var_dict ={}
        for var in addr.variables:
            if var.startswith("state_merge"):
                var_dict["state_merge"] = True
            elif var.startswith("precon_sp"):
                var_dict["precon_sp"] = True
            else:
                merged_stack_address = False
                break

        if merged_stack_address is None and len(var_dict.keys()) == 2:
            merged_stack_address = True
        else:
            merged_stack_address = False

        save = False
        var_ast_list = []
        conc_addrs = None

        if self.state.solver.symbolic(simplified_addr):
            try:
                conc_addrs = self.state.partial_symbolic_constraint_solver.eval_upto(simplified_addr, 3)
            except:
                pass

        if conc_addrs:
            ast_addrs = []
            for con_addr in conc_addrs:
                ast_addrs.append(claripy.BVV(con_addr, addr.size()))

            conc_addrs = ast_addrs

            if len(conc_addrs) <= 3:
                if isinstance(result.args[0], str) and result.args[0].startswith('symbolic_read_unconstrained_') and not merged_stack_address:
                    if not self.state.solver.symbolic(simplified_addr):
                        return result
                    save = True

            if len(var_ast_list) > 1:
                print("More than one variables? which one to save.... maybe both")


        if save:
            if len(conc_addrs) > 2 and len(simplified_addr.variables) == 1 and list(simplified_addr.variables)[0].startswith('switch_case_table'):
                # loading different vip values based on the switch case jump table
                switch_case_var = None
                for ast in simplified_addr.leaf_asts():
                    if isinstance(ast.args[0], str) and ast.args[0].startswith('switch_case_table'):
                        switch_case_var = ast
                # conc_addrs = self.state.partial_symbolic_constraint_solver.eval_upto(simplified_addr, 8)
                solns = self.state.partial_symbolic_constraint_solver._solver.batch_eval(
                    [simplified_addr, switch_case_var], 8)
                solns_dict = defaultdict(set)
                for soln in solns:
                    # we sort the conc addrs such that they are in the same order as the previous switch case condition
                    solns_dict[soln[0]].add(soln[1])

                last_addr = None
                conc_addrs_dict = {}
                for k in solns_dict.keys():
                    if len(solns_dict[k]) == 1:
                        var_val = list(solns_dict[k])[0]
                        conc_addrs_dict[var_val] = k
                    else:
                        last_addr = k

                conc_addrs = []
                for i in range(len(solns_dict) - 1):
                    conc_addrs.append(conc_addrs_dict[i])

                # conc_addrs sorted in the same order as the jump case conditional variable
                conc_addrs.append(last_addr)

                ast_addrs = []
                for con_addr in conc_addrs:
                    ast_addrs.append(claripy.BVV(con_addr, addr.size()))

                conc_addrs = ast_addrs
                loaded_values = []
                for conc_addr in conc_addrs:
                    loaded_value = self.state.memory.load(conc_addr, self._ty_to_bytes(ty),
                                                          endness=self.state.arch.memory_endness)
                    loaded_values.append(loaded_value)

                final_cond = loaded_values[-1]
                for idx, loaded_value in enumerate(loaded_values[:-1]):
                    final_cond = claripy.If(switch_case_var == idx, loaded_value, final_cond)

                import ipdb;
                ipdb.set_trace()

                return final_cond

            # elif len(conc_addrs) > 2:
            #     # jump table for switch case
            #     sec = self.project.loader.main_object.find_section_containing(conc_addrs[0].args[0])
            #     if not sec:
            #         return result
            #     elif (sec.name.startswith('.rdata') or sec.name.startswith('.data')):
            #         return result
            #
            #     import ipdb;
            #     ipdb.set_trace()
            #
            #     print("possibly a switch case jump table?")
            #     conc_addrs = self.state.partial_symbolic_constraint_solver.eval_upto(simplified_addr, 12)
            #     ast_addrs = []
            #     for con_addr in conc_addrs:
            #         ast_addrs.append(claripy.BVV(con_addr, addr.size()))
            #
            #     conc_addrs = ast_addrs
            #
            #     loaded_values = []
            #
            #     for conc_addr in conc_addrs:
            #         loaded_value = self.state.memory.load(conc_addr, self._ty_to_bytes(ty),
            #                                               endness=self.state.arch.memory_endness)
            #         if loaded_value.concrete and self.state.project.loader.main_object.contains_addr(
            #                 loaded_value.concrete_value):
            #             loaded_values.append(loaded_value)
            #
            #     no_bits = len(bin(len(loaded_values))) - 2
            #     indirect_jump_var = claripy.BVS('switch_case_table', no_bits)
            #     final_cond = loaded_values[-1]
            #     for idx, loaded_value in enumerate(loaded_values[:-1]):
            #         final_cond = claripy.If(indirect_jump_var == idx, loaded_value, final_cond)
            #
            #     return final_cond
            elif len(conc_addrs) == 2 and self.state.scratch.ins_addr not in self.project.bt_ins_addrs:#and self.state.block(self.state.scratch.ins_addr, size=15).disassembly.insns[0].mnemonic.startswith("mov"):
                loaded_values = []
                for conc_addr in conc_addrs:
                    loaded_value = self.state.memory.load(conc_addr, self._ty_to_bytes(ty),
                                                          endness=self.state.arch.memory_endness)
                    if self.state.solver.symbolic(loaded_value):
                        try:
                            new_val = self.state.partial_symbolic_constraint_solver.eval_one(loaded_value)
                            loaded_value = claripy.BVV(new_val, loaded_value.size())
                        except:
                            pass
                    loaded_values.append(loaded_value)

                existing_state_split_var = False
                if self.state.globals['last_added_state_split_cond'] is not None:
                    for var in simplified_addr.variables:
                        if var.startswith(self.state.globals['last_added_state_split_cond'].args[0]):
                            existing_state_split_var = True
                            break

                if existing_state_split_var:
                    print("experimental")
                    # import ipdb;
                    # ipdb.set_trace()
                    state_split_cond = self.state.globals['last_added_state_split_cond']
                    solns = self.state.partial_symbolic_constraint_solver._solver.batch_eval([state_split_cond, simplified_addr], 2)

                    loaded_value_0 = self.state.memory.load(solns[0][1], self._ty_to_bytes(ty),
                                                            endness=self.state.arch.memory_endness)
                    loaded_value_1 = self.state.memory.load(solns[1][1], self._ty_to_bytes(ty),
                                                            endness=self.state.arch.memory_endness)
                    if solns[0][0] is True:
                        to_return = claripy.If(state_split_cond, loaded_value_0, loaded_value_1)
                    else:
                        to_return = claripy.If(state_split_cond, loaded_value_1, loaded_value_0)

                    # import ipdb;ipdb.set_trace()
                    return to_return

                state_split_cond = claripy.BoolS('mba_state_split_cond')
                self.state.globals['last_added_state_split_cond'] = state_split_cond
                addr_mba=claripy.If(state_split_cond, conc_addrs[0], conc_addrs[1])
                self.project.load_addr_mba_to_jump_addr_mapping[addr_mba] = []
                self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr, addr_mba)
                to_return=claripy.If(state_split_cond, loaded_values[0], loaded_values[1])
                self.state.partial_symbolic_constraint_solver._solver.add_replacement(result, to_return)


                ## This to add addrs which are of the following form mba+offset, mba+4
                if addr.op in ["__add__","__sub__"]:
                    if len(addr.args) == 2:
                        if addr.args[0].depth == 1:
                            if addr.op == "__add__":
                                self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr.args[1], claripy.If(state_split_cond, conc_addrs[0] - addr.args[0], conc_addrs[1] - addr.args[0]))
                            elif addr.op == "__sub__":
                                self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr.args[1], claripy.If(state_split_cond, addr.args[0] - conc_addrs[0], addr.args[0] - conc_addrs[1]))
                        elif addr.args[1].depth == 1:
                            if addr.op == "__add__":
                                self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr.args[0] ,claripy.If(state_split_cond, conc_addrs[0] - addr.args[1], conc_addrs[1] - addr.args[1]))
                            elif addr.op == "__sub__":
                                self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr.args[0] ,claripy.If(state_split_cond, conc_addrs[0] + addr.args[1], conc_addrs[1] + addr.args[1]))
                        elif addr.args[0].depth == 2 and len(addr.args[0].variables) == 1 and list(addr.args[0].variables)[0].startswith("precon_sp"):
                            if addr.op == "__add__":
                                self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr.args[1], claripy.If(state_split_cond, conc_addrs[0] - addr.args[0], conc_addrs[1] - addr.args[0]))

                            elif addr.op == "__sub__":
                                import ipdb;ipdb.set_trace()
                                self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr.args[1], claripy.If(state_split_cond, addr.args[0] - conc_addrs[0], addr.args[0] - conc_addrs[1]))

                        else:
                            try:
                                conc_val = self.state.partial_symbolic_constraint_solver.eval_one(addr.args[0])
                                if addr.op == "__add__":
                                    self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr.args[1], claripy.If(state_split_cond, conc_addrs[0] - conc_val, conc_addrs[1] - conc_val))
                                elif addr.op == "__sub__":
                                    self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr.args[1], claripy.If(state_split_cond, conc_val - conc_addrs[0], conc_val - conc_addrs[1]))
                            except:
                                pass

                    elif len(addr.args) == 3:
                        if addr.args[0].depth == 1:
                            if addr.op == "__add__":
                                self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr.args[1] + addr.args[2], claripy.If(state_split_cond, conc_addrs[0] - addr.args[0], conc_addrs[1] - addr.args[0]))
                            elif addr.op == "__sub__":
                                print("Not implemented")
                                import ipdb;
                                ipdb.set_trace()
                        elif addr.args[1].depth == 1:
                            if addr.op == "__add__":
                                self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr.args[0] + addr.args[2],claripy.If(state_split_cond, conc_addrs[0] - addr.args[1], conc_addrs[1] - addr.args[1]))
                            elif addr.op == "__sub__":
                                print("Not implemented")
                                import ipdb;
                                ipdb.set_trace()
                        elif addr.args[2].depth == 1:
                            if addr.op == "__add__":
                                self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr.args[0] + addr.args[1],claripy.If(state_split_cond, conc_addrs[0] - addr.args[2], conc_addrs[1] - addr.args[2]))
                            elif addr.op == "__sub__":
                                print("Not implemented")
                                import ipdb;
                                ipdb.set_trace()

                ## Do replacement for all registers and temps just to be safe....... although the mba can still be on stack...... will deal with it later.
                ## That should not be a problem since we try to evaluate every address above, so it should be resolved
                for ind in range(len(self.state.scratch.temps)):
                    if self.state.scratch.temps[ind] is not None:
                        new_val = self.state.partial_symbolic_constraint_solver._solver._replacement(
                            self.state.scratch.temps[ind])
                        if new_val is not self.state.scratch.temps[ind]:
                            self.state.scratch.temps[ind] = new_val
                        else:
                            # check for state_var depndent exprs
                            to_replace, new_mba_expr = self.should_replace_with_mba_var(self.state.scratch.temps[ind],
                                                                                        addr,
                                                                                        addr_mba)
                            if to_replace:
                                self.state.scratch.temps[ind] = new_mba_expr


                for reg in self.state.arch.registers.keys():
                    offset = self.state.arch.registers[reg][0]
                    size = self.state.arch.registers[reg][1]
                    old_val = self.state.registers.load(offset, size)
                    new_val = self.state.partial_symbolic_constraint_solver._solver._replacement(old_val)
                    if old_val is not new_val:
                        self.state.registers.store(offset, new_val)
                    else:
                        # perform extra simplifications and check
                        simp_ast = self.custom_simplify_ast(old_val)
                        if simp_ast is not old_val:
                            new_val = self.state.partial_symbolic_constraint_solver._solver._replacement(simp_ast)
                            if new_val is not simp_ast:
                                self.state.registers.store(offset, new_val)
                        elif old_val.op == "__add__" and len(old_val.args) == 3:
                            new_val = old_val
                            # deal with three argument adds, since they are not in the replacements
                            if old_val.args[0].depth == 1:
                                new_val = self.state.partial_symbolic_constraint_solver._solver._replacement(
                                    old_val.args[1] + old_val.args[2]) + old_val.args[0]
                            elif old_val.args[1].depth == 1:
                                new_val = self.state.partial_symbolic_constraint_solver._solver._replacement(
                                    old_val.args[0] + old_val.args[2]) + old_val.args[1]
                            elif old_val.args[2].depth == 1:
                                new_val = self.state.partial_symbolic_constraint_solver._solver._replacement(
                                    old_val.args[0] + old_val.args[1]) + old_val.args[2]

                            if new_val is not old_val:
                                self.state.registers.store(offset, new_val)
                        else:
                            # check for state_var depndent exprs
                            to_replace, new_mba_expr = self.should_replace_with_mba_var(old_val, addr, addr_mba)

                            if to_replace:
                                self.state.registers.store(offset, new_mba_expr)


                return to_return
            else:
                print("More than one possible addrs")
                # import ipdb;ipdb.set_trace()

        return result

    def should_replace_with_mba_var(self, expr_to_check, orig_addr, mba_split_cond):
        # heuristically trying to make sure one expr is the subset of another
        # this is specifically for exprs which are dependent on the state_var
        if expr_to_check.op == "If" and orig_addr.op == "If":
            if expr_to_check.variables == orig_addr.variables:
                # direct batch eval on orig_addr will cause issues due to the replacement thats already added
                # so we check only one of the if else values
                solns = self.state.partial_symbolic_constraint_solver._solver.batch_eval([expr_to_check.args[1], orig_addr.args[1]], 3)
                if len(solns) == 2:
                    for val1, val2 in solns:
                        sec = self.project.loader.main_object.find_section_containing(val1)
                        if not sec:
                            return False, None

                assert solns[0][0] - solns[0][1] == solns[1][0] - solns[1][1]

                diff = solns[0][0] - solns[0][1]

                import ipdb;ipdb.set_trace()

                if diff > 0:
                    return True, mba_split_cond + diff
                elif diff < 0:
                    return True, mba_split_cond - abs(diff)
                elif diff == 0:
                    return True, mba_split_cond

        return False, None

    def _handle_vex_defaultexit(self, expr, jumpkind):
        super()._handle_vex_defaultexit(expr, jumpkind)
        # if blockid is None then it's probably some weird VEX instruction and we are still in the same block most likely
        if isinstance(expr, pyvex.expr.RdTmp):
            if expr.block_id:
                self.state.globals['cur_block_id'] = expr.block_id
        else:
            if expr.con.block_id:
                self.state.globals['cur_block_id'] = expr.con.block_id

    def _handle_vex_stmt_Exit(self, stmt):
        super()._handle_vex_stmt_Exit(stmt)
        if stmt.dst.block_id:
            self.state.globals['cur_block_id'] = stmt.dst.block_id


class EmulatedCFGVisitor(GraphVisitor):

    def __init__(self, graph, start):
        super(EmulatedCFGVisitor, self).__init__()
        self._start = start
        self.graph=graph
        self.reset()

    def startpoints(self):
        return [self._start]

    def successors(self, node):
        return list(self.graph.successors(node))

    def predecessors(self, node):
        return list(self.graph.predecessors(node))

    def sort_nodes(self, nodes=None):
        sorted_nodes = GraphUtils.quasi_topological_sort_nodes(self.graph)
        if nodes is not None:
            sorted_nodes = [ n for n in sorted_nodes if n in set(nodes) ]
        return sorted_nodes

# The base state

class PropagatorState:
  #  _tops = {}

    def __init__(self, arch, replacements=None, concrete_states=None):
        self.arch = arch
        self.gpr_size = arch.bits // arch.byte_width  # size of the general-purpose registers
        self._replacements = defaultdict(dict) if replacements is None else replacements
        self._concrete_states = concrete_states

    def __repr__(self):
        return "<PropagatorState>"

    def copy(self):
        raise NotImplementedError()

    def merge(self, *others):
        state = self.copy()
        for o in others:
            for loc, vars_ in o._replacements.items():
                if loc not in state._replacements:
                    state._replacements[loc] = vars_.copy()
                else:
                    for var, repl in vars_.items():
                        if var not in state._replacements[loc]:
                            state._replacements[loc][var] = repl
                        else:
                            if state._replacements[loc][var] != repl:
                                state._replacements[loc][var] = TOP
        return state


    def add_replacement(self, codeloc, old, new):
        self._replacements[codeloc][old] = new

    @staticmethod
    def top(bits: int) -> claripy.ast.Bits:
        """
        Get a TOP value.

        :param size:    Width of the TOP value (in bits).
        :return:        The TOP value.
        """
        # if bits in PropagatorState._tops:
        #     return PropagatorState._tops[bits]
        r = claripy.BVS("TOP", bits)#, explicit_name=True)


        # PropagatorState._tops[bits] = r
        return r

    @staticmethod
    def is_top(expr) -> bool:
        """
        Check if the given expression is a TOP value.

        :param expr:    The given expression.
        :return:        True if the expression is TOP, False otherwise.
        """
        if isinstance(expr, str) and expr == "TOP":
            return True
        else:
            for var in expr.variables:
                if var.startswith("TOP"):
                    return True
        return False

    def _get_weakref(self):
        return weakref.proxy(self)

    @property
    def concrete_states(self):
        return self._concrete_states

    @concrete_states.setter
    def concrete_states(self, v):
        self._concrete_states = v

    def get_concrete_state(self, block_id):
        """

        :param addr:
        :return:
        """
        ## This is for handling the initial concrete_states set with a list
        #if isinstance(self.concrete_states, list):
        to_return = []
        possible_successors =self.concrete_states
        #else:
        #    possible_successors = self.concrete_states.all_successors
        for s in possible_successors:
            if s.globals['cur_block_id'] == block_id:
                to_return.append(s)

        return to_return

# VEX state

class PropagatorVEXState(PropagatorState):

    def __init__(self, arch, replacements=None, concrete_states=None):
        super().__init__(arch, replacements=replacements, concrete_states=concrete_states)
        # this mapping is used to decide which exprs to treat as symbolic in future analysis

    def __repr__(self):
        return "<PropagatorVEXState>"

    def copy(self):
        new_replacements = defaultdict(dict)
        for loc, vars_ in self._replacements.items():
            new_replacements[loc] = vars_.copy()

        return PropagatorVEXState(self.arch, replacements=new_replacements)
        # return PropagatorVEXState(self.arch, replacements=self._replacements.copy())

    def merge(self, node, *all_states):
        #here we merge the input states and the input replacements
        #the replacements merge here is not what decides the fixed_point......... that happens in run_on_node
        #the replacements merge here are just to carry the replacements from other states e.g. multiple states merging into one

        #Collect all concretes states for the current node from all the abstract states and merge them

        conc_states_to_merge = []
        for state in all_states:
            other_conc_states = state.get_concrete_state(node.block_id)
            if other_conc_states is not None:
                conc_states_to_merge = conc_states_to_merge + other_conc_states

        merged_concrete_states = []
        merged_concrete_state = None
        states_on_same_sp =defaultdict(list)

        #group states based on same stack pointer value
        for cur_conc_state in conc_states_to_merge:
            #states_on_same_sp[cur_conc_state.solver.eval_one(cur_conc_state.regs.sp)].append(cur_conc_state)
            states_on_same_sp[cur_conc_state.partial_symbolic_constraint_solver.eval_one(cur_conc_state.regs.sp)].append(cur_conc_state)
        # We have states which don't have matching stack pointer, so we should not be merging now

        ## make sure they have the same stack pointer exactly other merging will result in TOP
        for addr, states_to_merge_same_sp in states_on_same_sp.items():
            for cur_conc_state in states_to_merge_same_sp[1:]:
                cur_conc_state.regs.sp = states_to_merge_same_sp[0].regs.sp

        merged_concrete_states = []
        for addr, states_to_merge_same_sp in states_on_same_sp.items():
            merged_concrete_state = states_to_merge_same_sp[0]
            for cur_conc_state in states_to_merge_same_sp[1:]:
                merged_concrete_state = self._merge_concrete_states(merged_concrete_state, cur_conc_state)
            merged_concrete_states.append(merged_concrete_state)

        # if len(states_on_same_sp) != 1:
        #     import ipdb;
        #     ipdb.set_trace()


            # merged_concrete_states = self._merge_concrete_states(other, node.block_id)
        merged_replacements = defaultdict(dict)
        for loc, vars_ in all_states[-1]._replacements.items():
            merged_replacements[loc] = vars_.copy()
        merge_occurred = False
        for state in all_states[:-1]:
            if state is not None:
                merged_replacements, _ = self._merge_replacements(merged_replacements, state._replacements)

        if merged_concrete_state is None:
            print("Merged state is None")

        return PropagatorVEXState(arch=self.arch, concrete_states=merged_concrete_states, replacements=merged_replacements), None

    def _merge_concrete_states(self, state0, state1):
        """

        :param StorageState other:
        :return:
        :rtype:                             list
        """

        merged = [ ]
        # if not isinstance(self.concrete_states, list):
        #     self.concrete_states = self.concrete_states.all_successors
        # add a copy of the original state to globals, so that the order in which the plugins are merged doesn't impact the constraints when
        # using the solver to evaluate values
        state0.globals['orig_state_copy'] = state0.copy()
        state1.globals['orig_state_copy'] = state1.copy()
        merged_stuff = state0.merge(state1, plugin_whitelist=['inspect', 'preconstrainer', 'globals', 'mem', 'heap', 'regs', 'solver', 'callstack', 'history', 'fs', 'scratch', 'memory', 'registers', 'libc', 'partial_symbolic_constraint_solver'])
        state0.globals['orig_state_copy'] = None
        state1.globals['orig_state_copy'] = None
        merged_stuff[0].globals['orig_state_copy'] = None
        return merged_stuff[0]

    def add_replacement(self, codeloc, old, new):
        if old not in self._replacements[codeloc]:
            self._replacements[codeloc][old] = new

        ## If it is not the same as the previous replacement then it is not a constant and should not be replaced
        elif self._replacements[codeloc][old].con.value != new.con.value:
            import ipdb;ipdb.set_trace()
            self._replacements[codeloc][old] = self.top(new.size())

    def _merge_replacements(self, replacements_0, replacements_1):
        merged_replacements = replacements_0
        merge_occurred = False
        for loc, vars_ in replacements_1.items():
            if loc not in merged_replacements:
                merged_replacements[loc] = vars_.copy()
                merge_occurred = True
            else:
                for var, repl in vars_.items():
                    if var not in merged_replacements[loc]:
                        merged_replacements[loc][var] = repl
                        merge_occurred = True
                    else:
                        if self.is_top_str(repl) and self.is_top_str(merged_replacements[loc][var]):
                            continue
                        elif self.is_top_str(repl) or self.is_top_str(merged_replacements[loc][var]):
                            merged_replacements[loc][var] = "TOP"
                            merge_occurred = True

                        elif merged_replacements[loc][var].con.value != repl.con.value:
                            t = "TOP"
                            merged_replacements[loc][var] = t
                            merge_occurred = True

        return merged_replacements, merge_occurred

    def is_top_str(self, repl):
        if isinstance(repl, str) and repl == "TOP":
            return True
        return False


# AIL state

class PropagatorAILState(PropagatorState):

    def __init__(self, arch, replacements=None):
        super().__init__(arch, replacements=replacements)
        self._variables = { }  # variable to values

    def __repr__(self):
        return "<PropagatorAILState>"

    def copy(self):
        rd = PropagatorAILState(
            self.arch,
            replacements=self._replacements.copy(),
        )
        rd._variables = self._variables.copy()
        return rd

    def merge(self, *others):
        state = super().merge(*others)

        for o in others:
            for k, v in o._variables.items():
                if k not in state._variables:
                    state._variables[k] = v
                else:
                    if state._variables[k] != o._variables[k]:
                        # Go to TOP
                        state._variables[k] = TOP
        return state

    def store_variable(self, old, new):
        if new is not None:
            self._variables[old] = new

    def get_variable(self, old):
        return self._variables.get(old, None)

    def remove_variable(self, old):
        self._variables.pop(old, None)

    def filter_variables(self, atom):
        keys_to_remove = set()

        for k, v in self._variables.items():
            if isinstance(v, ailment.Expr.Expression) and (v == atom or v.has_atom(atom)):
                keys_to_remove.add(k)

        for k in keys_to_remove:
            self._variables.pop(k)


class Symbolizer(ForwardAnalysis, Analysis):  # pylint:disable=abstract-method
    """
    PropagatorAnalysis propagates values, either constants or variables, across a block or a function. It supports both
    VEX and AIL. It performs certain arithmetic operations between constants, including but are not limited to:

    - addition
    - subtraction
    - multiplication
    - division
    - xor

    It also performs the following memory operations, too:

    - Loading values from a known address
    - Writing values to a stack variable
    """

    def __init__(self, func=None, block=None, func_graph=None, base_state=None, max_iterations=1,
                 load_callback=None, stack_pointer_tracker=None, start=None, graph=None, iropt_level=None):
        start = self._resolve_graph_start_node(graph, self.project.entry if start is None else start)
        graph_visitor = EmulatedCFGVisitor(graph, start)
        self.debug = False
        self.debug_two = False

        ForwardAnalysis.__init__(self, order_jobs=True, allow_merging=False, allow_state_merging=True,
                                 allow_widening=False,
                                 graph_visitor=graph_visitor)
        self._graph=graph
        self._base_state = base_state
        self._function = func
        self._max_iterations = max_iterations
        self._load_callback = load_callback
        self._stack_pointer_tracker = stack_pointer_tracker  # only used when analyzing AIL functions
        self._iropt_level = iropt_level
        self._node_iterations = defaultdict(int)
        self._states = { }
        self.replacements = {}
        self.symbolic_expr_locations = {}
        self._engine_ail = None
        self._prev_input_states = { }
        self.project.simprocedures_to_remove = set()
        self._engine= PropagatorEmulatedEngine(project=self.project)

        backs = self.back_edges_from_start(self._graph, start)
        headers = self.loop_headers_from_back_edges(backs)
        self.project.loop_start_nodes = headers
        # we save the entry points of loop here, which will be used later
        self._analyze()
        self._initial_state = None

        for node in graph.nodes():
            ## end points which are not reachable are skippe from replacements collections
            if node.block_id in self._states:
                cur_abstract_state = self._states[node.block_id]
                self.replacements[node.block_id] = cur_abstract_state._replacements

        # #Get all the symbolic locations
        # self.symbolic_expr_locations_blockwise = defaultdict(dict)
        # for block_id, repls in self.replacements.items():
        #     for codeloc, exprs_repls in repls.items():
        #         for expr, repl in exprs_repls.items():
        #             if self.is_top_str(repl):
        #                 if codeloc in self.symbolic_expr_locations_blockwise[block_id]:
        #                     self.symbolic_expr_locations_blockwise[block_id][codeloc].append(expr)
        #                 else:
        #                     self.symbolic_expr_locations_blockwise[block_id][codeloc] = [expr]

        #Get all the symbolic locations
        for block_id, repls in self.replacements.items():
            for codeloc, exprs_repls in repls.items():
                for expr, repl in exprs_repls.items():
                    if self.is_top_str(repl):
                        self.symbolic_expr_locations[(codeloc, expr)] = "TOP"



        for key,value in self._states.items():
            self._states[key] = None

        l.debug(len(self.symbolic_expr_locations))
        l.debug(len(self.replacements))

        # for block_key, iter in self._node_iterations.items():
        #     if iter<2:
        #         if block_key.addr == 0x48139d and block_key.vm_vpc == 4306815:
        #             print(block_key)
        #             import ipdb;ipdb.set_trace()
        #         if block_key.addr == 0x46b038 and block_key.vm_vpc == 4305884:
        #             print(block_key)
        #             import ipdb;
        #             ipdb.set_trace()
        #         if block_key.addr == 0x40a533 and block_key.vm_vpc == 4305884:
        #             print(block_key)
        #             import ipdb;
        #             ipdb.set_trace()
        #         if block_key.addr == 0x40a533 and block_key.vm_vpc == 4305884:
        #             print(block_key)
        #             import ipdb;
        #             ipdb.set_trace()

    #
    # Main analysis routines
    #

    @staticmethod
    def _format_graph_start_candidates(candidates):
        return [
            (getattr(node, "addr", None), getattr(node, "block_id", None))
            for node in candidates
        ]

    @staticmethod
    def _resolve_graph_start_node(G, start):
        if G is None or start is None:
            return start

        try:
            if start in G:
                return start
        except TypeError:
            pass

        candidates = [node for node in G if getattr(node, "block_id", None) == start]
        if len(candidates) == 1:
            return candidates[0]
        if candidates:
            raise ValueError(
                "Ambiguous Symbolizer start block_id %s: %s"
                % (start, Symbolizer._format_graph_start_candidates(candidates))
            )

        start_block_id = getattr(start, "block_id", None)
        if start_block_id is not None:
            candidates = [node for node in G if getattr(node, "block_id", None) == start_block_id]
            if len(candidates) == 1:
                return candidates[0]
            if candidates:
                raise ValueError(
                    "Ambiguous Symbolizer start block_id %s: %s"
                    % (start_block_id, Symbolizer._format_graph_start_candidates(candidates))
                )

        start_addr = getattr(start, "addr", start)
        candidates = [node for node in G if getattr(node, "addr", None) == start_addr]
        if len(candidates) == 1:
            return candidates[0]
        if not candidates:
            raise ValueError("Symbolizer start %r is not present in the graph" % (start,))

        initialized_candidates = [
            node for node in candidates
            if getattr(node, "input_state", None) is not None
        ]
        if len(initialized_candidates) == 1:
            return initialized_candidates[0]

        raise ValueError(
            "Ambiguous Symbolizer start addr %r: %s"
            % (start_addr, Symbolizer._format_graph_start_candidates(candidates))
        )

    def back_edges_from_start(self, G, start):
        """
        Find all DFS back edges (u, v) reachable from `start` in a NetworkX DiGraph.
        A back edge is an edge to an ancestor currently on the DFS stack.
        Only nodes reachable from `start` are explored.
        """
        WHITE, GRAY, BLACK = 0, 1, 2  # DFS colors

        start = self._resolve_graph_start_node(G, start)

        color = {n: WHITE for n in G.nodes()}
        on_stack = set()
        backs = []

        # iterative DFS from the provided start node
        color[start] = GRAY
        on_stack.add(start)
        stack = [(start, iter(G.successors(start)))]

        while stack:
            u, it = stack[-1]
            try:
                v = next(it)
            except StopIteration:
                stack.pop()
                on_stack.discard(u)
                color[u] = BLACK
                continue

            c = color.get(v, WHITE)
            if c == WHITE:
                color[v] = GRAY
                on_stack.add(v)
                stack.append((v, iter(G.successors(v))))
            elif v in on_stack:
                # v is an ancestor of u in the current DFS tree -> back edge
                backs.append((u, v))

        return backs

    def loop_headers_from_back_edges(self, back_edges):
        """
        Targets of back edges; in a reducible CFG these are the loop headers.
        """
        return {v.block_id for _, v in back_edges}

    def _get_and_update_input_state(self, node):
        """
        Get the input abstract state for this node, and remove it from the state map.

        :param node: The node in graph.
        :return:     A merged state, or None if there is no input state for this node available.
        """
        if self._node_key(node) in self._input_states:
            input_state = self._get_input_state(node)
            # we only store the merged states for loop entries, the result of any other merge is used by the current node but not stored.
            # if we store it then it starts to merge at locations that are not the entry points of loop and TOP's values that should not be

            if node.block_id in self.project.loop_start_nodes:
                self._input_states[self._node_key(node)] = [input_state]
            else:
                del self._input_states[self._node_key(node)]
            return input_state
        return None

    def _pre_analysis(self):
        pass

    def _pre_job_handling(self, job):
        pass

    ## This mo_cmp is just to check fixed point
    @staticmethod
    def _mo_cmp(
        mo_self,
        mo_other,
        addr: int,
        size: int,
    ):  # pylint:disable=unused-argument
        # comparing bytes from two sets of memory objects
        # we don't need to resort to byte-level comparison. object-level is good enough.
        if PropagatorState.is_top(mo_self.object) and PropagatorState.is_top(mo_other.object):
            return True

        if not PropagatorState.is_top(mo_self.object) and not PropagatorState.is_top(mo_other.object):
            # we do not need to actually compare here because, in top_merger_mixin, if the values are actually different
            # they are merged to TOP, so if they are not both TOP, we can assume they both evaluate to same concrete value
            return True

        return False

    def _initial_abstract_state(self, node):
        if not node.input_state:
            # This is for nodes that do not have any concrete state yet
            return PropagatorVEXState(arch=self.project.arch, concrete_states=[])
        node.input_state.globals['last_added_state_split_cond'] = None
        node.input_state.globals['cur_block_id'] = node.block_id
        if isinstance(node, ailment.Block):
            # AIL
            state = PropagatorAILState(arch=self.project.arch)
        else:
            # VEX
            #state = SimState(arch=self.projct.arch)
            state = PropagatorVEXState(arch=self.project.arch)
            state.concrete_states = [node.input_state]
        self._initial_state = state
        return state

    def _merge_states(self, node, *states):
        #return states[-1], True
        if len(states) == 1:
            return states[0]
        # merged_abstract_state, fixedpoint_reached = reduce(lambda s_0, s_1: s_0.merge(s_1), states[1:], states[0])
        # return merged_abstract_state, fixedpoint_reached

        merged_state, merge_occurred = states[0].merge(node, *states)
        return merged_state, not merge_occurred
    # def _add_input_state(self, node, input_state):
    #     successors_to_visit = []
    #     successors = self._graph_visitor.successors(node)
    #     for succ in successors:
    #         self._state_map[succ] = input_state
    #         for concrete_state in input_state.concrete_states:
    #             if succ.addr == concrete_state.ip._model_concrete.value:
    #                 successors_to_visit.append(succ)
    #     return successors_to_visit

    def _run_on_node(self, node, abstract_state):
        l.debug(node)
        print(node)
        # if str(node) == "<CFGENode 0x140061ee8 ()vm-vpc:5368833178 [2]>":
        #     import ipdb;ipdb.set_trace()
        if node.is_simprocedure and len(self._graph_visitor.successors(node)) == 1 and \
                self._graph_visitor.successors(node)[0] is node and \
                node.name == "exit":
            return False, abstract_state
        concrete_states = abstract_state.get_concrete_state(node.block_id)
        l.debug("Total concrete states: "+str(len(concrete_states)))
        if len(concrete_states) == 0:
            l.debug("No concrete state..... so no executing")
            # import ipdb;ipdb.set_trace()
            # didn't find any state going here
            return False, abstract_state

        if node.block_id in self._prev_input_states and len(list(self.graph.predecessors(node))) > 1 and len(concrete_states) == 1:
            if len(self._prev_input_states[node.block_id]) > 1:
                import ipdb;ipdb.set_trace()
            # right now we assume only one concrete state
            changed = self.compare_concrete_states(concrete_states[0], self._prev_input_states[node.block_id][0])
        elif node.block_id in self._prev_input_states and len(concrete_states) == 1 and concrete_states[0].globals['same_sp_merged']:
            if len(self._prev_input_states[node.block_id]) > 1:
                import ipdb;ipdb.set_trace()
            concrete_states[0].globals['same_sp_merged'] = False
            # right now we assume only one concrete state
            changed = self.compare_concrete_states(concrete_states[0], self._prev_input_states[node.block_id][0])
        else:
            changed = True

        self._prev_input_states[node.block_id] = concrete_states
        l.debug("Changed: "+str(changed))


        if not changed:
            return False, abstract_state

        # if abstract_state is not self._initial_state:
        #     print("copying state")
        #     # make a copy of the state if it's not the initial state
        #     abstract_state = abstract_state.copy()
        #     print("done")
        #
        #     # clear previous saved abstract states
        #     if len(list(self.graph.predecessors(node))) == 1:
        #         for pred in self.graph.predecessors(node):
        #             if len(list(self.graph.predecessors(pred))) > 1:
        #                 continue
        #             else:
        #                 self._states[pred.block_id] = None
        #                 self._input_states[pred] = None

        if abstract_state is not self._initial_state:
            # make a copy of the state if it's not the initial state
            if node.block_id in self._states:
                prev_replacements = self._states[node.block_id]._replacements
                abstract_state = PropagatorVEXState(arch=self.project.arch, replacements=prev_replacements)
            else:
                abstract_state = PropagatorVEXState(arch=self.project.arch)



        else:
            # clear self._initial_state so that we *do not* run this optimization again!
            self._initial_state = None

        all_successors = defaultdict(list)
        changed = False


        for conc_state in concrete_states:
            block_key = node.block_id

            conc_state.globals['abstract_state'] = weakref.ref(abstract_state)
            conc_state.globals['cur_block_id'] = block_key
            conc_state.globals['cur_iter'] = self._node_iterations[block_key]
            engine = self._engine
            # if node.addr == 0x1400d2181 and node.block_id.vm_vpc == 5368833050:
            # import cProfile, pstats
            # profiler = cProfile.Profile()
            # profiler.enable()

            if self._node_iterations[block_key] == 0 and block_key in self.project.to_symbolize:
                for k in self.project.to_symbolize[block_key].keys():
                    for page_no, offset, size in self.project.to_symbolize[block_key][k]:
                        sym_result = PropagatorState.top(size * self.project.arch.byte_width)
                        self.project.merger_top_dict_debug[sym_result.args[0]] = (block_key,(page_no, offset, size, k), "This comes from symbolizing existing values")

                        if k == 'mem':
                            conc_state.memory.store(page_no + offset, sym_result,
                                                   endness=self.project.arch.memory_endness, inspect=False)
                        elif k == 'reg':
                            conc_state.registers.store(page_no + offset, sym_result,
                                                      endness=self.project.arch.register_endness, inspect=False)

            if node.is_simprocedure and node.name == "read":
                read_buf_addr = conc_state.regs.rsi
                read_buf_size = conc_state.regs.edx

            for block_id, (same_ip, split_block_id) in self.project.split_same_ips_block_addrs.items():
                if split_block_id == node.block_id:
                    conc_state.globals["skip_same_ip_constant_prop"] = True

            sim_successors = engine.process(conc_state, opt_level=self._iropt_level, irsb=node.irsb)

            for succ in sim_successors.all_successors:
                for block_id, (same_ip, split_block_id) in self.project.split_same_ips_block_addrs.items():
                    if block_id == node.block_id:
                        import ipdb;ipdb.set_trace()
                        del succ.globals["skip_same_ip_constant_prop"]

            if node.is_simprocedure and node.name == "read":
                if not sim_successors.all_successors[0].solver.symbolic(sim_successors.all_successors[0].memory.load(read_buf_addr, read_buf_size)) and \
                        not sim_successors.all_successors[0].solver.symbolic(sim_successors.all_successors[0].regs.rax):
                    self.project.simprocedures_to_remove.add(node)

            # for my_succ in sim_successors.successors:
            #     if my_succ.solver.symbolic(my_succ.scratch.guard):
            #         for ast in my_succ.scratch.guard.leaf_asts():
            #             if ast.args[0] == "unconstrained_ret_CopyFileA_65_32":
            #                 import ipdb;ipdb.set_trace()
            # if PropagatorState.is_top(sim_successors.all_successors[0].regs.esp):
            #     import ipdb;ipdb.set_trace()
            # profiler.disable()
            # stats = pstats.Stats(profiler).sort_stats('tottime')
            #
            # if stats.total_tt > (60*5):
            #     stats.print_stats()
            #     import ipdb;
            #     ipdb.set_trace()

            # for connie in sim_successors.all_successors[0].solver.constraints:
            #     if connie.depth > 15:
            #         import ipdb;ipdb.set_trace()

            # for connie in sim_successors.all_successors[0].partial_symbolic_constraint_solver.constraints:
            #     if connie.depth > 15:
            #         for var in connie.variables:
            #             if var.startswith("mba") or var.startswith("TOP"):
            #                 import ipdb;ipdb.set_trace()
            #                 break

            l.debug("The length of the constraints is: "+str(len(conc_state.solver.constraints)))
            # if node.addr == 0x1400d2181 and node.block_id.vm_vpc == 5368833050:
            #     profiler.disable()
            #     stats = pstats.Stats(profiler).sort_stats('tottime')
            #     stats.print_stats()
            #     import ipdb;
            #     ipdb.set_trace()
            l.debug(sim_successors)

            if False:#node.is_simprocedure:
                if len(list(self._graph.successors(node))) > 1 and len(sim_successors.unconstrained_successors) > 0:
                    # create successors for the sim procedure since it is unconstrained because we are not emulating the sim procedures for constant prop
                    new_sim_successors = SimSuccessors(sim_successors.addr, sim_successors.initial_state)
                    new_sim_successors.artifacts = sim_successors.artifacts
                    new_sim_successors.engine = sim_successors.engine
                    new_sim_successors.processed = sim_successors.processed
                    new_sim_successors.description = sim_successors.description
                    new_sim_successors.sort = sim_successors.sort

                    for succ in self.graph.successors(node):
                        new_state = sim_successors.unconstrained_successors[0].copy()
                        new_state.regs.ip = claripy.BVV(succ.addr, new_state.arch.bits)
                        new_sim_successors.add_successor(new_state, succ.addr,
                                                         new_state.scratch.guard,
                                                         new_state.history.jumpkind, True,
                                                         new_state.scratch.exit_stmt_idx,
                                                         new_state.scratch.exit_ins_addr,
                                                         new_state.scratch.source)

                    sim_successors = new_sim_successors
                    sim_successors.artifacts['irsb_direct_next'] = True

                for succ in sim_successors.all_successors:
                    for graph_succ in self._graph.successors(node):
                        if succ.addr == graph_succ.addr:
                            succ.globals['cur_block_id'] = graph_succ.block_id

                symbolic_sim_successors = sim_successors

            else:
                split_same_ip_state = False
                if len(sim_successors.all_successors) == 1:
                    # # special check for VMProtect when conditional check but both jump targets are same, but we still have two unique VPCs, we now need to split into two states
                    # # and give them unique VPCs immediately
                    # for ast in sim_successors.all_successors[0].regs.ip.leaf_asts():
                    #     if isinstance(ast.args[0], str) and ast.args[0].startswith('mba_state_split_cond') and ast.args[
                    #         0] not in sim_successors.all_successors[0].globals['existing_mba_split_constraints']:
                    #         split_same_ip_state = True
                    #         break
                    #
                    # if split_same_ip_state:
                    #     try:
                    #         sim_successors.all_successors[0].partial_symbolic_constraint_solver.eval_one(
                    #             sim_successors.all_successors[0].regs.ip)
                    #         # check if it evaluates to one address only, if it does, we need to split the state
                    #     except:
                    #         # if evaluates to two address, the states are anyway going to split
                    #         split_same_ip_state = False

                    if node.block_id in self.project.split_same_ips_block_addrs:
                        import ipdb;ipdb.set_trace()
                        split_same_ip_state = True
                        new_states = []
                        cur_addr_mba = None
                        for addr_mba in self.project.load_addr_mba_to_jump_addr_mapping.keys():
                            cur_state_var = sim_successors.all_successors[0].globals['last_added_state_split_cond']
                            if cur_state_var is addr_mba.args[0]:
                                cur_addr_mba = addr_mba
                                break

                        if cur_addr_mba is not None:
                            for node_succ in self.graph.successors(node):
                                if node_succ.block_id.vm_vpc == cur_addr_mba.args[1].args[0]:
                                    new_state = sim_successors.all_successors[0].copy()
                                    new_state.partial_symbolic_constraint_solver.add(cur_state_var == True)
                                    new_state.globals['cur_block_id'] = node_succ.block_id

                                elif node_succ.block_id.vm_vpc == cur_addr_mba.args[2].args[0]:
                                    new_state = sim_successors.all_successors[0].copy()
                                    new_state.partial_symbolic_constraint_solver.add(cur_state_var == False)
                                    new_state.globals['cur_block_id'] = node_succ.block_id

                                new_states.append(new_state)

                            if len(new_states) != 0:
                                # import ipdb;ipdb.set_trace()
                                new_sim_successors = SimSuccessors(sim_successors.addr, sim_successors.initial_state)
                                new_sim_successors.artifacts = sim_successors.artifacts
                                new_sim_successors.engine = sim_successors.engine
                                new_sim_successors.processed = sim_successors.processed
                                new_sim_successors.description = sim_successors.description
                                new_sim_successors.sort = sim_successors.sort
                                for new_state in new_states:
                                    new_sim_successors.add_successor(new_state,
                                                                     new_state.solver.eval(new_state.scratch.target),
                                                                     new_state.scratch.guard,
                                                                     new_state.history.jumpkind, True,
                                                                     new_state.scratch.exit_stmt_idx,
                                                                     new_state.scratch.exit_ins_addr,
                                                                     new_state.scratch.source)
                                sim_successors = new_sim_successors
                                sim_successors.artifacts['irsb_direct_next'] = True

                if (len(sim_successors.unconstrained_successors) == 1 and len(sim_successors.successors) == 0 and len(list(self.graph.successors(node))) !=0):# or split_same_ip_state:

                    new_states = []
                    uncon_succ = sim_successors.unconstrained_successors[0]
                    #poss_target = uncon_succ.partial_symbolic_constraint_solver._solver._replacement(uncon_succ.regs.ip)
                    poss_target = uncon_succ.regs.ip

                    try:
                        poss_target = uncon_succ.partial_symbolic_constraint_solver.eval_one(uncon_succ.regs.ip)
                    except:
                        l.debug("more than one target?, possible going to split states now")

                    # if the ip has become top then just replace with successor ip
                    if uncon_succ.solver.symbolic(poss_target) and PropagatorState.is_top(uncon_succ.regs.ip):
                        if len(list(self._graph.successors(node))) == 1:
                            # import ipdb;ipdb.set_trace()
                            uncon_succ.regs.ip = list(self._graph.successors(node))[0].addr
                            uncon_succ.scratch.target = uncon_succ.regs.ip
                        else:
                            l.debug("TOP ip and more than one successor..... create more than once successors")
                            import ipdb;ipdb.set_trace()

                    # if it's till symbolic try to eval with the partial constraint solver
                    #if uncon_succ.solver.symbolic(poss_target):

                   # poss_target = uncon_succ.solver.simplify(uncon_succ.scratch.target).replace_dict(uncon_succ.solver._solver._replacement_cache)

                    if not uncon_succ.solver.symbolic(poss_target):
                        #import ipdb;ipdb.set_trace()
                        new_sim_successors = SimSuccessors(sim_successors.addr, sim_successors.initial_state)
                        new_sim_successors.artifacts = sim_successors.artifacts
                        new_sim_successors.engine = sim_successors.engine
                        new_sim_successors.processed = sim_successors.processed
                        new_sim_successors.description = sim_successors.description
                        new_sim_successors.sort = sim_successors.sort

                        uncon_succ.regs.ip = poss_target

                        new_sim_successors.add_successor(uncon_succ, uncon_succ.partial_symbolic_constraint_solver.eval_one(uncon_succ.scratch.target),
                                                         uncon_succ.scratch.guard,
                                                         uncon_succ.history.jumpkind, True,
                                                         uncon_succ.scratch.exit_stmt_idx,
                                                         uncon_succ.scratch.exit_ins_addr,
                                                         uncon_succ.scratch.source)

                        sim_successors = new_sim_successors
                        sim_successors.artifacts['irsb_direct_next'] = True


                    else:
                        repl_ip= sim_successors.all_successors[0].partial_symbolic_constraint_solver._solver._replacement(sim_successors.all_successors[0].regs.ip)

                        state_var_ast = []
                        for ast in repl_ip.leaf_asts():
                            if isinstance(ast.args[0], str) and ast.args[0].startswith('mba_state_split_cond') and ast.args[0] not in sim_successors.all_successors[0].globals['existing_mba_split_constraints']:
                                state_var_ast.append(ast)
                            elif isinstance(ast.args[0], str) and ast.args[0].startswith('switch_case_table') and ast.args[0] not in sim_successors.all_successors[0].globals['existing_mba_split_constraints']:
                                state_var_ast.append(ast)
                                import ipdb;ipdb.set_trace()

                        # if len(state_var_ast) != 1:
                        #     import ipdb;ipdb.set_trace()

                        if len(state_var_ast) > 0:
                            # state_var_ast = state_var_ast[0]

                            state_var_ast = sim_successors.all_successors[0].globals['last_added_state_split_cond']

                            sim_successors.all_successors[0].globals['last_added_state_split_cond'] = None

                            sim_successors.all_successors[0].globals['existing_mba_split_constraints'].append(state_var_ast.args[0])

                            try:
                                # This eval result is not added to repalcements even though unsafe replacements is turned on number of solns must be only one
                                solns = sim_successors.unconstrained_successors[0].partial_symbolic_constraint_solver._solver.batch_eval([sim_successors.unconstrained_successors[0].regs.ip, state_var_ast], 5)
                                # This batch eval for switch case variable needs work, right now it doesn't always give all
                                # possible jump targets due to the way the switch case variable is constructed with the if-else-then.
                                # the default case ends up in too many of the batch eval solns
                            except:
                                import ipdb;ipdb.set_trace()

                            if len(solns) > 2:
                                import ipdb;ipdb.set_trace()

                            cur_addr_mba = None
                            for addr_mba in self.project.load_addr_mba_to_jump_addr_mapping.keys():
                                if addr_mba.args[0] is state_var_ast:
                                    cur_addr_mba = addr_mba
                                    for soln in solns:
                                        if soln[1] is True:
                                            ## tuple of (mba_state_var, jumpaddress, loadaddress)
                                            self.project.load_addr_mba_to_jump_addr_mapping[addr_mba].append(
                                                (True, soln[0], addr_mba.args[1].args[0]))
                                        elif soln[1] is False:
                                            ## tuple of (mba_state_var, jumpaddress, loadaddress)
                                            self.project.load_addr_mba_to_jump_addr_mapping[addr_mba].append(
                                                (False, soln[0], addr_mba.args[2].args[0]))

                            for soln_pair in solns:
                                new_state = sim_successors.unconstrained_successors[0].copy()


                                new_state.partial_symbolic_constraint_solver.add(state_var_ast == soln_pair[1])

                                for reg in new_state.arch.registers.keys():
                                    offset = new_state.arch.registers[reg][0]
                                    size = new_state.arch.registers[reg][1]
                                    old_val = new_state.registers.load(offset, size)
                                    if new_state.solver.symbolic(old_val):
                                        is_sp = False
                                        for var in old_val.variables:
                                            if var.startswith("precon_sp"):
                                                is_sp = True
                                        if not is_sp:
                                            try:
                                                new_val = new_state.partial_symbolic_constraint_solver.eval_one(old_val)
                                                new_val = claripy.BVV(new_val, size*self.project.arch.byte_width)
                                                new_state.registers.store(offset, new_val)
                                            except:
                                                pass

                                # we are doing eval_one because only when one soln exists unsafe replacements will happen

                                k= new_state.partial_symbolic_constraint_solver.eval_one(new_state.partial_symbolic_constraint_solver._solver._replacement(new_state.regs.ip))

                                new_state.regs.ip = new_state.partial_symbolic_constraint_solver.eval_one(new_state.regs.ip)
                                new_state.scratch.target = new_state.partial_symbolic_constraint_solver.eval_one(new_state.scratch.target)



                                # Fill the block id
                                for node_succ in self.graph.successors(node):
                                    try:
                                        if new_state.solver.eval_one(new_state.regs.ip) == node_succ.addr:
                                            new_state.globals['cur_block_id'] = node_succ.block_id
                                    except:
                                        l.debug("failed to set cur block id")
                                        import ipdb;
                                        ipdb.set_trace()

                                new_states.append(new_state)
                                # import ipdb;ipdb.set_trace()
                        else:
                            new_sim_successors = SimSuccessors(sim_successors.addr, sim_successors.initial_state)
                            new_sim_successors.artifacts = sim_successors.artifacts
                            new_sim_successors.engine = sim_successors.engine
                            new_sim_successors.processed = sim_successors.processed
                            new_sim_successors.description = sim_successors.description
                            new_sim_successors.sort = sim_successors.sort

                            assert len(list(self.graph.successors(node))) == 1

                            uncon_succ.regs.ip = list(self.graph.successors(node))[0].addr

                            new_sim_successors.add_successor(uncon_succ, list(self.graph.successors(node))[0].addr,
                                                             uncon_succ.scratch.guard,
                                                             uncon_succ.history.jumpkind, True,
                                                             uncon_succ.scratch.exit_stmt_idx,
                                                             uncon_succ.scratch.exit_ins_addr,
                                                             uncon_succ.scratch.source)

                            sim_successors = new_sim_successors
                            sim_successors.artifacts['irsb_direct_next'] = True


                        # for ast in sim_successors.unconstrained_successors[0].regs.ip.leaf_asts():
                        #     if ast in sim_successors.unconstrained_successors[0].globals['concretized_load_addr_dict']:
                        #         conc_addr_and_new_constraints = sim_successors.unconstrained_successors[0].globals['concretized_load_addr_dict'][ast][0]
                        #         if len(conc_addr_and_new_constraints) > 2:
                        #             print("More than two possible jumps? is this not a direct jump converted to an indirect jump?")
                        #             import ipdb;ipdb.set_trace()
                        #         for conc_addr, input_constraints, loaded_value_constraint in conc_addr_and_new_constraints:
                        #             sym_addr = sim_successors.unconstrained_successors[0].globals['concretized_load_addr_dict'][ast][2]
                        #             size = sim_successors.unconstrained_successors[0].globals['concretized_load_addr_dict'][ast][1]
                        #             new_state = sim_successors.unconstrained_successors[0].copy()
                        #
                        #
                        #             new_state.partial_symbolic_constraint_solver._solver.add_replacement(sym_addr, conc_addr, invalidate_cache=False)
                        #             new_state.partial_symbolic_constraint_solver.add(loaded_value_constraint)
                        #
                        #             if new_state.solver.symbolic(new_state.regs.ip):
                        #                 try:
                        #                     new_state.regs.ip = new_state.partial_symbolic_constraint_solver.eval_one(
                        #                         new_state.regs.ip)
                        #                 except:
                        #                     import ipdb;
                        #                     ipdb.set_trace()
                        #             if new_state.solver.symbolic(new_state.scratch.target):
                        #                 try:
                        #                     new_state.scratch.target = new_state.partial_symbolic_constraint_solver.eval_one(
                        #                         new_state.scratch.target)
                        #                 except:
                        #                     import ipdb;
                        #                     ipdb.set_trace()
                        #
                        #
                        #             # Fill the block id
                        #             for node_succ in self.graph.successors(node):
                        #                 try:
                        #                     if new_state.solver.eval_one(new_state.regs.ip) == node_succ.addr:
                        #                         new_state.globals['cur_block_id'] = node_succ.block_id
                        #                 except:
                        #                     print("failed to set cur block id")
                        #                     import ipdb;
                        #                     ipdb.set_trace()
                        #
                        #             new_states.append(new_state)

                        if len(new_states) != 0:
                            #import ipdb;ipdb.set_trace()
                            new_sim_successors = SimSuccessors(sim_successors.addr, sim_successors.initial_state)
                            new_sim_successors.artifacts = sim_successors.artifacts
                            new_sim_successors.engine = sim_successors.engine
                            new_sim_successors.processed = sim_successors.processed
                            new_sim_successors.description = sim_successors.description
                            new_sim_successors.sort = sim_successors.sort
                            for new_state in new_states:
                                new_sim_successors.add_successor(new_state, new_state.solver.eval(new_state.scratch.target), new_state.scratch.guard,
                                                                          new_state.history.jumpkind, True,
                                                                          new_state.scratch.exit_stmt_idx,
                                                                          new_state.scratch.exit_ins_addr,
                                                                          new_state.scratch.source)
                            sim_successors=new_sim_successors
                            sim_successors.artifacts['irsb_direct_next'] = True

                elif (len(sim_successors.unconstrained_successors) == 1 and len(sim_successors.all_successors) != 1) or len(sim_successors.unconstrained_successors) > 1:
                    handled_mixed_successors = False

                    if len(sim_successors.unconstrained_successors) == 1 and len(sim_successors.successors) == 1:
                        uncon_succ = sim_successors.unconstrained_successors[0]
                        normal_succ = sim_successors.successors[0]
                        graph_succ_addrs = {graph_succ.addr for graph_succ in self._graph.successors(node)}

                        matched_successors = []
                        if normal_succ.addr in graph_succ_addrs:
                            matched_successors.append((normal_succ, normal_succ.addr))

                        try:
                            resolved_target = uncon_succ.partial_symbolic_constraint_solver.eval_one(uncon_succ.regs.ip)
                            if resolved_target in graph_succ_addrs:
                                uncon_succ.regs.ip = resolved_target
                                uncon_succ.scratch.target = resolved_target
                                matched_successors.append((uncon_succ, resolved_target))
                        except:
                            pass

                        if len(matched_successors) != 0:
                            new_sim_successors = SimSuccessors(sim_successors.addr, sim_successors.initial_state)
                            new_sim_successors.artifacts = sim_successors.artifacts
                            new_sim_successors.engine = sim_successors.engine
                            new_sim_successors.processed = sim_successors.processed
                            new_sim_successors.description = sim_successors.description
                            new_sim_successors.sort = sim_successors.sort

                            for matched_succ, target in matched_successors:
                                new_sim_successors.add_successor(
                                    matched_succ,
                                    target,
                                    matched_succ.scratch.guard,
                                    matched_succ.history.jumpkind,
                                    True,
                                    matched_succ.scratch.exit_stmt_idx,
                                    matched_succ.scratch.exit_ins_addr,
                                    matched_succ.scratch.source,
                                )

                            sim_successors = new_sim_successors
                            sim_successors.artifacts['irsb_direct_next'] = True
                            handled_mixed_successors = True

                    if not handled_mixed_successors:
                        l.debug("More than one unconstrained successor?!")
                        import ipdb;ipdb.set_trace()

                if not split_same_ip_state:
                    for succ in sim_successors.all_successors:
                        for graph_succ in self._graph.successors(node):
                            if succ.addr == graph_succ.addr:
                                succ.globals['cur_block_id'] = graph_succ.block_id

                symbolic_sim_successors = sim_successors

                if len(sim_successors.all_successors) >1:
                    l.debug("Before:removing succs")
                    l.debug(sim_successors.all_successors)
                    symbolic_sim_successors = SimSuccessors(sim_successors.addr, sim_successors.initial_state)
                    symbolic_sim_successors.artifacts = sim_successors.artifacts
                    symbolic_sim_successors.engine = sim_successors.engine
                    symbolic_sim_successors.processed = sim_successors.processed
                    symbolic_sim_successors.description = sim_successors.description
                    symbolic_sim_successors.sort = sim_successors.sort

                    ## Only keep those successors that are already in the cfg
                    for successor in sim_successors.all_successors:
                        keep=False
                        for graph_succ in self._graph.successors(node):
                            if successor.addr == graph_succ.addr:
                                keep=True

                        if keep:
                            if successor.solver.symbolic(successor.scratch.guard):
                                # special case to deal with preconstrained sp related guards
                                if len(list(successor.scratch.guard.variables)) == 1 and \
                                        list(successor.scratch.guard.variables)[0].startswith("precon_sp"):
                                    try:
                                        if successor.solver.eval(successor.scratch.guard):
                                            symbolic_sim_successors.add_successor(successor, successor.scratch.target,
                                                                                  successor.scratch.guard,
                                                                                  successor.history.jumpkind, True,
                                                                                  successor.scratch.exit_stmt_idx,
                                                                                  successor.scratch.exit_ins_addr,
                                                                                  successor.scratch.source)
                                    except SimUnsatError:
                                        print("Hmmmmmmmmmmm")
                                        import ipdb;
                                        ipdb.set_trace()
                                else:
                                    # this is so that we do not keep the newly discovered from previous iter of symbolizer, since in the first iteration it's still Unsat(for loops)
                                    # we will keep these branches once the guards become TOP after n iterations
                                    try:
                                        if successor.partial_symbolic_constraint_solver.eval_one(successor.scratch.guard):
                                            symbolic_sim_successors.add_successor(successor, successor.scratch.target,
                                                                                  successor.scratch.guard,
                                                                                  successor.history.jumpkind, True,
                                                                                  successor.scratch.exit_stmt_idx,
                                                                                  successor.scratch.exit_ins_addr,
                                                                                  successor.scratch.source)
                                    except SimUnsatError:
                                        print("Drop this for now, we'll get it later.... after some merging causes TOPs")
                                    except claripy.UnsatError:
                                        pass
                                    except SimSolverError:
                                        symbolic_sim_successors.add_successor(successor, successor.scratch.target,
                                                                              successor.scratch.guard,
                                                                              successor.history.jumpkind, True,
                                                                              successor.scratch.exit_stmt_idx,
                                                                              successor.scratch.exit_ins_addr,
                                                                              successor.scratch.source)
                                    except Exception as e:
                                        symbolic_sim_successors.add_successor(successor, successor.scratch.target,
                                                                              successor.scratch.guard,
                                                                              successor.history.jumpkind, True,
                                                                              successor.scratch.exit_stmt_idx,
                                                                              successor.scratch.exit_ins_addr,
                                                                              successor.scratch.source)


                            elif successor.scratch.guard.is_true():
                                # only adding successors that are non-symbolic and true guard
                                symbolic_sim_successors.add_successor(successor, successor.scratch.target,
                                                                      successor.scratch.guard,
                                                                      successor.history.jumpkind, True,
                                                                      successor.scratch.exit_stmt_idx,
                                                                      successor.scratch.exit_ins_addr,
                                                                      successor.scratch.source)


            break_flag = True
            for succ in symbolic_sim_successors.all_successors:
                for graph_succ in self._graph.successors(node):
                    if succ.addr == graph_succ.addr:
                        break_flag = False

            if break_flag and len(list(self._graph.successors(node))) != 0:
                import ipdb;ipdb.set_trace()

            # If we don't do this it won't free the memory..... prolly due to cyclic references
            conc_state.globals['abstract_state'] = None
            for succ in symbolic_sim_successors.all_successors:
                succ.globals['abstract_state'] = None
            # node.input_state.globals['cur_block_id'] = block_key

            #self._merge_replacements(self.replacements, abstract_state._replacements)

            for succ in symbolic_sim_successors.all_successors:
                # all_successors[succ.regs.ip].append(succ)
                all_successors[succ.globals['cur_block_id']].append(succ)


            prev_abstract_state = None

            # if not changed:
            #     if block_key in self._states and self._states[block_key]:
            #         prev_abstract_state = self._states[block_key]
            #         # the comparision order matters
            #         changed = self._changed(prev_abstract_state._replacements, abstract_state._replacements)
            #     else:
            #         # It's the first time exploring this node
            #         changed = True
            #
            # if changed is False:
            #     merge_res = self._merge_replacements(self.replacements, abstract_state._replacements)

            # for succ in symbolic_sim_successors.all_successors:
            #     all_successors[succ.regs.ip].append(succ)

        l.debug("replacemtns: "+str(len(self.replacements)))
        l.debug("symb locs: "+str(len(self.symbolic_expr_locations)))

        #trying to merge same addr successors, this is part of the late mergning strategy
        merged_state_collection = []
        for addr, states in all_successors.items():
            if len(states) > 2:
                import ipdb;ipdb.set_trace()

            elif len(states) == 2:
                if states[0].solver.eval_one(states[0].regs.sp) == states[1].solver.eval_one(states[1].regs.sp) and not split_same_ip_state:
                    states[0].globals['orig_state_copy'] = states[0].copy()
                    states[1].globals['orig_state_copy'] = states[1].copy()
                    merged_stuff = states[0].merge(states[1],
                                                plugin_whitelist=['inspect', 'preconstrainer', 'globals', 'mem', 'heap',
                                                                  'regs', 'solver', 'callstack', 'history', 'fs', 'scratch',
                                                                  'memory', 'registers', 'libc',
                                                                  'partial_symbolic_constraint_solver'])
                    states[0].globals['orig_state_copy'] = None
                    states[1].globals['orig_state_copy'] = None
                    merged_stuff[0].globals['orig_state_copy'] = None
                    merged_stuff[0].globals["same_sp_merged"] = True

                    merged_state_collection.append(merged_stuff[0])

                else:
                    merged_state_collection = merged_state_collection + states
            else:
                merged_state_collection = merged_state_collection + states

        #node.final_states = symbolic_sim_successors
        abstract_state.concrete_states = merged_state_collection
        self._node_iterations[block_key] += 1
        # this stores the last merged/normal state
        #self.replacements[block_key] = abstract_state._replacements

        l.debug(self._node_iterations[block_key])

        # if node.block_id in self._states and len(list(self.graph.predecessors(node))) > 1:
        #     changed = self.compare_concrete_states(abstract_state, self._states[node.block_id])
        # else:
        #     changed = True

        self._states[block_key] = abstract_state

        return True, abstract_state

        # if changed:
        #     return True, abstract_state
        # else:
        #     return False, abstract_state

    def compare_concrete_states(self, conc_state0, conc_state1):
        changed = False

        # if len(conc_state1.concrete_states) == len(conc_state0.concrete_states) and len(conc_state1.concrete_states) == 1:
        all_plugins = set(conc_state1.plugins.keys())
        for p in all_plugins:
            if p in ["memory","registers"]:
                plugin0 = conc_state0.plugins[p]
                plugin1 = conc_state1.plugins[p]
                changed_pages = self.changed_pages(plugin1, plugin0)
                if len(changed_pages) != 0:
                    return True

        return changed

    def changed_pages(self,plugin0, plugin1):
        my_pages = set(plugin0._pages)
        other_pages = set(plugin1._pages)
        intersection = my_pages.intersection(other_pages)
        difference = my_pages.symmetric_difference(other_pages)
        changes= {d: None for d in difference}

        for pageno in intersection:
            my_page = plugin0._pages[pageno]
            other_page = plugin1._pages[pageno]

            if (my_page is None) ^ (other_page is None):
                changes[pageno] = None
            elif my_page is None:
                pass
            elif my_page is other_page:
                pass
            else:
                changed_offsets = self.changed_bytes(my_page, other_page, page_addr=pageno * plugin0.page_size)
                if changed_offsets:
                    changes[pageno] = changed_offsets

        return changes

    def changed_bytes(self, cur_page, other: "ListPage", page_addr: int = None):
        candidates = None
        if candidates is None:
            candidates = set()
            if cur_page.sinkhole is None:
                candidates |= cur_page.stored_offset
            else:
                for i in range(len(cur_page.content)):
                    if cur_page._contains(i, page_addr):
                        candidates.add(i)

            if other.sinkhole is None:
                candidates |= other.stored_offset
            else:
                for i in range(len(other.content)):
                    if other._contains(i, page_addr):
                        candidates.add(i)

        byte_width = 8  # TODO: Introduce self.state if we want to use self.state.arch.byte_width
        differences = set()
        for c in candidates:
            s_contains = cur_page._contains(c, page_addr)
            o_contains = other._contains(c, page_addr)
            if not s_contains and o_contains:
                differences.add(c)
            elif s_contains and not o_contains:
                differences.add(c)
            else:
                if cur_page.content[c] is None:
                    cur_page.content[c] = SimMemoryObject(
                        cur_page.sinkhole.bytes_at(page_addr + c, 1),
                        page_addr + c,
                        byte_width=byte_width,
                        endness="Iend_BE",
                    )
                if other.content[c] is None:

                    other.content[c] = SimMemoryObject(
                        other.sinkhole.bytes_at(page_addr + c, 1),
                        page_addr + c,
                        byte_width=byte_width,
                        endness="Iend_BE",
                    )

                if s_contains and cur_page.content[c] != other.content[c]:
                    same = None
                    if self._mo_cmp is not None:
                        same = self._mo_cmp(cur_page.content[c], other.content[c], page_addr + c, 1)
                    # if same is None:
                    #     # Try to see if the bytes are equal
                    #     self_byte = cur_page.content[c].bytes_at(page_addr + c, 1)
                    #     other_byte = other.content[c].bytes_at(page_addr + c, 1)
                    # #    same = self_byte is other_byte
                    # # Ashwin added this to remove the problem that arises from comparing same valued asts with different(only hash is different) annotations
                    #     if not (self_byte == other_byte).is_true():
                    #         differences.add(c)

                    if same is False:
                        differences.add(c)
                else:
                    # this means the byte is in neither memory
                    pass

        return differences

    def _changed(self, replacements_0, replacements_1):
        return not(replacements_1 == replacements_0)
        # for loc, vars_ in replacements_1.items():
        #     if loc not in replacements_0:
        #         return True
        #     else:
        #         for var, repl in vars_.items():
        #             if var not in replacements_0[loc]:
        #                 return True
        #             else:
        #                 if PropagatorState.is_top(repl) and PropagatorState.is_top(replacements_0[loc][var]):
        #                     continue
        #                 elif PropagatorState.is_top(repl) or PropagatorState.is_top(replacements_0[loc][var]):
        #                     return True
        #
        #                 elif replacements_0[loc][var].con.value != repl.con.value:
        #                     return True
        #
        # return False

    def _merge_replacements(self, replacements_0, replacements_1):
        merge_occurred = False
        for loc, vars_ in replacements_1.items():
            if loc not in replacements_0:
                replacements_0[loc] = vars_.copy()
                merge_occurred = True
            else:
                for var, repl in vars_.items():
                    if var not in replacements_0[loc]:
                        replacements_0[loc][var] = repl
                        merge_occurred = True
                    else:
                        if self.is_top_str(repl) and self.is_top_str(replacements_0[loc][var]):
                            continue
                        elif self.is_top_str(repl) or self.is_top_str(replacements_0[loc][var]):
                            replacements_0[loc][var] = "TOP"
                            merge_occurred = True

                        elif replacements_0[loc][var].con.value != repl.con.value:
                            replacements_0[loc][var] = "TOP"
                            merge_occurred = True

        return merge_occurred

    def is_top_str(self, repl):
        if isinstance(repl, str) and repl == "TOP":
            return True
        return False


    def _intra_analysis(self):
        pass

    def _post_analysis(self):
        pass

register_analysis(Symbolizer, "Symbolizer")
