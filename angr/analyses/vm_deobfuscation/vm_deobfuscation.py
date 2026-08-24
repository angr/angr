import ipdb
import networkx
from functools import wraps
import time
import objgraph
import tracemalloc
import angr
from angr.procedures.definitions import msvcr as msvcr_defs
from angr.utils.graph import as_networkx
from angr.analyses.cfg.vm_cfg_model import VMCFGModel
import logging
import pyvex
import claripy
import networkx as nx
import re
import copy
import os
import pickle

from pathlib import Path

from collections import defaultdict, OrderedDict, Counter
from angr.code_location import CodeLocation, ExternalCodeLocation
from angr.engines import UberEngine
from angr.analyses.reaching_definitions.function_handler import FunctionHandler
from angr.analyses.reaching_definitions.subject import Subject
from angr.knowledge_plugins.cfg.cfg_node import CFGENode
from angr.knowledge_plugins.key_definitions.atoms import Tmp, Register, MemoryLocation
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER, ObservationPointType
from angr.errors import SimMemoryMissingError
from pyvex.expr import DataSensitiveRdTmp
from pyvex.const import U64, U32

from ...state_plugins import SimSolver
from ...engines.vex import TrackActionsMixin, SimInspectMixin, HeavyResilienceMixin, SuperFastpathMixin
from ...engines.unicorn import SimEngineUnicorn
from ...engines.failure import SimEngineFailure
from ...engines.syscall import SimEngineSyscall
from ...engines.hook import HooksMixin
from ...engines.soot import SootMixin
from ...engines import HeavyVEXMixin

from angr.knowledge_plugins.cfg.block_id import BlockID
from ..reaching_definitions.dep_graph import DepGraph
from ..analysis import Analysis
from ..cfg.cfg_vm_deobfuscation import StackPointerAnnotation, StackTouchedAnnotation, DataRegionAnnotation, annotate_with_new_replacements, VMStackVariableAnnotation
from angr.state_plugins.inspect import BP, BP_AFTER, BP_BEFORE
from angr import state_plugins
from ...knowledge_plugins import Function
from ...knowledge_plugins.key_definitions import atoms
from ...engines.light.data import SpOffset
from ...storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from ...utils.constants import DEFAULT_STATEMENT

from .pretty_dump_ail_cfg import pretty_dump_ail_cfg
to_break = False
#logger = logging.getLogger('angr.analyses.cfg.cfg_vm_deobfuscation').setLevel(logging.DEBUG)
#filename = "/media/sf_Security/sample_vm/sample_vm_with_input"
#filename = "/media/sf_Security/sample_vm/a.out"
filename = "/media/sf_Security/sample_vm/simple_vm_set/sample_vm_with_input/samplevm_with_input"
#filename = "/media/sf_Security/sample_vm/simple_vm_set/sample_vm_with_two_input/samplevm_with_two_input"
#filename = "/media/sf_Security/sample_vm/simple_vm_set/sample_vm_with_input_loop/samplevm_with_input_loop"
#filename = "/media/sf_Security/sample_vm/sample_vm_with_input_depend_branch"
#filename="/media/sf_Security/sample_vm/tigress-challenges/Linux-x86_64/0000/challenge-0"
l = logging.getLogger(name=__name__)

TIMING = True

class AndingSimSolver(SimSolver):
    def merge(self, others, merge_conditions, common_ancestor=None):  # pylint: disable=W0613
        # Start from our current constraints

        fast_exact = claripy.solvers.SolverCacheless(track=False, timeout=1200000)

        repl = claripy.solvers.SolverReplacement(
            actual_frontend=fast_exact,
            unsafe_replacement=True,
            auto_replace=False,
        )
        merged_frontend = repl

        cons_dict = defaultdict(list)
        general_constraints = []
        for cons in self.constraints:
            if len(cons.variables) == 1 and list(cons.variables)[0].startswith("mba_state_split_cond"):
                cons_dict[list(cons.variables)[0]].append(cons)
            else:
                general_constraints.append(cons)

        for o in others:
            for cons in o.constraints:
                if len(cons.variables) == 1 and list(cons.variables)[0].startswith("mba_state_split_cond"):
                    cons_dict[list(cons.variables)[0]].append(cons)
                else:
                    general_constraints.append(cons)


        for var, cons in cons_dict.items():
            if len(cons) == 2:
                merged_frontend.add(cons[0] | cons[1])
            elif len(cons) == 1:
                merged_frontend.add(cons[0])
            elif len(cons) > 2:
                import ipdb;ipdb.set_trace()

        for con in general_constraints:
            merged_frontend.add(con)

        for other in others:
            for var, val in other._solver._replacements.items():
                merged_frontend.add_replacement(var.ast, val)

        for var, val in self._solver._replacements.items():
            merged_frontend.add_replacement(var.ast, val)

        # Store and report
        self._stored_solver = merged_frontend
        return True

class DataSensitiveU64(pyvex.const.U64):
    def __init__(self, value, block_id):
        super(DataSensitiveU64, self).__init__(value)
        self.block_id = block_id


class DataSensitiveU32(pyvex.const.U32):
    def __init__(self, value, block_id):
        super(DataSensitiveU32, self).__init__(value)
        self.block_id = block_id



class IndSensitiveCodeLocation(CodeLocation):
    def __init__(self, block_addr: int, stmt_idx: int, ins_ind=None, sim_procedure=None, ins_addr=None,
                 context=None, block_idx=None, block_id=None, **kwargs):
        super(IndSensitiveCodeLocation, self).__init__(block_addr, stmt_idx, sim_procedure, ins_addr,
                 context, block_idx, block_id, **kwargs)
        self.ins_ind = ins_ind


class StatementNode:
    def __init__(self, stmt, codeloc=None, def_atom=None):
        # codeloc can be none for new modified statements
        self.stmt = stmt
        self.codeloc = codeloc

        #definition_atom
        self.def_atom = def_atom

    def __repr__(self):
        return f"<Statement:{self.stmt} Codeloc:{self.codeloc} Atom:{self.def_atom}>"

    def __eq__(self, other):
        return self.stmt == other.stmt and self.codeloc == other.codeloc and self.def_atom == other.def_atom

    def __hash__(self):
        return hash((self.stmt, self.codeloc, self.def_atom))

class StatementGraph:
    def __init__(self, graph=None):
        if graph is None:
            self._graph = nx.DiGraph()
        else:
            self._graph = graph
        self.simplified_asts = {}

    @property
    def graph(self):
        return self._graph

    def add_edge(self, src_node, dst_node, **labels):
        self._graph.add_edge(src_node, dst_node, **labels)

    def add_node(self, node):
        self._graph.add_node(node)

    def nodes(self):
        return self._graph.nodes()

    def subgraph(self, nodes):
        return self._graph.subgraph(nodes)

# class InputConcretizeEngine(SimEngineFailure, SimEngineSyscall, HooksMixin, SimEngineUnicorn, SuperFastpathMixin,
#                                TrackActionsMixin, SimInspectMixin, HeavyResilienceMixin, SootMixin, HeavyVEXMixin):
class InputConcretizeEngine(SimEngineFailure, SimEngineSyscall, HooksMixin, SimEngineUnicorn, SuperFastpathMixin,
                            SimInspectMixin, HeavyResilienceMixin, SootMixin, HeavyVEXMixin):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _handle_vex_expr_DataSensitiveRdTmp(self, expr):
        return self._handle_vex_expr_RdTmp(expr)

    def _handle_vex_expr_Load(self, expr: pyvex.expr.Load):
        return self._perform_vex_expr_Load(self._analyze_vex_expr_Load_addr(expr.addr), expr.ty, expr.end, expr=expr)

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
            except:
                pass

        result = super()._perform_vex_expr_Load(simplified_addr, ty, endness, **kwargs)


        if 'vm_graph_exploration' in self.state.globals and self.state.globals['vm_graph_exploration'] and \
                'use_mem_vpc_finder' in self.state.globals and self.state.globals['use_mem_vpc_finder'] and \
                not self.state.globals['mem_vpc_bp_set'] and \
                not result.symbolic and \
                self.state.project.loader.main_object.contains_addr(self.state.partial_symbolic_constraint_solver.eval_one(result)) and \
                self.state.project.loader.main_object.contains_addr(self.state.partial_symbolic_constraint_solver.eval_one(simplified_addr)):
            addr = self.state.partial_symbolic_constraint_solver.eval_one(result)
            bl=self.state.block()
            dis = bl.disassembly
            mnemonic = dis.insns[bl.instruction_addrs.index(self.state.scratch.ins_addr)].mnemonic
            if mnemonic == "mov":
                print("VPC loc: "+str(hex(simplified_addr.args[0])))
                self.state.inspect.add_breakpoint('mem_write',
                                                   BP(BP_AFTER, mem_write_address=simplified_addr, action=save_vpc_at_mem_loc))
                self.state.globals['mem_vpc_bp_set'] = True

        if not self.state.solver.symbolic(simplified_addr):
            return result

        save = False
        var_ast_list = []

        if self.state.solver.symbolic(simplified_addr):
            conc_addrs = self.state.partial_symbolic_constraint_solver.eval_upto(simplified_addr, 3)
            ast_addrs = []
            for con_addr in conc_addrs:
                ast_addrs.append(claripy.BVV(con_addr, addr.size()))

            conc_addrs = ast_addrs

            if len(conc_addrs) <= 3:
                save = True

        if len(var_ast_list) > 1:
            print("More than one variables? which one to save.... maybe both")
            #import ipdb;ipdb.set_trace()


        if save:
            if len(conc_addrs) > 2 and len(simplified_addr.variables) == 1 and list(simplified_addr.variables)[0].startswith('switch_case_table'):
                # loading different vip values based on the switch case jump table

                switch_case_var = None
                for ast in simplified_addr.leaf_asts():
                    if isinstance(ast.args[0], str) and ast.args[0].startswith('switch_case_table'):
                        switch_case_var = ast
                #conc_addrs = self.state.partial_symbolic_constraint_solver.eval_upto(simplified_addr, 8)
                solns = self.state.partial_symbolic_constraint_solver._solver.batch_eval([simplified_addr, switch_case_var], 8)
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
                for i in range(len(solns_dict)-1):
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

                return final_cond

            # elif len(conc_addrs) > 2:
            #     # jump table for switch case
            #     sec = self.project.loader.main_object.find_section_containing(conc_addrs[0].args[0])
            #     if not sec:
            #         return result
            #     elif (sec.name.startswith('.rdata') or sec.name.startswith('.data')):
            #         return result
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
            #         if loaded_value.concrete and self.state.project.loader.main_object.contains_addr(loaded_value.concrete_value):
            #             loaded_values.append(loaded_value)
            #
            #     no_bits = len(bin(len(loaded_values)))-2
            #     indirect_jump_var = claripy.BVS('switch_case_table', no_bits)
            #     final_cond = loaded_values[-1]
            #     for idx, loaded_value in enumerate(loaded_values[:-1]):
            #         final_cond = claripy.If(indirect_jump_var == idx, loaded_value, final_cond)
            #
            #
            #     return final_cond


            elif len(conc_addrs) == 2 and self.state.scratch.ins_addr not in self.project.bt_ins_addrs:# and self.state.block(self.state.scratch.ins_addr).disassembly.insns[0].mnemonic.startswith("mov"):
                loaded_values = []
                for conc_addr in conc_addrs:
                    loaded_value = self.state.memory.load(conc_addr, self._ty_to_bytes(ty),
                                                          endness=self.state.arch.memory_endness)
                    loaded_values.append(loaded_value)
                # if len(simplified_addr.variables) == 2:
                #     is_mba_addr_1 = False
                #     is_mba_addr_2 = False
                #     for var in simplified_addr.variables:
                #         if var.startswith('mba_state_split_cond'):
                #             is_mba_addr_1 = True
                #         elif var.startswith('precon_sp'):
                #             is_mba_addr_2 = True
                #     if is_mba_addr_2 and is_mba_addr_1:
                #         print("experimental")
                #         import ipdb;ipdb.set_trace()

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
                    # for ast in list(simplified_addr.leaf_asts()):
                    #     if ast.symbolic:
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
                if state_split_cond.args[0].startswith("mba_state_split_cond_1096_-1") or state_split_cond.args[0].startswith("mba_state_split_cond_1092_-1") or  state_split_cond.args[0].startswith("mba_state_split_cond_1094_-1"):
                    import ipdb;ipdb.set_trace()
                # if state_split_cond.args[0].startswith('mba_state_split_cond_1012') or state_split_cond.args[0].startswith('mba_state_split_cond_1016') and  state_split_cond.args[0].startswith('mba_state_split_cond_1014'):
                self.state.globals['last_added_state_split_cond'] = state_split_cond
                self.state.globals['last_state_split_cond_block_id'] = self.state.globals["cur_block_id"]
                ## IF OPTIMIZATION IS ZERO THEN WE HAVE TO STORE THIS IN THE REGISTER WHICH CREATED THIS TMP AS WELL,SINCE THE TEMP WILL NOT BE USED LATER WHEN THE REGISTER IS READ
                ## OR WE CAN JUST DO _replacement on all regs and current temps....... but still possible it might be on stack
                addr_mba=claripy.If(state_split_cond, conc_addrs[0], conc_addrs[1])
                ## this is used later in decompilation to simplify the branching
                ## This gets filled with the corresponding jump address for the each of the load address.... used for decomp results regex
                self.project.load_addr_mba_to_jump_addr_mapping[addr_mba] = []
                self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr, addr_mba)
                self.state.scratch.temps[kwargs["expr"].addr.tmp] = addr_mba
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

                    elif len(addr.args) == 3:
                        if addr.args[0].depth == 1:
                            if addr.op == "__add__":
                                self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr.args[1] + addr.args[2], claripy.If(state_split_cond, conc_addrs[0] - addr.args[0], conc_addrs[1] - addr.args[0]))
                            elif addr.op == "__sub__":
                                print("Not implemented")
                                import ipdb;
                                ipdb.set_trace()
                                #self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr.args[1], claripy.If(state_split_cond, addr.args[0] - conc_addrs[0], addr.args[0] - conc_addrs[1]))
                        elif addr.args[1].depth == 1:
                            if addr.op == "__add__":
                                self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr.args[0] + addr.args[2],claripy.If(state_split_cond, conc_addrs[0] - addr.args[1], conc_addrs[1] - addr.args[1]))
                            elif addr.op == "__sub__":
                                print("Not implemented")
                                import ipdb;
                                ipdb.set_trace()
                                # self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr.args[0] ,claripy.If(state_split_cond, conc_addrs[0] + addr.args[1], conc_addrs[1] + addr.args[1]))
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
                        self.state.scratch.temps[ind] = self.state.partial_symbolic_constraint_solver._solver._replacement(self.state.scratch.temps[ind])

                for reg in self.state.arch.registers.keys():
                    offset = self.state.arch.registers[reg][0]
                    size = self.state.arch.registers[reg][1]
                    old_val = self.state.registers.load(offset, size)
                    new_val = self.state.partial_symbolic_constraint_solver._solver._replacement(old_val)
                    if old_val is not new_val:
                        self.state.registers.store(offset, new_val)
                    else:
                        #perform extra simplifications and check
                        simp_ast = self.custom_simplify_ast(old_val)
                        if simp_ast is not old_val:
                            new_val = self.state.partial_symbolic_constraint_solver._solver._replacement(simp_ast)
                            if new_val is not simp_ast:
                                self.state.registers.store(offset, new_val)
                        elif old_val.op == "__add__" and len(old_val.args) == 3:
                            new_val = old_val
                            # deal with three argument adds, since they are not in the replacements
                            if old_val.args[0].depth == 1:
                                new_val = self.state.partial_symbolic_constraint_solver._solver._replacement(old_val.args[1] + old_val.args[2]) + old_val.args[0]
                            elif old_val.args[1].depth == 1:
                                new_val = self.state.partial_symbolic_constraint_solver._solver._replacement(old_val.args[0] + old_val.args[2]) + old_val.args[1]
                            elif old_val.args[2].depth == 1:
                                new_val = self.state.partial_symbolic_constraint_solver._solver._replacement(old_val.args[0] + old_val.args[1]) + old_val.args[2]

                            if new_val is not old_val:
                                self.state.registers.store(offset, new_val)

                return to_return
            else:
                print("More than one possible addrs")
                # import ipdb;ipdb.set_trace()


        return result

def save_vm_vpc(state):
    # This is just a hack to make sure that when the VIP reg is being used for something else we don't track it ### NEED A BETTER AND GENERIC WAY
    expr_val = state.partial_symbolic_constraint_solver.eval_upto(state.inspect.reg_write_expr, 2)
    if len(expr_val) > 1:
        l.debug("More than one VIP, gonna add both values and create a new one")
        #import ipdb;ipdb.set_trace()
        expr_val = expr_val[0]
    else:
        expr_val = expr_val[0]
    # expr_val = state.solver.eval_one(state.inspect.reg_write_expr)
    if state.project.loader.main_object.contains_addr(expr_val + state.globals['add_offset']):
        state.globals['cur_vm_vpc'] = expr_val + state.globals['add_offset']
        l.debug("The value of PROGRAM COUNTER is: " + str(state.globals.get('cur_vm_vpc')) + " reg_offset: " + str(state.inspect.reg_write_offset))
    else:
        l.debug("The value of the PROBLEMATIC PROGRAM COUNTER is and the PROBLEMATIC REGISTER IS: " + str(state.globals.get('cur_vm_vpc')) + " reg_offset: " + str(
            state.inspect.reg_write_offset))
        #import ipdb;ipdb.set_trace()
    return

def activate_save_vm_vpc(state):
    # if state.scratch.ins_addr in [0x474FB7, 0x4743F4, 0x407C38, 0x477F66, 0x44E43B, 0x42ECB6, 0x4511b4, 0x409687]:
    #     print(hex(state.scratch.ins_addr))
    #     import ipdb;ipdb.set_trace()
    # changing the offset to the vpc to differentiate between the two different byte code programs
    if 'visited' not in state.globals.keys():
        # state.inspect.add_breakpoint('reg_write',  BP(BP_AFTER, reg_write_offset=state.project.arch.registers["rbp"][0], reg_write_length=state.project.arch.registers["rbp"][1], action=save_vm_vpc))
        cur_vip_reg = state.globals['vm_vip_regs'][state.inspect.instruction]
        vm_end_addrs = state.globals['vm_end_addrs'][state.inspect.instruction]
        state.globals['reg_write_bp'] = state.inspect.b('reg_write', when=BP_AFTER, reg_write_offset=state.project.arch.registers[cur_vip_reg][0],
                                                                        reg_write_length=state.project.arch.registers[cur_vip_reg][1],
                                                                        action=save_vm_vpc)

        state.globals['call_stack_context_sensitivity_on'] = False


        # also activate the bp removing breakpoints
        state.globals['cur_rm_bps'] = []
        if vm_end_addrs is not None:
            for end_addr in vm_end_addrs:
                state.globals['cur_rm_bps'].append(state.inspect.b('instruction', when=BP_AFTER, instruction=end_addr, action=remove_breakpoints))
        else:
            import ipdb;ipdb.set_trace()
        state.globals['add_offset'] = 0

#This is for execryptor
def save_vpc_at_loc(state):
    # # This is just a hack to make sure that when the VIP reg is being used for something else we don't track it ### NEED A BETTER AND GENERIC WAY
    expr_val = state.partial_symbolic_constraint_solver.eval_upto(state.regs.esi, 2)
    if len(expr_val) > 1:
        l.debug("More than one VIP, gonna add both values and create a new one")
        import ipdb;ipdb.set_trace()
        expr_val = expr_val[0]
    else:
        expr_val = expr_val[0]
        state.globals['cur_vm_vpc'] = expr_val

    l.debug("The value of PROGRAM COUNTER is: " + str(state.globals.get('cur_vm_vpc')) + " mem_address: " + str(state.regs.esi))
    return

#This is for Themida
def save_vpc_at_mem_loc(state):
    expr_val = state.partial_symbolic_constraint_solver.eval_upto(state.memory.load(state.inspect.mem_write_address, state.arch.bytes, endness=state.arch.memory_endness), 2)
    if len(expr_val) > 1:
        l.debug("More than one VIP, gonna add both values and create a new one")
        # import ipdb;ipdb.set_trace()
        expr_val = expr_val[0]
    else:
        expr_val = expr_val[0]
        state.globals['cur_vm_vpc'] = expr_val

    l.debug("The value of PROGRAM COUNTER is: " + str(state.globals.get('cur_vm_vpc')) + " mem_address: " + str(state.inspect.mem_write_address))
    return

def remove_breakpoints(state):
    # if state.scratch.ins_addr in [0x474Fa5, 0x474Fa7, 0x439825, 0x407C28, 0x41C69A, 0x477F60, 0x4051E9, 0x4511ae]:
    #     print(hex(state.scratch.ins_addr))
    #     import ipdb;ipdb.set_trace()
    # remove the vm vpc tracking breakpoint
    state.inspect.remove_breakpoint('reg_write', state.globals['reg_write_bp'])
    # remove all breakpoints related to this save vm breakpoint
    for bp in state.globals['cur_rm_bps']:
        state.inspect.remove_breakpoint('instruction', bp)
    state.globals['reg_write_bp'] = None
    state.globals['call_stack_context_sensitivity_on'] = True
    #state.globals['cur_vm_vpc'] = None

time_so_far = 0
total_time = defaultdict(float)
time_distribution = defaultdict(list)
depth = 0


def _project_int_attr(project, name, default):
    value = getattr(project, name, default) if project is not None else default
    if value is None:
        return default
    return int(value)


def _project_bool_attr(project, name, default):
    value = getattr(project, name, default) if project is not None else default
    if isinstance(value, str):
        return value.lower() not in {"", "0", "false", "no", "off"}
    return bool(value)


def _cfg_shape(cfg):
    """
    Cheap fingerprint of a CFG: enough to tell whether a graph-editing pass did anything.
    Catches node/edge changes, statement removals and next-expression rewrites.
    """
    graph = getattr(cfg, "graph", None)
    if graph is None:
        return None

    parts = []
    for node in graph.nodes():
        irsb = getattr(node, "irsb", None)
        if irsb is None:
            parts.append((node.addr, -1, ""))
        else:
            parts.append((node.addr, len(irsb.statements), type(irsb.next).__name__))
    parts.sort()
    return graph.number_of_edges(), parts


def detects_changes(func):
    """
    For graph-editing passes that have no single mutation site to hook: compare the CFG
    shape across the call and record a change if it moved.
    """
    @wraps(func)
    def wrapper(self, cfg, *args, **kwargs):
        before = _cfg_shape(cfg)
        result = func(self, cfg, *args, **kwargs)
        after = _cfg_shape(result if getattr(result, "graph", None) is not None else cfg)
        if before != after:
            self._note_change()
        return result

    return wrapper


def skip_if_unchanged(func):
    """
    These passes are deterministic functions of the CFG, so one that last ran without
    changing anything cannot change anything until the CFG moves. Only no-op runs are
    recorded: a pass that did change something may still have more to do next time.

    Only for passes that return the CFG they were handed. Disable with
    project.vm_deob_skip_unchanged_passes = False.
    """
    @wraps(func)
    def wrapper(self, cfg, *args, **kwargs):
        if not _project_bool_attr(self.project, "vm_deob_skip_unchanged_passes", True):
            return func(self, cfg, *args, **kwargs)

        seen = self._pass_seen.get(func.__name__)
        if seen is not None and seen[0] is cfg and seen[1] == self._change_counter:
            return cfg

        before = self._change_counter
        result = func(self, cfg, *args, **kwargs)
        if self._change_counter == before:
            self._pass_seen[func.__name__] = (cfg, before)
        else:
            self._pass_seen.pop(func.__name__, None)
        return result

    return wrapper


def logtime(func):
    @wraps(func)
    def timed_func(*args, **kwargs):
        if TIMING:

            def _t():
                return time.perf_counter_ns() / 1000000

            global depth
            depth += 1

            global time_so_far

            start = _t()
            l.info(f"Started: {func.__name__}")
            r = func(*args, **kwargs)
            l.info(f"Finished: {func.__name__}")
            millisec = _t() - start
            sec = millisec / 1000

            indent = " " * ((depth - 1) * 2)
            if sec > 1.0:
                l.info(f"[timing] {indent}{func.__name__} took {sec:f} seconds ({millisec:f} milliseconds).")
            else:
                l.info(f"[timing] {indent}{func.__name__} took {millisec:f} milliseconds.")
            total_time[func] += millisec

            time_so_far += millisec
            sec = time_so_far / 1000
            if sec > 1.0:
                l.info(f"time taken so far {sec:f} seconds ({time_so_far:f} milliseconds).")
            else:
                l.info(f"time taken so far {time_so_far:f} milliseconds.")

            time_distribution[func].append(millisec)
            depth -= 1
            return r
        else:
            return func(*args, **kwargs)

    return timed_func
class VMDeobfuscation(Analysis):

    def __init__(self, vsp_reg, prev_unroll_vm_addrs=None, start_addr=None, start_state=None, cfg_fast_graph=None,
                 avoid_runs=None, vm_start_addr=None, verification_state=None, remove_insts=None,
                 constant_prop_func_replacements=None, semantic_verf_hooks=None, decomp_start_end_node_str=None,
                 decomp_function_addresses=None, decomp_function_prototypes=None,
                 decomp_main_func_prototype=None,  keep_sp_changes_dae=False, start_deobfuscation_immediately=False,
                 deobfuscation_start_addr=None, deobfuscation_end_addr=None,vpc_loc=None, vpc_mem_loc=None, allow_global_dead_ass_elim=False,
                 max_symbolizer_iterations=None, allow_global_mem_simplifications=True, constant_prop_level=0, use_vip_finder=False, skip_call_ret=False,
                 symbolizer_start_state=None, nodes_to_prune=[], themida_split_branches=False, remove_dead_simprocedures=False, only_verification_test=False,
                 ail_propagator_init_values=None, unroll_same_vpc_loop=False, byte_code_regions=None, min_entropy_threshold=5.00, use_mem_vpc_finder=False, hook_other_functions=False,
                 remove_vmp_semantically_same_branch=False, use_ctf_vpc_finder=False,
                 enable_pre_decompilation_vex_simplifications=False):

        self.project.vm_deobfuscation = True
        # the Windows targets reach msvcrt through imports with no declarations
        msvcr_defs.publish_procedure_prototypes()

        # (vm_vpc, addr) -> base of that block's synthetic address range; see convert_addr_to_int
        self._synthetic_addrs = {}

        # This is the address of the node where the virtual machine implementation starts
        self.vm_start_addr = vm_start_addr
        self.vsp_reg = vsp_reg
        self.start_addr = start_addr
        self.verification_state = verification_state
        self.constant_prop_func_replacements = constant_prop_func_replacements
        self.start_deobfuscation_immediately = start_deobfuscation_immediately
        self.deobfuscation_start_addr = deobfuscation_start_addr
        self.deobfuscation_end_addr = deobfuscation_end_addr
        self.vpc_loc = vpc_loc
        self.vpc_mem_loc = vpc_mem_loc
        self.draw_graph_flag = False
        self._pass_changed = False
        self._change_counter = 0
        self._coarse_epoch = 0
        self._pass_seen = {}
        self._node_dirty = {}
        self._node_seen = {}
        self.allow_global_mem_simplifications = allow_global_mem_simplifications
        self.nodes_to_prune = nodes_to_prune
        calls_as_rets = {}
        self.project.byte_code_regions=byte_code_regions
        self.project.min_entropy_threshold = min_entropy_threshold
        self.project.start_deobfuscation_immediately = start_deobfuscation_immediately
        self.project_dir = Path(self.project.filename).resolve().parent
        self.hook_other_functions = hook_other_functions
        self.remove_vmp_semantically_same_branch = remove_vmp_semantically_same_branch
        self.enable_pre_decompilation_vex_simplifications = (
            enable_pre_decompilation_vex_simplifications
            or _project_bool_attr(self.project, "enable_pre_decompilation_vex_simplifications", False)
        )


        DUMP = "dump"
        LOAD = "load"
        THEMIDA = True

        if only_verification_test:
            pickled_file_name = self.project_dir / "themida_simplification_cfg"
            new_cfg = self.pickle_dump_load_cfg(None, pickled_file_name, LOAD)


            verification_state_copy = verification_state.copy()
            self.perform_semantic_verification(new_cfg, self.project, start_state=verification_state_copy, start_addr=start_addr,semantic_verf_hooks=semantic_verf_hooks)
            return

        if self.project.arch.bits == 32:
            start_state.registers.store(start_state.arch.registers['ss'][0], 0)

        start_state_copy_without_bps = start_state.copy()


        # unroll the loops for the previous VM's
        start_state.globals['vm_vip_regs'] = {}
        start_state.globals['vm_end_addrs'] = {}
        start_state.globals['cur_rm_bps'] = []

        if start_deobfuscation_immediately:
            # if we are starting the deobfuscation immediately then no need to have call stack sensitivity since it doesn't make sense for obfuscated code
            start_state.globals['call_stack_context_sensitivity_on'] = False
        else:
            start_state.globals['call_stack_context_sensitivity_on'] = True

        start_state.globals['start_deobfuscation'] = False

        # add breakpoints to activate and remove bps for each vm region
        if prev_unroll_vm_addrs:
            for vm_tuple in prev_unroll_vm_addrs:
                vm_start_addr = vm_tuple[0]
                vm_end_addrs = vm_tuple[1]
                cur_vip_reg = vm_tuple[2]
                start_state.globals['vm_vip_regs'][vm_start_addr] = cur_vip_reg
                start_state.globals['vm_end_addrs'][vm_start_addr] = vm_end_addrs
                start_state.inspect.add_breakpoint('instruction',
                                                   BP(BP_BEFORE, instruction=vm_start_addr, action=activate_save_vm_vpc))
        elif vpc_loc:
            start_state.inspect.add_breakpoint('instruction',
                                               BP(BP_BEFORE, instruction=vpc_loc, action=save_vpc_at_loc))

        elif vpc_mem_loc:
            start_state.inspect.add_breakpoint('mem_write',
                                           BP(BP_AFTER, mem_write_address=vpc_mem_loc, action=save_vpc_at_mem_loc))
        elif use_vip_finder:
            start_state.globals['use_vip_finder'] = True
        elif use_ctf_vpc_finder:
            start_state.globals['use_ctf_vpc_finder'] = True
            if symbolizer_start_state is not None:
                symbolizer_start_state.globals['use_ctf_vpc_finder'] = True
        elif use_mem_vpc_finder:
            start_state.globals['use_mem_vpc_finder'] = True
            start_state.globals['mem_vpc_bp_set'] = False


        proj=self.project
        start_state_copy = start_state.copy()
        cfg, proj = self.data_sensitive_graph(self.project.filename, start_addr=self.start_addr, start_state=start_state_copy,
                                              cfg_fast_graph=cfg_fast_graph, avoid_runs=avoid_runs, remove_insts=remove_insts,
                                              unroll_same_vpc_loop=unroll_same_vpc_loop)

        with open('./total_node_count','w') as f:
            f.write(str(len(list(cfg.graph.nodes()))))

        import pickle
        pickled_file_name = self.project_dir / "rep_movsb_addr_pickle"
        with open(pickled_file_name, 'wb') as f:
            pickle.dump(self.project.rep_movsb_addr, f)

        pickled_file_name = self.project_dir / "same_branch_points"
        with open(pickled_file_name, 'wb') as f:
            pickle.dump(self.project.semantically_same_branch_points, f)


        self.project.kb.cfgs.cfgs = {}
        # clearing the saved states to save space
        for node in cfg.graph.nodes():
            node.input_state = None
            node.final_states = None

        # self.draw_graph_flag =True
        # self.draw_graph(cfg, self.project_dir / "input.svg")
        # self.draw_graph_flag = False

        # removing path terminators, cause...............they causing problems
        cfg = self.new_model_without_terminator_graph(cfg.graph, proj, 'without_path_terminator')

        cfg = self.keep_only_one_graph(cfg, start_addr)
        start_state_copy = start_state.copy()
        cfg = self.convert_to_data_sensitive_irsb(cfg, proj, start_state_copy)

        pickled_file_name = self.project_dir / "data_sens_cfg"
        cfg = self.pickle_dump_load_cfg(cfg, pickled_file_name, DUMP)

        self.project.kb.cfgs.cfgs = {}
        # clearing the saved states to save space
        for node in cfg.graph.nodes():
            node.input_state = None
            node.final_states = None

        # removing path terminators, cause...............they causing problems
        cfg = self.new_model_without_terminator_graph(cfg.graph, proj, 'without_path_terminator')

        cfg = self.keep_only_one_graph(cfg, start_addr)
        start_state_copy = start_state.copy()
        cfg = self.convert_to_data_sensitive_irsb(cfg, proj, start_state_copy)

        cfg = self.remove_vmp_semantic_same_branches(cfg)

        self.draw_graph_flag =True
        self.draw_graph(cfg, self.project_dir / "input.svg")
        self.draw_graph_flag = False
        new_cfg=cfg
        cfg = None
        all_symbolic_expr_locations = {}
        import pickle
        prev_node_count = 0
        fixed_point = False
        if max_symbolizer_iterations is None:
            max_symbolizer_iterations = 100
        #THe symbolizer should be run till all branches are explored.. Constant loops determine this
        for symb_iter in range(max_symbolizer_iterations):
            proj.merger_top_dict_debug = {}
            if themida_split_branches:
                to_split_nodes = self.split_redundant_branch_themida(new_cfg)
                new_cfg = self.split_redundant_branch_obf(new_cfg, to_split_nodes)
            self.draw_graph(new_cfg, self.project_dir / f"{symb_iter}after_all_split.svg")

            pickled_file_name = self.project_dir / f"pickled_{symb_iter}_all_symbolic_expr_location"
            with open(pickled_file_name, 'wb') as f:
                pickle.dump(all_symbolic_expr_locations, f)

            # this constant prop is just used to get the symbolic_expr_locations_blockwise not to actually do constant prop
            # symbolizer here tells us which values to symbolize during next cfg exploration stage, it does not discover new nodes
            #we need to pass previous symb exprs because, once a conditonal jmp is symbolized, we may not necessariy explore the branchs in the correct order
            # in symbolizer. which could lead to a incomplete graph. e.g exploring the False branch first, will cause us to miss the loop branch which symbolzies the
            # correct variable. this is specifically in themida which has two conditionals jmp for every conditional jump
            symbolic_expr_locations= self.symbolizer(new_cfg, proj,
                                                                  start_addr, None,
                                                                  start_state=symbolizer_start_state,
                                                                  prev_symbolic_expr_locations=all_symbolic_expr_locations,
                                                                  prev_unroll_vm_addrs=prev_unroll_vm_addrs,
                                                                  constant_prop_level=constant_prop_level)[1]

            import pickle
            pickled_file_name = self.project_dir / f"symbolizer_z3_time_prof_iter_{symb_iter}"
            with open(pickled_file_name, 'wb') as f:
                pickle.dump(self.project.symbolizer_solve_times, f)

            pickled_file_name = self.project_dir / f"merge_state_to_symb{symb_iter}"
            with open(pickled_file_name, 'wb') as f:
                pickle.dump(self.project.to_symbolize, f)

            self.project.symbolizer_solve_times = []


            self.merge_symbolic_expr_locations(all_symbolic_expr_locations, symbolic_expr_locations)

            pickled_file_name = self.project_dir / f"pickled_{symb_iter}_all_symbolic_expr_location"
            with open(pickled_file_name, 'wb') as f:
                pickle.dump(all_symbolic_expr_locations, f)

            self.project.kb.cfgs.cfgs = {}
            # clearing the saved states to save space
            for node in new_cfg.graph.nodes():
                node.input_state = None
                node.final_states = None
            node = None # remove refernce to this node, so gc can collect it
            new_cfg.graph.clear()
            new_cfg = None
            import gc
            gc.collect()
            start_state_copy = start_state.copy()
            #here we discover new nodes based on the values to symbolize from the symbolizer
            #here we discover one nested branch each iteration,so more the nested branches more iterations of this needed
            #TO DO: there is a way to do this together in one analysis, by allowing to visit the blocks more than once in CFGEmulated(max_iter)
            #and also changing the way merging of values happens
            #INFO: The reason we need to pass all previous symb locs is that cfgemulated does not merge values as it does not
            # explore a node(merge point node) twice, so it cannot symbolize values itself.
            new_cfg, _ = self.symbolify_exprs(proj, all_symbolic_expr_locations,
                                                                  start_addr=start_addr, start_state=start_state_copy,
                                                                  cfg_fast_graph=cfg_fast_graph, avoid_runs=avoid_runs,
                                                                  remove_insts=remove_insts,
                                                                unroll_same_vpc_loop=unroll_same_vpc_loop)
            import pickle
            pickled_file_name = self.project_dir / f"rep_movsb_addr_pickle_{symb_iter}"
            with open(pickled_file_name, 'wb') as f:
                pickle.dump(self.project.rep_movsb_addr, f)

            self.project.kb.cfgs.cfgs = {}
            # clearing the saved states to save space
            for node in new_cfg.graph.nodes():
                node.input_state = None
                node.final_states = None

            new_cfg = self.new_model_without_terminator_graph(new_cfg.graph, proj, 'without_path_terminator')

            new_cfg = self.keep_only_one_graph(new_cfg, start_addr)

            start_state_copy = start_state.copy()
            new_cfg = self.convert_to_data_sensitive_irsb(new_cfg, proj, start_state_copy)

            pickled_file_name = self.project_dir / f"{symb_iter}_symbolizer_cfg_pickle"
            new_cfg = self.pickle_dump_load_cfg(new_cfg, pickled_file_name, DUMP)

            new_cfg = self.remove_vmp_semantic_same_branches(new_cfg)

            self.draw_graph_flag=True
            self.draw_graph(new_cfg, self.project_dir / f"{symb_iter}symb_result.svg")
            self.draw_graph_flag=False

            fixed_point = len(new_cfg.nodes()) == prev_node_count
            if fixed_point:
                break

            prev_node_count = max(len(new_cfg.nodes()), prev_node_count)

        if themida_split_branches:
            to_split_nodes = self.split_redundant_branch_themida(new_cfg)
            new_cfg = self.split_redundant_branch_obf(new_cfg, to_split_nodes)

        new_cfg = self.convert_to_data_sensitive_irsb(new_cfg, proj, None)

        self.draw_graph_flag = True

        self.draw_graph(new_cfg, self.project_dir / "after_all_symb_and_split.svg")

        # Leaving this commented out left the flag set for the next ~90 lines, so every
        # intermediate debug svg inside the simplification loops got rendered: 86s of
        # graphviz on vmwhere1-uiuctf alone.
        self.draw_graph_flag = False

        import pickle
        pickled_file_name = self.project_dir / "pickled_load_addr_mba_to_jump_addr_mapping"
        with open(pickled_file_name,'wb') as load_addr_mba_to_jump_addr_mapping:
            pickle.dump(self.project.load_addr_mba_to_jump_addr_mapping, load_addr_mba_to_jump_addr_mapping)


        import gc
        gc.collect()
        self.project.to_symbolize = defaultdict(dict)
        ## This is constant propgation along with finding non-constants
        new_cfg, _ = self.symbolizer(new_cfg, proj, start_addr, None, start_state=symbolizer_start_state, prev_symbolic_expr_locations=None,
                                     prev_unroll_vm_addrs=prev_unroll_vm_addrs,do_replacements=True, constant_prop_level=constant_prop_level)
        self.project.kb.cfgs.cfgs = {}
        # clearing the saved states to save space
        for node in new_cfg.graph.nodes():
            node.input_state = None
            node.final_states = None

        pickled_file_name = self.project_dir / "initial_full_cfg"
        new_cfg = self.pickle_dump_load_cfg(new_cfg, pickled_file_name, DUMP)
        self.inst_count(new_cfg)

        new_cfg = self.vmp_remove_bt_rdtsc_insts(new_cfg, self.project.bt_ins_addrs, self.project.rdtsc_ins_addrs)
        if remove_dead_simprocedures:
            new_cfg = self.eliminate_dead_simprocedures(new_cfg, proj, self.project.simprocedures_to_remove)

        # important to perform this first before any other simplifiactions
        new_cfg = self.remove_segment_selector_vex_inst(new_cfg)
        import gc
        gc.collect()
        self.draw_graph(new_cfg, self.project_dir / "full_cp_result.svg")

        # This stores all the returns that are actually calls for later adjusting the stack args location in callsite_maker.py
        # calls_as_rets is used later during decompilation to adjust stack argument offset for cdcel because the ret has different offsets compared to a normal call
        new_cfg, calls_as_rets = self.replace_jumpkinds(new_cfg)

        import pickle
        pickled_file_name = self.project_dir / "calls_as_rets"
        with open(pickled_file_name,'wb') as calls_as_rets_pickle:
            pickle.dump(calls_as_rets, calls_as_rets_pickle)

        # this is a simplification pass to remove all push x, ret to x type of jumpsh
        new_cfg = self.remove_push_ret(new_cfg, proj, start_addr=start_addr, start_state=None, decomp_function_addresses=decomp_function_addresses)
        self.draw_graph(new_cfg, self.project_dir / "remove_push_ret.svg")


        # this is to remove those vex jump insts that will always to the same location. This is after the data sensitive analysis
        new_cfg = self.remove_useless_jump_instructions(new_cfg, keep_sp_changes_dae=keep_sp_changes_dae)
        self.draw_graph(new_cfg, self.project_dir / "remove_useless_jump.svg")

        pickled_file_name = self.project_dir / "mid_way_cfg"
        new_cfg = self.pickle_dump_load_cfg(new_cfg, pickled_file_name, DUMP)

        print("start")
        for i in range(4):
            self._pass_changed = False
            new_cfg = self._eliminate_dead_assignments(new_cfg, proj,  keep_sp_changes_dae=keep_sp_changes_dae)
            new_cfg = self.keep_only_one_graph(new_cfg, start_addr)
            self.draw_graph(new_cfg, self.project_dir / f"dae_{i}_result.svg")

            new_cfg = self.remove_useless_jump_instructions(new_cfg, keep_sp_changes_dae=keep_sp_changes_dae)

            new_cfg = self.block_arithmetic_simplifications_using_dep_graph(new_cfg, proj)
            self.draw_graph(new_cfg, self.project_dir / f"{i}block_arithmetic_simplifications.svg")

            new_cfg = self.join_basic_blocks(new_cfg, proj, start_addr=start_addr, start_state=None, skip_call_ret=skip_call_ret)

            if self._converged():
                break

        #pickled_file_name = os.path.dirname(self.project.filename) + "/two_mid_way_cfg"
        # with open(pickled_file_name,'wb') as mid_way_cfg_pickle:
        #     pickle.dump(new_cfg, mid_way_cfg_pickle)



        #### These need to be after join basic blocks becasue of the way RDA considers a libc func call as internal instead of external
        for i in range(4):
            global to_break
            to_break = True
            self._pass_changed = False
            new_cfg = self.testing_new_improved_whole_vm_RDA_deadassignment_elimination(new_cfg, proj, keep_sp_changes_dae=keep_sp_changes_dae)
            self.draw_graph(new_cfg, self.project_dir / f"{i}whole_cfg_deadassignment_elimination.svg")
            if self._converged():
                break

        self.draw_graph_flag = True
        self.draw_graph(new_cfg, self.project_dir / "mid_graph_result")
        self.draw_graph_flag = False

        for i in range(4):
            self._pass_changed = False
            new_cfg = self._eliminate_dead_assignments(new_cfg, proj, keep_sp_changes_dae=keep_sp_changes_dae)
            self.draw_graph(new_cfg, self.project_dir / f"dae_{i}_result.svg")
            if self._converged():
                break


        new_cfg = self.remove_redundant_store_load(new_cfg, proj, start_state=start_state)
        self.draw_graph(new_cfg, self.project_dir / "debug_2_result.svg")

        for i in range(2):
            self._pass_changed = False
            new_cfg = self.testing_new_improved_whole_vm_RDA_deadassignment_elimination(new_cfg, proj, keep_sp_changes_dae=keep_sp_changes_dae)
            self.draw_graph(new_cfg, self.project_dir / f"{i}whole_cfg_deadassignment_elimination.svg")
            if self._converged():
                break
        for i in range(2):
            self._pass_changed = False
            new_cfg = self._eliminate_dead_assignments(new_cfg, proj,  keep_sp_changes_dae=keep_sp_changes_dae)
            self.draw_graph(new_cfg, self.project_dir / f"dae_{i}_result.svg")
            if self._converged():
                break

        self.draw_graph(new_cfg, self.project_dir / "debug_1_result.svg")
        new_cfg = self.remove_redundant_assignment(new_cfg, proj, start_state=start_state)
        self.draw_graph(new_cfg, self.project_dir / "redun_store_load.svg")


        pickled_file_name = self.project_dir / "before_get_put"
        new_cfg = self.pickle_dump_load_cfg(new_cfg, pickled_file_name, DUMP)

        for i in range(8):
            self._pass_changed = False
            new_cfg = self.testing_new_improved_whole_vm_RDA_deadassignment_elimination(new_cfg, proj,  keep_sp_changes_dae=keep_sp_changes_dae)
            self.draw_graph(new_cfg, self.project_dir / f"{i}whole_cfg_deadassignment_elimination.svg")

            new_cfg = self._eliminate_dead_assignments(new_cfg, proj,  keep_sp_changes_dae=keep_sp_changes_dae)
            self.draw_graph(new_cfg, self.project_dir / f"dae_cake_{i}_result.svg")

            new_cfg = self.block_arithmetic_simplifications_using_dep_graph(new_cfg, proj)
            self.draw_graph(new_cfg, self.project_dir / f"{i}_block_arithmetic_simplifications.svg")


            new_cfg = self.remove_redundant_Get_Put(new_cfg, proj, start_state=start_state)
            self.draw_graph(new_cfg, self.project_dir / f"{i}remove_redun_get_put.svg")

            if self._converged():
                break

        pickled_file_name = self.project_dir / "after_get_put"
        new_cfg = self.pickle_dump_load_cfg(new_cfg, pickled_file_name, DUMP)


        new_cfg = self.remove_redundant_assignment(new_cfg, proj, start_state=start_state)
        self.draw_graph(new_cfg, self.project_dir / "redun_store_load.svg")

        for i in range(3):
            self._pass_changed = False
            new_cfg = self.remove_redundant_Get_Put(new_cfg, proj, start_state=start_state)
            self.draw_graph(new_cfg, self.project_dir / f"{i}remove_redun_get_put.svg")

            new_cfg = self.testing_new_improved_whole_vm_RDA_deadassignment_elimination(new_cfg, proj,  keep_sp_changes_dae=keep_sp_changes_dae)
            self.draw_graph(new_cfg, self.project_dir / f"{i}whole_cfg_deadassignment_elimination.svg")

            new_cfg = self._eliminate_dead_assignments(new_cfg, proj,  keep_sp_changes_dae=keep_sp_changes_dae)
            self.draw_graph(new_cfg, self.project_dir / f"dae_{i}_result.svg")

            new_cfg = self.remove_useless_jump_instructions(new_cfg, keep_sp_changes_dae=keep_sp_changes_dae)

            if self._converged():
                break

        pickled_file_name = self.project_dir / "pickled_final_cfg"
        new_cfg = self.pickle_dump_load_cfg(new_cfg, pickled_file_name, DUMP)

        # pickled_file_name = os.path.dirname(self.project.filename) + "/pickled_final_cfg"
        # new_cfg = self.pickle_dump_load_cfg(None, pickled_file_name, LOAD)


        if THEMIDA:
            new_cfg = self.remove_call_to_next_addr(new_cfg)

            new_cfg = self.remove_push_ret(new_cfg, proj, start_addr=start_addr, start_state=None, decomp_function_addresses=decomp_function_addresses)

            for i in range(35):
                self._pass_changed = False
                new_cfg = self.testing_new_improved_whole_vm_RDA_deadassignment_elimination(new_cfg, proj,  keep_sp_changes_dae=keep_sp_changes_dae)
                self.draw_graph(new_cfg, self.project_dir / f"{i}whole_cfg_deadassignment_elimination.svg")

                new_cfg = self._eliminate_dead_assignments(new_cfg, proj,  keep_sp_changes_dae=keep_sp_changes_dae)
                self.draw_graph(new_cfg, self.project_dir / f"dae_cake_{i}_result.svg")

                # new_cfg = self.block_arithmetic_simplifications_using_dep_graph(new_cfg, proj)
                # self.draw_graph(new_cfg, os.path.join(folder_name, str(i)+"_block_arithmetic_simplifications.svg"))

                new_cfg = self.remove_redundant_store_load(new_cfg, proj, start_state=start_state)

                new_cfg = self.remove_redundant_assignment(new_cfg, proj, start_state=start_state)

                new_cfg = self.join_basic_blocks(new_cfg, proj, start_addr=start_addr, start_state=None, skip_call_ret=skip_call_ret)

                new_cfg = self.remove_push_ret(new_cfg, proj, start_addr=start_addr, start_state=None, decomp_function_addresses=decomp_function_addresses)

                if self._converged():
                    break

            pickled_file_name = self.project_dir / "pickled_beyond_final_cfg"
            new_cfg = self.pickle_dump_load_cfg(new_cfg, pickled_file_name, DUMP)


            self.draw_graph(new_cfg,self.project_dir / "before_beyond.svg")

            new_cfg = self.CAS_to_mov_simplification(new_cfg, proj)

            for i in range(35):
                self._pass_changed = False
                new_cfg = self.block_arithmetic_simplifications_using_dep_graph(new_cfg, proj)

                new_cfg = self.remove_redundant_assignment(new_cfg, proj, start_state=start_state)

                new_cfg = self._eliminate_dead_assignments(new_cfg, proj, keep_sp_changes_dae=keep_sp_changes_dae)

                new_cfg = self.testing_new_improved_whole_vm_RDA_deadassignment_elimination(new_cfg, proj,
                                                                                            keep_sp_changes_dae=keep_sp_changes_dae)

                new_cfg = self.remove_redundant_store_load(new_cfg, proj, start_state=start_state)

                new_cfg = self.remove_redundant_Get_Put(new_cfg, proj, start_state=start_state)

                new_cfg = self.join_basic_blocks(new_cfg, proj, start_addr=start_addr, start_state=None, skip_call_ret=skip_call_ret)

                self.draw_graph(new_cfg, self.project_dir / f"{i}block_arithmetic_simplifications_using_dep_graph.svg")

                if self._converged():
                    break

            pickled_file_name = self.project_dir / "themida_simplification_cfg"
            new_cfg = self.pickle_dump_load_cfg(new_cfg, pickled_file_name, DUMP)

        # pickled_file_name = self.project_dir / "themida_simplification_cfg"
        # new_cfg = self.pickle_dump_load_cfg(None, pickled_file_name, LOAD)

        if self.enable_pre_decompilation_vex_simplifications:
            new_cfg = self.run_pre_decompilation_vex_simplifications(
                new_cfg,
                proj,
                start_state=start_state,
                keep_sp_changes_dae=keep_sp_changes_dae,
            )
        else:
            new_cfg = self.remove_segment_selector_vex_inst(new_cfg)

        # verification_state_copy = verification_state.copy()
        # self.perform_semantic_verification(new_cfg, proj, start_state=verification_state_copy, start_addr=start_addr,semantic_verf_hooks=semantic_verf_hooks)

        # pickled_file_name = os.path.dirname(self.project.filename) + "/pickled_load_addr_mba_to_jump_addr_mapping"
        # with open(pickled_file_name,'rb') as load_addr_mba_to_jump_addr_mapping_pickle:
        #     self.project.load_addr_mba_to_jump_addr_mapping = pickle.load(load_addr_mba_to_jump_addr_mapping_pickle)

        pickled_file_name = self.project_dir / "calls_as_rets"
        with open(pickled_file_name, 'rb') as calls_as_rets_pickle:
            calls_as_rets = pickle.load(calls_as_rets_pickle)

        self.draw_graph_flag = True

        self.draw_graph(new_cfg, self.project_dir /  "final_result.svg", without_insts=False, super_graph_only=False)

        self.try_decompilation(new_cfg, decomp_start_end_node_str, decomp_function_addresses=decomp_function_addresses,
                               decomp_function_prototypes=decomp_function_prototypes, semantic_verf_hooks=semantic_verf_hooks,
                               decomp_main_func_prototype=decomp_main_func_prototype, calls_as_rets=calls_as_rets,
                               allow_global_dead_ass_elim=allow_global_dead_ass_elim, ail_propagator_init_values=ail_propagator_init_values)


        # verification_state_copy = verification_state.copy()
        # # self.draw_png_graph(new_cfg, os.path.join(folder_name,  "final_result.png"))
        # self.perform_semantic_verification(new_cfg, proj, start_state=verification_state_copy, start_addr=start_addr,semantic_verf_hooks=semantic_verf_hooks)
        self.draw_graph(new_cfg, self.project_dir /  "final_result_enc_addr.svg")

        self.log_timing_results()

        # self.draw_original_graph(new_cfg, os.path.join(folder_name, "comparision_graph.svg"), proj)
        # self.compare_vex(initial_cfg, new_cfg, folder_name)
        # self.pattern_match_to_x86_instructions(new_cfg, initial_cfg, proj, folder_name)

    def _note_change(self, node=None):
        """
        Record that a simplification pass actually altered the CFG. The fixed-count
        simplification loops use this to stop once they stop making progress.

        Pass the node when the change is confined to that block. Anything else -- graph
        edits, node removals, whole-model rebuilds -- is a coarse change that retires
        every per-node cache entry by bumping the epoch.
        """
        self._pass_changed = True
        self._change_counter += 1
        if node is None:
            self._coarse_epoch += 1
        else:
            self._node_dirty[node] = self._change_counter

    def _node_is_clean(self, pass_name, node):
        """
        True when pass_name already examined this exact block without changing it, and
        nothing has touched the block since. These passes analyse one block in isolation,
        so a change to some other block cannot give them new work here.
        """
        if not _project_bool_attr(self.project, "vm_deob_skip_unchanged_nodes", True):
            return False
        seen = self._node_seen.get((pass_name, node))
        return seen is not None and seen[0] == self._coarse_epoch and \
            seen[1] >= self._node_dirty.get(node, -1)

    def _mark_node_clean(self, pass_name, node, epoch, counter):
        """Record a no-op examination. epoch/counter are the values from before the node ran."""
        if self._node_dirty.get(node, -1) < counter:
            self._node_seen[(pass_name, node)] = (epoch, counter)

    def _converged(self):
        """
        True when the round that just ran changed nothing, so further rounds cannot either.
        Set project.vm_deob_converge_loops = False to keep running the full fixed counts.
        """
        return not self._pass_changed and _project_bool_attr(self.project, "vm_deob_converge_loops", True)

    def remove_vmp_semantic_same_branches(self, cfg):
        """
        Removes branches at semantic same points by:
        1. Converting to unconditional jump to first successor
        2. Removing the pruned branch and all its unique successors
           until they rejoin nodes with multiple predecessors
        """
        self.project.semantically_same_branch_points.add(0x7ff74db5f1eb)

        # Create a list copy of nodes to avoid "dictionary changed size during iteration"
        nodes_list = list(cfg.graph.nodes())

        for node in nodes_list:
            # Check if node still exists in graph (may have been removed during branch pruning)
            if node not in cfg.graph:
                continue

            if node.addr in self.project.semantically_same_branch_points:
                succs = list(cfg.graph.successors(node))
                if len(succs) >= 2:
                    succs_sorted = sorted(succs, key=lambda s: s.addr)

                    # Choose the target address (first successor to keep)
                    target_addr = succs_sorted[0].addr
                    target_block_id = succs_sorted[0].block_id

                    # Identify branches to remove (all except the first)
                    branches_to_remove = succs_sorted[1:]

                    # For each branch to remove, traverse and collect nodes to delete
                    nodes_to_remove = set()
                    for branch_root in branches_to_remove:
                        self._collect_unique_path_nodes(cfg, branch_root, nodes_to_remove)

                    # Remove the collected nodes from the graph
                    for removed_node in nodes_to_remove:
                        if removed_node in cfg.graph:
                            cfg.graph.remove_node(removed_node)

                    # Remove all Exit statements from the branch point
                    new_stmts = [stmt for stmt in node.irsb.statements
                                 if not isinstance(stmt, pyvex.stmt.Exit)]
                    node.irsb.statements = new_stmts

                    # Set unconditional next target
                    if self.project.arch.bits == 32:
                        node.irsb.next = pyvex.expr.Const(DataSensitiveU32(target_addr, target_block_id))
                    elif self.project.arch.bits == 64:
                        node.irsb.next = pyvex.expr.Const(DataSensitiveU64(target_addr, target_block_id))

        return cfg

    def _collect_unique_path_nodes(self, cfg, start_node, nodes_to_remove):
        """
        Recursively collect nodes that are unique to this path.
        Stop when reaching a node with multiple predecessors (rejoin point).
        """
        # Check if this node has already been visited
        if start_node in nodes_to_remove:
            return

        # Check if node still exists in graph
        if start_node not in cfg.graph:
            return

        # Check if this is a rejoin point (multiple predecessors)
        predecessors = list(cfg.graph.predecessors(start_node))
        if len(predecessors) > 1:
            return  # Don't remove this node - it's a rejoin point

        # Mark this node for removal
        nodes_to_remove.add(start_node)

        # Recursively process successors
        successors = list(cfg.graph.successors(start_node))
        for succ in successors:
            self._collect_unique_path_nodes(cfg, succ, nodes_to_remove)

    # def remove_vmp_semantic_same_branches(self, cfg):
    #     self.project.semantically_same_branch_points.add(0x7ff74db5f1eb)
    #     # NOTE: this does not remove the branch only makes one of the paths unaccessible, so it will later be removedby dead ass elim
    #     for node in cfg.graph.nodes():
    #         if node.addr in self.project.semantically_same_branch_points:
    #             succs = list(cfg.graph.successors(node))
    #             if len(succs) == 1:
    #                 for stmt in node.irsb.statements:
    #                     if isinstance(stmt, pyvex.stmt.Exit):
    #                         exit_addr = stmt.dst
    #
    #                 if exit_addr.value == succs[0].addr:
    #                     new_addr = exit_addr.value
    #                     if self.project.arch.bits == 32:
    #                         new_addr = pyvex.expr.Const(DataSensitiveU32(new_addr, succs[0].block_id))
    #                     elif self.project.arch.bits == 64:
    #                         new_addr = pyvex.expr.Const(DataSensitiveU64(new_addr, succs[0].block_id))
    #
    #                     node.irsb.next = new_addr
    #                 else:
    #                     new_addr = succs[0].addr
    #                     for stmt in node.irsb.statements:
    #                         if isinstance(stmt, pyvex.stmt.Exit):
    #                             if self.project.arch.bits == 32:
    #                                 stmt.dst = DataSensitiveU32(new_addr, succs[0].block_id)
    #                             elif self.project.arch.bits == 64:
    #                                 stmt.dst = DataSensitiveU64(new_addr, succs[0].block_id)
    #             else:
    #                 for stmt in node.irsb.statements:
    #                     if isinstance(stmt, pyvex.stmt.Exit):
    #                         exit_addr = stmt.dst
    #
    #                 if exit_addr.value == succs[0].addr:
    #                     new_addr = exit_addr.value
    #                     if self.project.arch.bits == 32:
    #                         new_addr = pyvex.expr.Const(DataSensitiveU32(new_addr, succs[0].block_id))
    #                     elif self.project.arch.bits == 64:
    #                         new_addr = pyvex.expr.Const(DataSensitiveU64(new_addr, succs[0].block_id))
    #
    #                     node.irsb.next = new_addr
    #                 else:
    #                     new_addr = succs[0].addr
    #                     for stmt in node.irsb.statements:
    #                         if isinstance(stmt, pyvex.stmt.Exit):
    #                             if self.project.arch.bits == 32:
    #                                 stmt.dst = DataSensitiveU32(new_addr, succs[0].block_id)
    #                             elif self.project.arch.bits == 64:
    #                                 stmt.dst = DataSensitiveU64(new_addr, succs[0].block_id)
    #
    #     return cfg

    def faster_eliminate_dead_assignments(self, cfg, proj, keep_sp_changes_dae=False):

        def remove_path(cur_cfg, start_node):
            reachable = set(networkx.dfs_preorder_nodes(as_networkx(cur_cfg.graph), source=start_node))
            to_prune = [n for n in cur_cfg.graph.nodes if n not in reachable]
            return to_prune

        dsa_new_model = cfg

        # find start node
        for node in dsa_new_model.nodes():
            if node.addr == self.vm_start_addr:
                start_node = node
                break

        nodes_to_remove = set()

        for node in list(dsa_new_model.nodes()):
            if node.is_simprocedure:
                continue

            cur_block = angr.Block(node.irsb.addr, project=proj, vex=node.irsb)

            # --- RD once per block; we'll iterate eliminations using the same model
            rd = self.project.analyses.ReachingDefinitions(
                cur_block,
                track_tmps=True,
                track_consts=False,
                observation_points=[('node', node.addr, OP_AFTER)]
            )
            rd.model.liveness.def_to_liveness = None
            rd.model.liveness.loc_to_defs = None

            live_defs = rd.one_result
            all_defs = rd.all_definitions

            # Keep a growing set of removed statement indices for this block
            removed_stmt_idxs: set[int] = set()

            def _filter_uses_excluding_removed(uses):
                """
                'uses' can be a set/list of Use objects or CodeLocations depending on angr version.
                We conservatively check for .codeloc or treat the object itself as a CodeLocation.
                """
                filtered = []
                for u in uses or []:
                    cl = getattr(u, 'codeloc', u)
                    if getattr(cl, 'stmt_idx', None) is None:
                        filtered.append(u)
                    else:
                        if cl.stmt_idx not in removed_stmt_idxs:
                            filtered.append(u)
                return filtered

            def _defs_excluding_removed(defs_set):
                """Filter a set of Definition objects so only keep those not already removed."""
                out = set()
                for d in defs_set:
                    si = getattr(d.codeloc, 'stmt_idx', None)
                    if si is None or si not in removed_stmt_idxs:
                        out.add(d)
                return out

            changed_any = False

            # Iterate until no more new eliminations (fixed point) using the same RD
            while True:
                pass_removed_now = set()
                dead_defs_stmt_idx = defaultdict(int)

                # Recompute used_tmp_indices *considering only non-removed uses*
                used_tmp_indices = set()
                for tmp_idx, tmp_uses in (getattr(live_defs, 'tmp_uses', {}) or {}).items():
                    filt = _filter_uses_excluding_removed(tmp_uses)
                    if filt:
                        used_tmp_indices.add(tmp_idx)

                # Scan all defs; if their only remaining uses are in removed stmts (or none), mark stmt dead
                for d in all_defs:
                    si = getattr(d.codeloc, 'stmt_idx', None)
                    if isinstance(d.codeloc, ExternalCodeLocation) or d.dummy:
                        continue
                    if si is None or si in removed_stmt_idxs:
                        # Already out of consideration
                        continue

                    if isinstance(d.atom, atoms.Tmp):
                        tmp_idx = d.atom.tmp_idx
                        uses = _filter_uses_excluding_removed(live_defs.tmp_uses.get(tmp_idx, []))
                        if not uses:
                            # Preserve tmp if it flows into next
                            if isinstance(node.irsb.next, DataSensitiveRdTmp):
                                if node.irsb.next.tmp != tmp_idx:
                                    dead_defs_stmt_idx[si] += 1
                                else:
                                    used_tmp_indices.add(tmp_idx)
                            else:
                                dead_defs_stmt_idx[si] += 1
                        else:
                            used_tmp_indices.add(tmp_idx)

                    else:
                        # Non-tmp atoms: check liveness at block end; if not alive, candidate for removal
                        defs_ = set()
                        vs = None

                        if isinstance(d.atom, atoms.Register):
                            if keep_sp_changes_dae and d.atom.reg_offset == self.project.arch.sp_offset:
                                continue
                            try:
                                vs = live_defs.registers.load(
                                    d.atom.reg_offset, size=d.atom.size
                                )
                            except SimMemoryMissingError:
                                vs = None

                        elif isinstance(d.atom, atoms.MemoryLocation) and isinstance(d.atom.addr, SpOffset):
                            stack_addr = live_defs.stack_offset_to_stack_addr(d.atom.addr.offset)
                            try:
                                vs = live_defs.stack.load(
                                    stack_addr, size=d.atom.size, endness=d.atom.endness
                                )
                            except SimMemoryMissingError:
                                vs = None

                        elif isinstance(d.atom, atoms.MemoryLocation) and \
                                isinstance(node.irsb.statements[si], pyvex.stmt.Store) and \
                                isinstance(node.irsb.statements[si].addr, pyvex.expr.Const):
                            try:
                                vs = live_defs.memory.load(
                                    d.atom.addr, size=d.atom.size, endness=d.atom.endness
                                )
                            except SimMemoryMissingError:
                                vs = None
                        else:
                            # Unsupported/complex address cases; skip this def
                            continue

                        if vs is None:
                            continue

                        for values in vs.values():
                            for value in values:
                                defs_.update(live_defs.extract_defs(value))

                        # Only consider non-removed defs
                        defs_ = _defs_excluding_removed(defs_)

                        if d not in defs_:
                            # Additional aliasing guard for concrete-address mem stores:
                            if isinstance(d.atom, atoms.MemoryLocation) and not isinstance(d.atom.addr, SpOffset):
                                possible_alias = False
                                # Look for any symbolic loads between d and the next def, skipping removed stmts
                                for n_def in defs_:
                                    assert d.codeloc.stmt_idx < n_def.codeloc.stmt_idx
                                    for i in range(d.codeloc.stmt_idx, n_def.codeloc.stmt_idx):
                                        if i in removed_stmt_idxs:
                                            continue
                                        st = node.irsb.statements[i]
                                        if isinstance(st, pyvex.stmt.WrTmp) and isinstance(st.data, pyvex.expr.Load):
                                            if not isinstance(st.data.addr, pyvex.IRExpr.Const):
                                                possible_alias = True
                                                break
                                    if possible_alias:
                                        break
                                if not possible_alias:
                                    dead_defs_stmt_idx[si] += 1
                            else:
                                dead_defs_stmt_idx[si] += 1

                # Decide which stmts to remove in this pass (excluding those already removed)
                for idx, stmt in enumerate(cur_block.vex.statements):
                    if idx in removed_stmt_idxs:
                        continue

                    # Kill dead tmps (WrTmp) whose tmp is not used anymore (after filtering)
                    if isinstance(stmt, pyvex.stmt.WrTmp):
                        if stmt.tmp not in used_tmp_indices:
                            pass_removed_now.add(idx)
                            continue

                    # CAS must have both defs dead
                    if isinstance(stmt, pyvex.stmt.CAS):
                        if dead_defs_stmt_idx.get(idx, 0) >= 2:
                            pass_removed_now.add(idx)
                            continue

                    # Any stmt with dead def(s)
                    if idx in dead_defs_stmt_idx:
                        pass_removed_now.add(idx)
                        continue

                if not pass_removed_now:
                    break  # fixed point for this block

                removed_stmt_idxs |= pass_removed_now
                changed_any = True

            # If nothing changed for this block, we still may simplify constant-guard Exits
            new_statements = []
            for idx, stmt in enumerate(cur_block.vex.statements):
                if idx in removed_stmt_idxs:
                    continue

                # Keep original "end-of-block" IMarks/AbiHints cleanup and duplicates skip
                if isinstance(stmt, pyvex.stmt.IMark) and idx == len(cur_block.vex.statements) - 1:
                    continue
                elif isinstance(stmt, pyvex.stmt.AbiHint) and idx == len(cur_block.vex.statements) - 1:
                    continue
                elif isinstance(stmt, pyvex.stmt.IMark) and idx + 1 < len(cur_block.vex.statements) and \
                        isinstance(cur_block.vex.statements[idx + 1], (pyvex.stmt.IMark, pyvex.stmt.AbiHint)):
                    continue

                # Constant-guard Exit pruning + CFG surgery (unchanged logic)
                if isinstance(stmt, pyvex.stmt.Exit) and type(stmt.guard) == pyvex.expr.Const:
                    if stmt.guard.con.value == 0:
                        edge_to_remove_node = None
                        succs = list(dsa_new_model.graph.successors(node))
                        if len(succs) == 2:
                            for succ in succs:
                                if succ.addr == stmt.dst.value and stmt.dst.block_id == succ.block_id:
                                    edge_to_remove_node = succ
                            if not edge_to_remove_node:
                                for succ in succs:
                                    if succ.addr == stmt.dst.value:
                                        import ipdb;
                                        ipdb.set_trace()
                                continue
                            dsa_new_model.graph.remove_edge(node, edge_to_remove_node)
                            nodes_to_remove = nodes_to_remove.union(remove_path(dsa_new_model, start_node))
                        continue
                    elif stmt.guard.con.value == 1:
                        edge_to_remove_node = None
                        succs = list(dsa_new_model.graph.successors(node))
                        if len(succs) == 2:
                            for succ in succs:
                                if succ.addr == node.irsb.next.con.value and node.irsb.next.con.block_id == succ.block_id:
                                    edge_to_remove_node = succ
                            dsa_new_model.graph.remove_edge(node, edge_to_remove_node)
                            nodes_to_remove = nodes_to_remove.union(remove_path(dsa_new_model, start_node))
                        node.irsb.next = pyvex.expr.Const(stmt.dst)
                        continue

                new_statements.append(stmt)

            # If the block becomes empty, splice it out like before
            if not new_statements:
                if len(list(dsa_new_model.graph.successors(node))) > 0:
                    succ = next(dsa_new_model.graph.successors(node))
                    preds = dsa_new_model.graph.predecessors(node)
                    to_remove = False
                    for pred in preds:
                        pred_edge_data = dsa_new_model.graph.get_edge_data(pred, node)
                        if not pred.is_simprocedure:
                            dsa_new_model.graph.add_edge(pred, succ, jumpkind=pred_edge_data['jumpkind'])
                            if len(pred.irsb.statements) > 0 and isinstance(pred.irsb.statements[-1], pyvex.stmt.Exit):
                                if pred.irsb.statements[-1].dst.block_id == node.block_id:
                                    pred.irsb.statements[-1].dst = node.irsb.next.con
                                else:
                                    pred.irsb.next = node.irsb.next
                                if pred.irsb.next.con.block_id == pred.irsb.statements[-1].dst.block_id and \
                                        pred.irsb.statements[-1].dst.value == pred.irsb.next.con.value:
                                    pred.irsb.statements = pred.irsb.statements[:-1]
                            else:
                                pred.irsb.next = node.irsb.next
                            to_remove = True
                        else:
                            print("Not removing this block, since there the previous block is a Sim Procedure")
                    if to_remove:
                        dsa_new_model.graph.remove_node(node)
                else:
                    dsa_new_model.graph.remove_node(node)
            else:
                # Rebuild block once with all removals applied
                node.irsb = pyvex.IRSB.empty_block(
                    node.irsb.arch,
                    node.irsb.addr,
                    statements=new_statements,
                    tyenv=node.irsb.tyenv,
                    nxt=node.irsb.next,
                    direct_next=node.irsb.direct_next,
                    jumpkind=node.irsb.jumpkind,
                    size=node.irsb.size
                )

        dsa_new_model.graph.remove_nodes_from(nodes_to_remove)
        return dsa_new_model

    def remove_action_tracking(self, state):
        ACTION_TRACKING = {
            "TRACK_MEMORY_ACTIONS",
            "TRACK_REGISTER_ACTIONS",
            "TRACK_TMP_ACTIONS",
            "TRACK_JMP_ACTIONS",
            "TRACK_CONSTRAINT_ACTIONS",
            "TRACK_OP_ACTIONS",
            "TRACK_ACTION_HISTORY",
        }
        removed = []
        for opt in ACTION_TRACKING:
            if opt in state.options._options:  # present & True/False stored
                state.options.discard(opt)  # drop the key entirely
                removed.append(opt)
        return removed
    def vmp_remove_bt_rdtsc_insts(self, cfg, inst_to_remove, rdtsc_ins_addr):
        for node in cfg.nodes():
            if not node.is_simprocedure:
                to_remove = set()
                for stmt_idx, stmt in enumerate(node.irsb.statements):
                    if isinstance(stmt, pyvex.stmt.IMark) and stmt.addr in inst_to_remove:
                        skip = True
                    elif isinstance(stmt, pyvex.stmt.IMark) and not(stmt.addr in inst_to_remove):
                        skip = False
                    if skip and isinstance(stmt, pyvex.stmt.Store):
                        # the stores in bt* insts are not tracked by RDA, because the addrs has been crafted using shift and AND operations possibly
                        #removing just the store instrs is enough, as rest will be removed by dead assignment elimination
                        to_remove.add(stmt_idx)

                for stmt_idx, stmt in enumerate(node.irsb.statements):
                    if isinstance(stmt, pyvex.stmt.IMark) and stmt.addr in rdtsc_ins_addr:
                        skip = True
                    elif isinstance(stmt, pyvex.stmt.IMark) and not(stmt.addr in rdtsc_ins_addr):
                        skip = False

                    if skip:
                        to_remove.add(stmt_idx)

                new_statements = []
                for stmt_idx, stmt in enumerate(node.irsb.statements):
                    if stmt_idx not in to_remove:
                        new_statements.append(stmt)
                node.irsb = pyvex.IRSB.empty_block(node.irsb.arch,
                                                   node.irsb.addr,
                                                   statements=new_statements,
                                                   tyenv=node.irsb.tyenv,
                                                   nxt=node.irsb.next,
                                                   direct_next=node.irsb.direct_next,
                                                   jumpkind=node.irsb.jumpkind,
                                                   size=node.irsb.size)
        return cfg
    def inst_count(self, cfg):
        count=0
        for node in cfg.nodes():
            if not node.is_simprocedure:
                for stmt in node.irsb.statements:
                    if isinstance(stmt, pyvex.stmt.IMark):
                        count+=1

        with open('inst_count.txt', 'w') as f:
            f.write(str(count))

    def log_timing_results(self):
        global total_time
        global time_distribution
        import time

        timestr = time.strftime("%Y%m%d_%H%M%S")
        log_file_name = './logs/total_time_' + timestr + ".log"

        with open(log_file_name, 'w') as f:
            for key, value in total_time.items():
                f.write(str(key)+": " + str(value) + "\n")

        timestr = time.strftime("%Y%m%d_%H%M%S")
        log_file_name = './logs/time_distribution_' + timestr + ".log"
        with open(log_file_name, 'w') as f:
            for key, value in time_distribution.items():
                f.write(str(key)+": " + str(value) + "\n")


    def merge_symbolic_expr_locations(self, all_symbolic_expr_locations, cur_symbolic_expr_locations):

        for codeloc, expr in cur_symbolic_expr_locations.keys():
            if (codeloc, expr) not in all_symbolic_expr_locations:
                all_symbolic_expr_locations[(codeloc, expr)] = cur_symbolic_expr_locations[(codeloc, expr)]

        # for block_id, codeloc_dict in cur_symbolic_expr_locations_blockwise.items():
        #     if block_id not in all_symbolic_expr_locations_blockwise:
        #         all_symbolic_expr_locations_blockwise[block_id] = codeloc_dict
        #
        #     else:
        #         for codeloc, expr_list in codeloc_dict.items():
        #             if codeloc not in all_symbolic_expr_locations_blockwise[block_id]:
        #                 all_symbolic_expr_locations_blockwise[block_id] = codeloc_dict
        #             elif set(expr_list) != set(all_symbolic_expr_locations_blockwise[block_id][codeloc]):
        #                 all_expr_set = set()
        #                 for expr in expr_list:
        #                     all_expr_set.add(expr)
        #                 for expr in all_symbolic_expr_locations_blockwise[block_id][codeloc]:
        #                     all_expr_set.add(expr)
        #                 all_symbolic_expr_locations_blockwise[codeloc] = list(all_expr_set)

    def remove_redundant_ip_assignement(self, cfg):
        #
        # 16 | PUT(rip) = 0x00007ff6b5c21414    # remove this stmt
        # NEXT: PUT(rip) = 0x00007ff6b5c21414;
        #
        for node in cfg.graph.nodes():
            if not node.is_simprocedure:
                last_stmt = node.irsb.statements[-1]
                if isinstance(last_stmt, pyvex.stmt.Put) and \
                    last_stmt.offset == self.project.arch.registers['ip'][0] and \
                    isinstance(last_stmt.data, pyvex.expr.Const) and \
                    isinstance(node.irsb.next, pyvex.expr.Const) and \
                    last_stmt.data.result_size(node.irsb.tyenv) == self.project.arch.bits:

                    self._note_change(node)
                    new_statements = node.irsb.statements[:-1]
                    node.irsb = pyvex.IRSB.empty_block(node.irsb.arch,
                                                       node.irsb.addr,
                                                       statements=new_statements,
                                                       tyenv=node.irsb.tyenv,
                                                       nxt=node.irsb.next,
                                                       direct_next=node.irsb.direct_next,
                                                       jumpkind=node.irsb.jumpkind,
                                                       size=node.irsb.size)


        return cfg
    @logtime
    def split_redundant_branch_themida(self, cfg):
        #                     node_A (guard_cond_A)
        #                     /\
        #               l_obfs  r_obfs
        #                     \/
        #              merge_point_node
        #                      |
        #                      |
        #                     node_B (guard_cond_A) same guard as before
        #                     /\
        #          l_undo_obfs  r_undo_obfs
        #                     \/
        #                      |
        #
        # in this pass we split the the above mergepoint node into two copies such that we dont merge and loose information
        # we can do this since the guard for both the branch points are the same
        # TODO: ensure the guard is same and no writes happen between the first and second guard to the values used by the check

        # the start_node, the end_node and the offset to add to the vm_vpc
        to_split_nodes =[]

        for node in cfg.graph.nodes():
            exit_flag = False
            merge_point_node = None
            succs = list(cfg.graph.successors(node))
            cur_vm_vpc = node.vm_vpc
            l_branch = []
            r_branch = []
            # find the left branch and right branch start nodes
            if len(succs) == 2:
                for succ in succs:
                    cur_node = succ
                    no_nodes_in_branch = 0
                    while (len(list(cfg.graph.predecessors(cur_node))) < 2):
                        if len(list(cfg.graph.successors(cur_node))) == 0:
                            exit_flag = True
                            break
                        no_nodes_in_branch+=1
                        cur_node = list(cfg.graph.successors(cur_node))[0]
                    if exit_flag:
                        break

                    if len(list(cfg.graph.predecessors(cur_node))) == 2:
                        merge_point_node = cur_node
                        if no_nodes_in_branch == 2:
                            l_branch.append(succ)
                        elif no_nodes_in_branch == 1:
                            r_branch.append(succ)
                    else:
                        exit_flag = True
                        break
                if exit_flag:
                    continue
                # go till the next branch point with two successors
                cur_node = merge_point_node
                while len(list(cfg.graph.successors(cur_node))) < 2 and cur_vm_vpc == cur_node.vm_vpc:
                    if len(list(cfg.graph.successors(cur_node))) == 0:
                        exit_flag = True
                        break
                    cur_node = list(cfg.graph.successors(cur_node))[0]

                if exit_flag:
                    continue

                if len(list(cfg.graph.successors(cur_node))) == 2:
                    succs = list(cfg.graph.successors(cur_node))
                    # again find the left branch and right branch start nodes for this branch point and add to corresponding list
                    if len(succs) == 2:
                        for succ in succs:
                            cur_node = succ
                            no_nodes_in_branch = 0
                            while (len(list(cfg.graph.predecessors(cur_node))) < 2):
                                no_nodes_in_branch+=1
                                if len(list(cfg.graph.successors(cur_node))) == 0:
                                    exit_flag = True
                                    break
                                cur_node = list(cfg.graph.successors(cur_node))[0]

                            if exit_flag:
                                break

                            if len(list(cfg.graph.predecessors(cur_node))) == 2:
                                if no_nodes_in_branch == 2:
                                    l_branch.append(succ)
                                elif no_nodes_in_branch == 1:
                                    r_branch.append(succ)

                        if len(l_branch) == 2 and len(r_branch) == 2:
                            l_branch.append('l')
                            r_branch.append('r')
                            to_split_nodes.append(l_branch)
                            to_split_nodes.append(r_branch)

        return to_split_nodes
    @logtime
    def split_redundant_branch_obf(self, cfg, saved_same_guard_cond_to_merge):
        def get_new_node(old_node, new_vm_vpc, cfg):
            new_block_id = BlockID(old_node.block_id.addr, old_node.block_id.callsite_tuples,
                                   old_node.block_id.jump_type, new_vm_vpc)
            new_cur_node = CFGENode(old_node.addr,
                                    old_node.size,
                                    cfg,
                                    simprocedure_name=old_node.simprocedure_name,
                                    no_ret=old_node.no_ret,
                                    function_address=old_node.function_address,
                                    block_id=new_block_id,
                                    vm_vpc=new_vm_vpc,
                                    irsb=copy.deepcopy(old_node.irsb),
                                    instruction_addrs=copy.copy(old_node.instruction_addrs),
                                    thumb=copy.copy(old_node.thumb),
                                    byte_string=copy.copy(old_node.byte_string),
                                    is_syscall=old_node.is_syscall,
                                    name=copy.copy(old_node.name))
            return new_cur_node

        def remove_if_stmt(node):
            new_stmts = []
            for stmt in node.irsb.statements:
                if not str(stmt).startswith("If"):
                    import ipdb;ipdb.set_trace()
                    new_stmts.append(stmt)

            node.irsb = pyvex.IRSB.empty_block(node.irsb.arch,
                                               node.irsb.addr,
                                               statements=new_stmts,
                                               tyenv=node.irsb.tyenv,
                                               nxt=node.irsb.next,
                                               direct_next=node.irsb.direct_next,
                                               jumpkind=node.irsb.jumpkind,
                                               size=node.irsb.size)


        nodes_to_remove = set()

        for start_node, end_node, vpc_offset in saved_same_guard_cond_to_merge:
            vpc_offset = ord(vpc_offset)
            assert len(list(cfg.graph.predecessors(start_node))) == 1
            cur_node = list(cfg.graph.predecessors(start_node))[0]
            old_node = list(cfg.graph.predecessors(start_node))[0]

            exit = False
            while True:
                succs = list(cfg.graph.successors(old_node))
                succ = None
                if len(succs) == 2:
                    for succ in succs:
                        if succ == end_node:
                            succ = end_node
                            exit = True
                            break
                        elif succ == start_node:
                            succ = start_node
                            break
                else:
                    succ = succs[0]
                nodes_to_remove.add(succ)
                new_succ = get_new_node(succ, succ.block_id.vm_vpc + vpc_offset, cfg)
                # if exit:
                #     remove_if_stmt(new_succ)
                prev_edge_data = cfg.graph.get_edge_data(old_node, succ)
                cfg.graph.add_edge(cur_node, new_succ, jumpkind=prev_edge_data['jumpkind'])
                ## add to _nodes and _node_by_addr
                cfg.add_node(new_succ.block_id, new_succ)

                if succ == start_node:
                    cfg.graph.remove_edge(old_node, succ)

                cur_node = new_succ
                old_node = succ
                if exit:
                    break
            assert len(list(cfg.graph.successors(old_node))) == 1

            prev_edge_data = cfg.graph.get_edge_data(succ, list(cfg.graph.successors(old_node))[0])
            cfg.graph.add_edge(cur_node, list(cfg.graph.successors(old_node))[0], jumpkind=prev_edge_data['jumpkind'])

        for node in nodes_to_remove:
            cfg.graph.remove_node(node)
            # remove from _nodes
            cfg.remove_node(node.block_id, node)

        return cfg
    @logtime
    def remove_segment_selector_vex_inst(self, cfg):
        if self.project.arch.bits == 32:
            for node in cfg.nodes():
                if node.is_simprocedure:
                    continue

                new_statements = []
                for stmt in node.irsb.statements:
                    new_stmt = stmt
                    if isinstance(stmt, pyvex.stmt.WrTmp) and isinstance(stmt.data, pyvex.expr.CCall) and stmt.data.cee.name == "x86g_use_seg_selector":
                        if stmt.data.args[2].con.value == 0 and isinstance(stmt.data.args[3], pyvex.expr.RdTmp):
                            if node.irsb.tyenv.lookup(stmt.data.args[3].tmp) == "Ity_I32" and stmt.data.ret_type == "Ity_I64":
                                new_stmt = pyvex.stmt.WrTmp(stmt.tmp, pyvex.expr.Unop("Iop_32Uto64", [stmt.data.args[3]]))
                    new_statements.append(new_stmt)


                node.irsb.statements = new_statements

        return cfg

    def pickle_dump_load_cfg(self, cfg, pickled_file_name, dump_or_load=None,):
        if dump_or_load is None:
            return

        if dump_or_load == "dump":
            # Debugging snapshots: nothing in the pipeline or in PUSHAN-evaluation reads them
            # back, and they run ~25 MB apiece. The commented-out LOAD call sites need them,
            # so keep a way to turn them back on.
            if not _project_bool_attr(self.project, "vm_deob_dump_cfg_pickles", False):
                return cfg
            try:
                with open(pickled_file_name,'wb') as final_cfg_pickle:
                    pickle.dump(cfg, final_cfg_pickle)
            except:
                print("error while dumping pickle")
                # import ipdb;ipdb.set_trace()
            return cfg
        elif dump_or_load == "load":
            try:
                with open(pickled_file_name, "rb") as final_cfg_pickle:
                    new_cfg = pickle.load(final_cfg_pickle)
            except:
                print("error while loading")
                import ipdb;ipdb.set_trace()
            # since the hash is not same after loading from pickle
            for node in new_cfg.nodes():
                node.block_id._hash = None
            return new_cfg

    @logtime
    def try_decompilation(self, new_cfg, decomp_start_end_node_str=None, decomp_function_addresses=None, decomp_function_prototypes=None,
                          semantic_verf_hooks=[], decomp_main_func_prototype=None, calls_as_rets={}, allow_global_dead_ass_elim=False,
                          ail_propagator_init_values=None):
        visited_nodes = {}
        if decomp_start_end_node_str is not None:
            traversal_start_node = decomp_start_end_node_str[0][0]
            end_points = decomp_start_end_node_str[1]
        else:
            traversal_start_node = None
            end_points = None
        end_node_block_ids = []
        node_stack = []
        start_node= None
        for cur_node in new_cfg.nodes():
            # If the decomp start end node str is provided then use that
            if decomp_start_end_node_str is not None:
                if str(cur_node) == traversal_start_node:
                    node_stack.append(cur_node)
                    start_node = cur_node
                elif str(cur_node) in end_points:
                    end_node_block_ids.append(cur_node.block_id)
            else:
                if new_cfg.graph.in_degree(cur_node) == 0:
                    start_node = cur_node
                    node_stack.append(cur_node)
                elif new_cfg.graph.out_degree(cur_node) == 0:
                    end_node_block_ids.append(cur_node.block_id)
        VM_1_func = Function(self.project.kb.functions, self.convert_addr_to_int(start_node.addr, start_node.block_id), 'VM_1', None, is_simprocedure=False)
        #set the calling convention
        VM_1_func.calling_convention = self.project.factory._default_cc(self.project.arch)
        # prototype for toy samples
        VM_1_func.prototype = decomp_main_func_prototype

        self.project.kb.functions[VM_1_func.addr] = VM_1_func
        VM_1_func.startpoint = start_node

        decomp_model = self.project.kb.cfgs.new_model("decomp_graph")
        decomp_model.graph = networkx.DiGraph()
        new_block_id_embed_dict = {}
        # This stores all the returns that are actually calls for later adjusting the stack args location in callsite_maker.py
        # These are addresses for huffman, that are manually specified becasue the Rets are already converted to calls in replace_jumpkinds, so we loos that information when using pickled cfg
        #calls_as_rets = {0x41f6bb: 'Ijk_Ret', 0x41c6c2: 'Ijk_Ret', 0x461de0: 'Ijk_Ret', 0x451af1: 'Ijk_Ret'}
        ## convert to new encoded addresses
        for node in new_cfg.nodes():
            if not node.is_simprocedure:
                for stmt_idx, stmt in enumerate(node.irsb.statements):
                    if isinstance(stmt, pyvex.stmt.IMark) and stmt.addr in calls_as_rets:
                        calls_as_rets[self.convert_addr_to_int(node.addr, node.block_id, stmt_idx)] = calls_as_rets[stmt.addr]

        ## Populate nodes in the VM_1 func
        while len(node_stack) > 0:
            cur_node = node_stack.pop(0)
            if cur_node.block_id in end_node_block_ids or cur_node.block_id in visited_nodes:
                continue
            visited_nodes[cur_node.block_id] = True
            succs = new_cfg.get_successors(cur_node)
            node_stack = succs + node_stack

            # Don't add sim procs
            if cur_node.is_simprocedure or cur_node.addr in decomp_function_addresses:
                continue

            # new block_id for cur_node
            #new_cur_node = copy.deepcopy(cur_node)
            new_cur_node, calls_as_rets = self.create_new_node_with_block_id_addr(cur_node, decomp_model, new_cfg, new_block_id_embed_dict,
                                                                   end_node_block_ids,
                                                                   decomp_function_addresses=decomp_function_addresses,
                                                                   calls_as_rets=calls_as_rets)
            if str(cur_node) == traversal_start_node or (traversal_start_node is None and cur_node is start_node):
                VM_1_func.startpoint = new_cur_node
            if len(new_cfg.nodes()) == 1:
                #ONLY ONE NODE IN THE FUNCTION
                VM_1_func._register_node(True, new_cur_node)
            for succ in succs:
                if succ.is_simprocedure:
                    succ_func = None
                    # succ_func = Function(self.project.kb.functions, succ.addr, None, None, is_simprocedure=True)
                    # succ_func.calling_convention = self.project.factory._default_cc(self.project.arch)
                    succ_proc=None
                    for name_addr, sim_proc in semantic_verf_hooks:
                        if isinstance(name_addr, str) and succ.name == name_addr:
                            succ_proc = sim_proc
                        elif isinstance(name_addr, int) and succ.addr == name_addr:
                            succ_proc = sim_proc

                    if succ_proc:
                        succ_func=self.project.kb.functions.function(succ.addr, create=True)
                        # get the prototype from the sim procedure
                        succ_func.prototype = succ_proc.prototype
                        if succ_func.prototype._arch is None:
                            succ_func.prototype._arch = self.project.arch
                            succ_func.prototype.returnty._arch = self.project.arch
                        succ_func.calling_convention = succ_proc.cc
                    else:
                        # probably a Nop simprocedure so we try to get the prototype from the hooks
                        succ_func=self.project.kb.functions.function(succ.addr, create=True)
                        # get the prototype from the hooks
                        succ_func.prototype = self.project.hooked_by(succ_func.addr).prototype
                        succ_func.calling_convention = self.project.hooked_by(succ_func.addr).cc
                        if succ_func.prototype._arch is None:
                            succ_func.prototype._arch = self.project.arch
                            if succ_func.prototype.returnty:
                                succ_func.prototype.returnty._arch = self.project.arch
                        if succ_func.calling_convention is None:
                            succ_func.calling_convention = self.project.factory._default_cc(self.project.arch)

                        if self.project.hooked_by(succ_func.addr).display_name:
                            succ_func.name = self.project.hooked_by(succ_func.addr).display_name

                    succ_func.returning = True
                    succ_func.is_simprocedure = True
                    sim_proc_succ = new_cfg.get_successors(succ)

                    #special check for exit() loops, which we ignore
                    if sim_proc_succ[0] is succ and succ_func.name == "exit":
                        continue
                    new_succ, calls_as_rets = self.create_new_node_with_block_id_addr(sim_proc_succ[0], decomp_model, new_cfg,
                                                                       new_block_id_embed_dict,
                                                                       end_node_block_ids,
                                                                       decomp_function_addresses=decomp_function_addresses,
                                                                       calls_as_rets=calls_as_rets)

                    VM_1_func._call_to(new_cur_node, succ_func, new_succ)
                    VM_1_func._return_from_call(succ_func, new_succ)

                    #
                    # # Don't add sim procs
                    # sim_proc_succ = new_cfg.get_successors(succ)
                    # if len(sim_proc_succ) > 1:
                    #     import ipdb;ipdb.set_trace()
                    # else:
                    #     new_succ = self.create_new_node_with_block_id_addr(sim_proc_succ[0], decomp_model, new_cfg, new_block_id_embed_dict)
                    #     VM_1_func._transit_to(new_cur_node, new_succ)
                    continue
                elif succ.addr in decomp_function_addresses:
                    #succ_func = Function(self.project.kb.functions, succ.addr, decomp_function_addresses[succ.addr][1], None, is_simprocedure=False)
                    succ_func = self.project.kb.functions.function(succ.addr, decomp_function_addresses[succ.addr][1], create=True)
                    succ_func.is_simprocedure = False

                    succ_func.calling_convention = self.project.factory._default_cc(self.project.arch)

                    if succ.addr in decomp_function_prototypes:
                        self.project.kb.callsite_prototypes.set_prototype(new_cur_node.addr,
                                                                          self.project.factory._default_cc(self.project.arch),
                                                                          decomp_function_prototypes[succ.addr],
                                                                          manual=True)
                        succ_func.prototype = decomp_function_prototypes[succ.addr]

                    if succ_func.prototype:
                        succ_func.prototype = succ_func.prototype.with_arch(self.project.arch)
                    succ_func.returning = True

                    func_node = succ
                    func_stack = [func_node]
                    # skip the functions nodes, and add only the return node
                    while len(func_stack) != 0:
                        cur_func_node = func_stack.pop(0)
                        if cur_func_node.block_id in visited_nodes:
                            continue
                        # mark these as visited so that we don't visit them again in the outer loop
                        visited_nodes[cur_func_node.block_id] = True

                        if cur_func_node.addr in decomp_function_addresses[succ.addr][0]:
                            func_ret_node = new_cfg.get_successors(cur_func_node)[0]
                            new_func_ret_node, calls_as_rets = self.create_new_node_with_block_id_addr(func_ret_node, decomp_model, new_cfg,
                                                                               new_block_id_embed_dict,
                                                                                end_node_block_ids,
                                                                               decomp_function_addresses=decomp_function_addresses,
                                                                                calls_as_rets=calls_as_rets)
                            VM_1_func._call_to(new_cur_node, succ_func, new_func_ret_node)
                            VM_1_func._return_from_call(succ_func, new_func_ret_node)
                            node_stack = [func_ret_node] + node_stack
                            continue


                        func_stack = new_cfg.get_successors(cur_func_node) + func_stack
                    continue


                new_succ, calls_as_rets = self.create_new_node_with_block_id_addr(succ, decomp_model, new_cfg, new_block_id_embed_dict,
                                                                   end_node_block_ids,
                                                                   decomp_function_addresses=decomp_function_addresses,
                                                                   calls_as_rets=calls_as_rets)
                VM_1_func._transit_to(new_cur_node, new_succ)

        VM_1_func.normalized = True
        ## Add ret sites so that register_save_are_simplifier works
        for node in VM_1_func.transition_graph.nodes():
            if len(list(VM_1_func.transition_graph.successors(node))) == 0:
                VM_1_func._ret_sites.add(node)
                if len(list(VM_1_func.transition_graph.predecessors(node))) > 0:
                    VM_1_func._ret_sites.add(list(VM_1_func.transition_graph.predecessors(node))[0])

        # self.create_virtualized_func_svg(VM_1_func, decomp_function_addresses)

        self.project.new_block_id_embed_dict = new_block_id_embed_dict

        # The nodes of the virtualized function live at synthetic addresses with no bytes behind
        # them. Register their IRSBs so that every analysis that lifts a block by address (calling
        # convention recovery, the stack-pointer tracker, ...) sees the deobfuscated code.
        for node in VM_1_func.transition_graph.nodes():
            node_irsb = getattr(node, "irsb", None)
            if node_irsb is not None:
                self.project.synthetic_irsbs[node.addr] = node_irsb

        dec = self.project.analyses.Decompiler(VM_1_func, calls_as_rets=calls_as_rets, allow_global_dead_ass_elim=allow_global_dead_ass_elim,
                                               ail_propagator_init_values=ail_propagator_init_values,
                                               vm_deobfuscation=True)

        # import ipdb;ipdb.set_trace()
        with open("last_decomp_result.c", "w") as f:
            f.write(dec.codegen.text)

        pretty_dump_ail_cfg(dec.clinic.cc_graph, self.project)

        import pickle
        pickled_file_name = self.project_dir / "raw_ail_pickle.pickle"
        with open(pickled_file_name, 'wb') as f:
            pickle.dump(dec.clinic.cc_graph, f)

    @logtime
    @detects_changes
    def CAS_to_mov_simplification(self, cfg, proj):
        # this is specifically for themida to convert CAS stmts to simple store stmts if the comparision is always True
        # only for converting CAS from xchg to simple stores
        print("CAS simplification")
        for node in cfg.nodes():
            if node.is_simprocedure:
                continue
            new_stmts = []
            for stmt in node.irsb.statements:
                if isinstance(stmt, pyvex.stmt.IMark):
                    cur_ins_addr = stmt.addr
                if isinstance(stmt, pyvex.stmt.CAS):
                    bbl=self.project.factory.block(cur_ins_addr, num_inst=1)
                    cas_ins = bbl.disassembly.insns[0]
                    if cas_ins.mnemonic == "xchg":
                        new_stmts.append(pyvex.stmt.WrTmp(stmt.oldLo, pyvex.expr.Load(stmt.endness, node.irsb.tyenv.lookup(stmt.oldLo), stmt.addr)))
                        new_stmts.append(pyvex.stmt.Store(stmt.addr, stmt.dataLo, stmt.endness))
                        continue

                new_stmts.append(stmt)
            node.irsb = pyvex.IRSB.empty_block(node.irsb.arch,
                                               node.irsb.addr,
                                               statements=new_stmts,
                                               tyenv=node.irsb.tyenv,
                                               nxt=node.irsb.next,
                                               direct_next=node.irsb.direct_next,
                                               jumpkind=node.irsb.jumpkind,
                                               size=node.irsb.size)

        return cfg
    def emulated_stack_pointer_tracker(self, cfg, proj, start_state=None, start_addr=None):
        start_state = proj.factory.blank_state(addr=start_addr, add_options={angr.sim_options.REPLACEMENT_SOLVER, angr.sim_options.DO_CCALLS})
        actual_stack_end = start_state.solver.eval(start_state.regs.sp)
        start_state.regs.sp = start_state.solver.BVS("precon_sp", proj.arch.bits)
        start_state.preconstrainer.preconstrain(actual_stack_end, start_state.regs.sp)
        print(start_state.regs.sp)
        new_model = self.new_model_graph(cfg.graph, proj, 'stack_pointer_tracker')
        new_model._nodes_by_addr[self.start_addr][0].input_state = start_state
        spt = proj.analyses.EmulatedStackPointerTracker(model=new_model, keep_state=True, iropt_level=1,
                                                   resolve_indirect_jumps=True)
        return spt
    def create_virtualized_func_svg(self, virt_func, decomp_function_addresses):
        for i in range(1):
            all_nodes = list(virt_func.transition_graph.nodes())
            nodes_to_remove = []
            for node in all_nodes:
                preds = list(virt_func.transition_graph.predecessors(node))
                succs = list(virt_func.transition_graph.successors(node))

                if len(preds) == 1 and len(succs) == 1 and not node.is_simprocedure:
                    succ_of_preds = list(virt_func.transition_graph.successors(preds[0]))
                    pred_of_succs = list(virt_func.transition_graph.predecessors(succs[0]))
                    if len(pred_of_succs) == 1 and len(succ_of_preds) == 1:
                        nodes_to_remove.append(node)

            for node in nodes_to_remove:
                preds = list(virt_func.transition_graph.predecessors(node))
                succs = list(virt_func.transition_graph.successors(node))

                virt_func.transition_graph.remove_node(node)
                virt_func.transition_graph.add_edge(preds[0], succs[0])

        for edge in list(virt_func.transition_graph.edges()):
            if 'type' in virt_func.transition_graph.get_edge_data(edge[0], edge[1]) \
                    and virt_func.transition_graph.get_edge_data(edge[0], edge[1])['type'] == 'fake_return':
                virt_func.transition_graph.remove_edge(edge[0],edge[1])

        A = nx.nx_agraph.to_agraph(as_networkx(virt_func.transition_graph))

        for node in virt_func.transition_graph.nodes():
            graphviz_node = A.get_node(str(node))
            if node.is_simprocedure:
                graphviz_node.attr["label"] = node.name
            elif node.addr in decomp_function_addresses:
                import ipdb;ipdb.set_trace()
                graphviz_node.attr["label"] = decomp_function_addresses[node.addr][1]
            else:
                graphviz_node.attr["label"] = ""
            graphviz_node.attr["shape"] = "box"

        A.layout(prog="dot")
        A.draw(path="./graph_for_paper.svg", format="svg")

    def find_exit_stmt(self, irsb):

        for stmt_idx, stmt in reversed(list(enumerate(irsb.statements))):
            # ignore the exits created by popf and trap flag checks for single stepping
            if isinstance(stmt, pyvex.stmt.Exit) and stmt.jumpkind not in ["Ijk_EmWarn"]:
                return stmt, stmt_idx
        return None, None

    def create_new_node_with_block_id_addr(self, old_node, new_model, old_graph, new_block_id_embed_dict, end_node_block_ids,
                                           decomp_function_addresses=[],
                                           calls_as_rets={}):
        if old_node.block_id in new_block_id_embed_dict:
            return new_block_id_embed_dict[old_node.block_id], calls_as_rets

        new_jumpkind = old_node.irsb.jumpkind
        new_statements = old_node.irsb.statements
        new_next = old_node.irsb.next
        if old_node.is_simprocedure:
            return old_node, calls_as_rets

        successors = list(old_graph.graph.successors(old_node))
        is_ret_node = False
        if old_node.block_id in end_node_block_ids:
            is_ret_node = True

        if is_ret_node:
            new_jumpkind = "Ijk_Ret"

        elif len(successors) != 0:
            if old_node.irsb.jumpkind in ["Ijk_Ret", "Ijk_Boring"] and (successors[0].is_simprocedure or successors[0].addr in decomp_function_addresses):
                new_jumpkind = "Ijk_Call"

            elif old_node.irsb.jumpkind == "Ijk_Call":
                if len(successors) > 1:
                    import ipdb;ipdb.set_trace()
                elif len(successors) == 1 and not successors[0].is_simprocedure and successors[0].addr not in decomp_function_addresses:
                    new_jumpkind = "Ijk_Boring"

            elif old_node.irsb.jumpkind == "Ijk_Ret" and not successors[0].is_simprocedure and successors[0].addr not in decomp_function_addresses:
                new_jumpkind = "Ijk_Boring"

            same_ip = False
            if len(successors) == 2 and successors[0].addr == successors[1].addr:
                same_ip = True

            orig_exit_stmt, orig_exit_stmt_idx = self.find_exit_stmt(old_node.irsb)
            # replace indirect jumps that are acutally a branch, by adding exit statement
            if len(successors) == 2 and not orig_exit_stmt and not same_ip:
                new_jumpkind = "Ijk_Boring"


                cmp_tmp_no = len(old_node.irsb.tyenv.types)
                true_addr_enc = self.convert_addr_to_int(successors[0].addr, successors[0].block_id)
                true_addr_int = successors[0].addr
                if self.project.arch.bits == 64:
                    true_addr = pyvex.expr.Const(U64(true_addr_int))
                    false_addr_enc = self.convert_addr_to_int(successors[1].addr, successors[1].block_id)
                    jmp_tmp_no = old_node.irsb.next.tmp
                    cmp_stmt = pyvex.stmt.WrTmp(cmp_tmp_no, pyvex.expr.Binop("Iop_CmpEQ64", [true_addr, pyvex.expr.RdTmp(jmp_tmp_no)]))
                    new_exit_stmt = pyvex.stmt.Exit(pyvex.expr.RdTmp(cmp_tmp_no),
                                    U64(true_addr_enc),
                                    "Ijk_Boring",
                                    self.project.arch.registers['ip'][0])

                    new_statements = new_statements + [cmp_stmt, new_exit_stmt]
                    new_next = pyvex.expr.Const(U64(false_addr_enc))
                elif self.project.arch.bits == 32:
                    true_addr = pyvex.expr.Const(U32(true_addr_int))
                    false_addr_enc = self.convert_addr_to_int(successors[1].addr, successors[1].block_id)

                    jmp_tmp_no = old_node.irsb.next.tmp
                    cmp_stmt = pyvex.stmt.WrTmp(cmp_tmp_no, pyvex.expr.Binop("Iop_CmpEQ32",
                                                                             [true_addr, pyvex.expr.RdTmp(jmp_tmp_no)]))
                    new_exit_stmt = pyvex.stmt.Exit(pyvex.expr.RdTmp(cmp_tmp_no),
                                                U32(true_addr_enc),
                                                "Ijk_Boring",
                                                self.project.arch.registers['ip'][0])

                    new_statements = new_statements + [cmp_stmt, new_exit_stmt]
                    new_next = pyvex.expr.Const(U32(false_addr_enc))
                else:
                    import ipdb;ipdb.set_trace()

                old_node.irsb.tyenv.types.append('Ity_I1')

            elif len(successors) == 2 and orig_exit_stmt and not same_ip:
                # For existing branches we need to replace the addrs with the new hashed addresses
                true_addr_block_id = None
                false_addr_block_id = None
                for succ in successors:
                    if succ.addr == orig_exit_stmt.dst.value and succ.block_id == orig_exit_stmt.dst.block_id:
                        true_addr_block_id = succ.block_id
                    elif succ.addr == old_node.irsb.next.con.value and succ.block_id == old_node.irsb.next.con.block_id:
                        false_addr_block_id = succ.block_id
                    else:
                        import ipdb;ipdb.set_trace()

                true_addr_int = self.convert_addr_to_int(orig_exit_stmt.dst.value, true_addr_block_id)

                false_addr_int = self.convert_addr_to_int(old_node.irsb.next.con.value, false_addr_block_id)

                # a synthetic address is as wide as the architecture; typing it as U32 on a 64-bit
                # target leaves a 32-bit Const holding a 64-bit value
                addr_const = U64 if self.project.arch.bits == 64 else U32
                new_exit_stmt = pyvex.stmt.Exit(pyvex.expr.RdTmp(orig_exit_stmt.guard.tmp),
                                            addr_const(true_addr_int),
                                            "Ijk_Boring",
                                            self.project.arch.registers['ip'][0])
                new_next = pyvex.expr.Const(addr_const(false_addr_int))
                new_statements = new_statements[:orig_exit_stmt_idx] + [new_exit_stmt] + new_statements[orig_exit_stmt_idx+1:]

        elif len(successors) == 0 and old_node.irsb.jumpkind == "Ijk_Call":
            new_jumpkind = "Ijk_Ret"
            ## Last node return from here?

        # A block that just falls through to one successor still carries the original jump target.
        # angr's structuring reads that target to tell which successor a branch reaches, so leaving
        # an address that names no block in the graph costs us the whole region.
        if (
            new_jumpkind == "Ijk_Boring"
            and len(successors) == 1
            and isinstance(new_next, pyvex.expr.Const)
            and not successors[0].is_simprocedure
            and successors[0].addr not in decomp_function_addresses
        ):
            succ_addr_enc = self.convert_addr_to_int(successors[0].addr, successors[0].block_id)
            new_next = pyvex.expr.Const(U64(succ_addr_enc) if self.project.arch.bits == 64 else U32(succ_addr_enc))

        # Every instruction of this node is numbered inside the node's own reserved range, so that
        # the node's address (which is what branch targets are encoded from) is also the address of
        # its first instruction. The AIL block takes its address from the first IMark.
        block_id_int = self.convert_addr_to_int(old_node.addr, old_node.block_id)
        new_addr = block_id_int#<<36 + old_node.addr
        synthetic_ins_addrs = []
        for stmt_idx, stmt in enumerate(new_statements):
            if isinstance(stmt, pyvex.stmt.IMark):
                enc_addr = new_addr if not synthetic_ins_addrs else new_addr + stmt_idx
                self.project.enc_stmt_addr_to_original[enc_addr] = (stmt.addr, stmt_idx, old_node.block_id)
                stmt.addr = enc_addr
                synthetic_ins_addrs.append(enc_addr)

        # The node covers its synthetic instruction addresses, not the original byte range.
        synthetic_size = (max(synthetic_ins_addrs) - new_addr + 1) if synthetic_ins_addrs else old_node.size
        # for stmt in old_node.irsb.statements:
        #     if type(stmt) is pyvex.IRStmt.IMark:
        #         stmt.addr = block_id_int<<36+stmt.addr

        if old_node.irsb.jumpkind in ["Ijk_Ret"] and new_jumpkind == "Ijk_Call":
            for stmt in new_statements:
                if isinstance(stmt, pyvex.stmt.IMark):
                    last_ins_addr = stmt.addr
            calls_as_rets[last_ins_addr]="Ijk_Ret"

        new_irsb= pyvex.IRSB.empty_block(old_node.irsb.arch,
                                           new_addr,
                                           statements=new_statements,
                                           tyenv=old_node.irsb.tyenv,
                                           nxt=new_next,
                                           direct_next=old_node.irsb.direct_next,
                                           jumpkind=new_jumpkind,
                                           size=synthetic_size)
        new_cur_node = CFGENode(new_addr,
                                synthetic_size,
                                new_model,
                                simprocedure_name=old_node.simprocedure_name,
                                no_ret=old_node.no_ret,
                                function_address=old_node.function_address,
                                block_id=old_node.block_id,
                                irsb=new_irsb,
                                instruction_addrs=synthetic_ins_addrs or old_node.instruction_addrs,
                                thumb=old_node.thumb,
                                byte_string=old_node.byte_string,
                                is_syscall=old_node.is_syscall,
                                name=old_node.name)
        new_block_id_embed_dict[old_node.block_id] = new_cur_node
        return new_cur_node, calls_as_rets

    #: Synthetic block addresses are allocated from here upwards. Chosen to sit far above any real
    #: mapping while still fitting in 64 bits, which AIL requires.
    SYNTHETIC_ADDR_BASE = 0x7000_0000_0000_0000
    #: Each (block context, address) pair reserves this much address space, so that every
    #: instruction of a block lands inside [block addr, block addr + block size). Analyses that map
    #: an instruction address back to its block -- the stack pointer tracker, most importantly --
    #: rely on that containment.
    SYNTHETIC_BLOCK_STRIDE = 0x1_0000

    def convert_addr_to_int(self, addr, block_id, stmt_idx=0):
        """
        Give (block context, address, statement) a unique synthetic address.

        The original encoding packed the decimal digits of the VM program counter, the address and
        the statement index into one integer, which routinely ran past 64 bits; AIL addresses are
        u64. Reserve one contiguous range per block instead and keep the reverse map, which is the
        only thing any caller reads back.
        """
        key = (block_id.vm_vpc if block_id else None, addr)
        block_base = self._synthetic_addrs.get(key)
        if block_base is None:
            block_base = self.SYNTHETIC_ADDR_BASE + len(self._synthetic_addrs) * self.SYNTHETIC_BLOCK_STRIDE
            self._synthetic_addrs[key] = block_base
        assert stmt_idx < self.SYNTHETIC_BLOCK_STRIDE
        enc_addr = block_base + stmt_idx
        self.project.enc_stmt_addr_to_original[enc_addr] = (addr, stmt_idx, block_id)
        return enc_addr

    @detects_changes
    def remove_call_to_next_addr(self, cfg):
        #:0429040A call    $+5
        #:0429040F push    [esp+1Ch+var_1C]
        # In this case we just change the jumpkind from call to boring
        # This call just jumps to the next address, the return address is still on the stack though

        for node in cfg.nodes():
            if node.is_simprocedure:
                continue
            if node.irsb.jumpkind == "Ijk_Call" and isinstance(node.irsb.statements[-1], pyvex.stmt.Store) and \
                    isinstance(node.irsb.statements[-1].data, pyvex.expr.Const) and isinstance(node.irsb.next, pyvex.expr.Const):
                if node.irsb.statements[-1].data.con.value == node.irsb.next.con.value:
                    node.irsb.jumpkind = "Ijk_Boring"

        return cfg

    @logtime
    def replace_jumpkinds(self, new_cfg):
        # TO DO: replace the instructions, can't just replace return with call, semantics change
        calls_as_rets = {}
        for node in new_cfg.nodes():
            succs = list(new_cfg.get_successors(node))
            if len(succs) == 1 and not node.is_simprocedure and node.irsb.jumpkind == "Ijk_Ret":
                if succs[0].is_simprocedure:
                    node.irsb.jumpkind = "Ijk_Call"
                    for stmt in reversed(node.irsb.statements):
                        if isinstance(stmt, pyvex.stmt.IMark):
                            calls_as_rets[stmt.addr] = "Ijk_Ret"
                            break
                elif len(succs[0].irsb.statements) < 2:
                    # the succ is probaby just a jump to the simprocedure
                    succs_of_succ = list(new_cfg.get_successors(succs[0]))
                    if len(succs_of_succ) == 1:
                        if succs_of_succ[0].is_simprocedure:
                            node.irsb.jumpkind = "Ijk_Call"
                            for stmt in reversed(node.irsb.statements):
                                if isinstance(stmt, pyvex.stmt.IMark):
                                    calls_as_rets[stmt.addr] = "Ijk_Ret"
                                    break

        return new_cfg, calls_as_rets

    @logtime
    def symbolizer(self, cfg, proj, start_addr, q, start_state=None, options=None,
                             prev_symbolic_expr_locations=None, vm_vpc=None,
                             return_symbolic_expr_locations_blockwise=None, new_cfg=None, prev_unroll_vm_addrs=None,
                   do_replacements=False, constant_prop_level=0):
        self.project.prev_symbolic_expr_locations = prev_symbolic_expr_locations
        print("Doing constant propagation or symbolizing")
        # old_graph = cfg.graph
        # new_model = self.new_model_graph(old_graph, proj, "temporary1")
        # new_cfg_graph = new_model.graph
        new_model = cfg
        new_cfg_graph = cfg.graph

        ## Setting the input state for the first node(need to automate this)
        if start_addr == None:
            main = proj.loader.main_object.get_symbol("main")
            start_addr = main.rebased_addr
        if start_state:
            initial_input_state = start_state.copy()
        else:
            print("Using blank state!")
            # kwargs = {'plugins': {'memory': DefaultListPagesMemory(memory_id="mem")}, 'cle_memory_backer':proj.loader, }#,
            #                       #'registers': TopListPagesMemory(memory_id="reg")}}
            initial_input_state = proj.factory.blank_state(addr=start_addr, mode="fastpath",
                                                           add_options={'REPLACEMENT_SOLVER', 'DO_CCALLS',
                                                                        'SYMBOL_FILL_UNCONSTRAINED_REGISTERS',
                                                                        'SYMBOL_FILL_UNCONSTRAINED_MEMORY',
                                                                        'TOP_LIST_REGISTERS_SYMBOLIZER',
                                                                        'TOP_LIST_MEMORY_SYMBOLIZER'})  # 'REPLACEMENT_SOLVER' removed to test the spped without replacements
            # initial_input_state.register_plugin('partial_symbolic_constraint_solver', angr.state_plugins.solver.SimSolver(solver=claripy.solvers.SolverComposite()))

            # initial_input_state.register_plugin('partial_symbolic_constraint_solver',
            #                                     angr.state_plugins.solver.SimSolver(
            #                                         claripy.solvers.SolverReplacement(claripy.Solver(timeout=1200000),
            #                                                                           unsafe_replacement=True,
            #                                                                           auto_replace=False)))  # auto replace needs to be Fals otherwiseit will wrongly replace constraints that start with NOT to False

            fast_exact = claripy.solvers.SolverCacheless(track=False, timeout=1200000)

            repl = claripy.solvers.SolverReplacement(
                actual_frontend=fast_exact,
                unsafe_replacement=True,
                auto_replace=False,
            )

            initial_input_state.register_plugin('solver', angr.state_plugins.solver.SimSolver(repl))

            fast_exact = claripy.solvers.SolverCacheless(track=False, timeout=1200000)

            repl = claripy.solvers.SolverReplacement(
                actual_frontend=fast_exact,
                unsafe_replacement=True,
                auto_replace=False,
            )

            initial_input_state.register_plugin(
                'partial_symbolic_constraint_solver',
                AndingSimSolver(repl)
            )

            if proj.arch.bits == 32:
                initial_input_state.registers.store('ss', 0)

            # preconstrain the stack pointer
            actual_stack_end = initial_input_state.solver.eval(initial_input_state.regs.sp)
            initial_input_state.regs.sp = initial_input_state.solver.BVS("precon_sp", self.project.arch.bits)
            initial_input_state.preconstrainer.preconstrain(actual_stack_end, initial_input_state.regs.sp)

            initial_input_state.partial_symbolic_constraint_solver.add(initial_input_state.regs.sp == actual_stack_end)
            # We do not add this to replacements so that it does not replace sp in symbolizer(making it a constant), when performing the replacemnts
            # on the regs and temps to replace the symb_unconstained to state_split_cond variables (in _perform_vex_expr_Load)
            # initial_input_state.partial_symbolic_constraint_solver._solver.add_replacement(initial_input_state.regs.sp,
            #                                      actual_stack_end,
            #                                      invalidate_cache=False)
            initial_input_state.globals['sp_constraint'] = initial_input_state.regs.sp == actual_stack_end
            initial_input_state.globals['sp_start_value'] = actual_stack_end
            initial_input_state.globals['concretized_load_addr_dict'] = {}
            initial_input_state.globals['replaced_asts_str'] = {}
            initial_input_state.globals['existing_mba_split_constraints'] = []
            initial_input_state.globals['mba_locs'] = {}
            initial_input_state.globals['constant_prop_level'] = constant_prop_level
            initial_input_state.globals['same_sp_merged'] = False
            initial_input_state.globals['no_one_soln_cache'] = {}
            initial_input_state.globals['no_constraints_solver'] = claripy.solvers.SolverReplacement(claripy.Solver(timeout=500000),
                                                                                      unsafe_replacement=True,
                                                                                      auto_replace=False)

            def preconstrain_return_value(state):
                if state.inspect.simprocedure_name == "malloc" and state.inspect.simprocedure_result is not None and not state.solver.symbolic(
                        state.inspect.simprocedure_result):
                    value = state.solver.eval(state.inspect.simprocedure_result)
                    state.inspect.simprocedure_result = state.solver.BVS("return_val", 64)
                    state.preconstrainer.preconstrain(value, state.inspect.simprocedure_result)
                return

            ### preconstraining return values of library calls like malloc
            initial_input_state.inspect.add_breakpoint('simprocedure', BP(BP_AFTER, action=preconstrain_return_value))

        if do_replacements:
            initial_input_state.globals['is_constant_propagation'] = True
            initial_input_state.globals['is_symbolizer'] = False

        else:
            initial_input_state.globals['is_constant_propagation'] = False
            initial_input_state.globals['is_symbolizer'] = True

        ####### Adding breakpoints
        def annotate_stack_read_value(state):
            is_stack_touched = False
            if not isinstance(state.inspect.mem_read_address, int):
                for annotation in state.inspect.mem_read_address.annotations:
                    if isinstance(annotation, StackTouchedAnnotation):
                        is_stack_touched = True
                        break
            if is_stack_touched:
                state.inspect.mem_read_expr = annotate_with_new_replacements(state, state.inspect.mem_read_expr,
                                                                             StackTouchedAnnotation(1))
        self.remove_action_tracking(initial_input_state)


        ## annotating and preconstraining the stack pointer
        # self.annotate_and_preconstrain_sp(initial_input_state)

        symbolizer_start_nodes = [
            node for node in new_model._nodes_by_addr[start_addr]
            if node.addr == start_addr and node.block_id.vm_vpc == vm_vpc
        ]
        if len(symbolizer_start_nodes) != 1:
            raise ValueError(
                "Expected exactly one Symbolizer start node for addr %#x and vm_vpc %r, got %d: %s"
                % (
                    start_addr,
                    vm_vpc,
                    len(symbolizer_start_nodes),
                    [(node.addr, node.block_id) for node in symbolizer_start_nodes],
                )
            )

        symbolizer_start_node = symbolizer_start_nodes[0]
        symbolizer_start_node.input_state = initial_input_state
        ## find the replacements

        # replacing the printf hook with unconstrained return just for constant prop, since it get's a symbolic fmt str poitner
        for func_addr, orig_sim_proc, repl_sim_proc in self.constant_prop_func_replacements:
            proj.unhook(func_addr)
            proj.hook(func_addr, repl_sim_proc)

        prop = proj.analyses.Symbolizer(graph=new_cfg_graph, iropt_level=1, start=symbolizer_start_node, max_iterations=2)

        for func_addr, orig_sim_proc, repl_sim_proc in self.constant_prop_func_replacements:
            proj.unhook(func_addr)
            proj.hook(func_addr, orig_sim_proc)

        node_dict = {}
        for node in new_cfg_graph.nodes():
            node_dict[node.block_id] = node

        if do_replacements:
            for key, value in prop.replacements.items():
                node = node_dict[key]
                if not node.is_simprocedure:
                    new_stmts = node.irsb.statements

                    for stmt, repl_pair in value.items():
                        for old, new in repl_pair.items():
                            if not(isinstance(new, str) and new == "TOP"):
                                ## This is for the next expression
                                if stmt.stmt_idx == -2:
                                    node.irsb.next = new
                                else:
                                    new_stmts[stmt.stmt_idx].replace_expression({old: new})


        # tmp_syb_blockwise = defaultdict(dict)
        # for codeloc, expr_list in prop.symbolic_expr_locations_blockwise.items():
        #     if codeloc in tmp_syb_blockwise[codeloc.block_id]:
        #         tmp_syb_blockwise[codeloc.block_id][codeloc] = tmp_syb_blockwise[codeloc.block_id][codeloc] + expr_list
        #     else:
        #         tmp_syb_blockwise[codeloc.block_id][codeloc] = expr_list
        #
        # prop.symbolic_expr_locations_blockwise = tmp_syb_blockwise

        print("Done")
        return new_model, prop.symbolic_expr_locations

    @logtime
    def symbolify_exprs(self, proj, symbolic_expr_locations, start_addr=None, start_state=None, cfg_fast_graph=None, remove_insts=None, avoid_runs=None, unroll_same_vpc_loop=False):
        start_state.globals['to_use_symbolic_exprs'] = []
        start_state.globals['expr_loc_map'] = {}
        self.project.prev_symbolic_expr_locations = symbolic_expr_locations
        self.remove_action_tracking(start_state)
        cfg = proj.analyses.CFGVMDeobfuscation(fail_fast=True,
                                               data_sensitive=True,
                                               starts=(start_addr,),
                                               initial_state=start_state,
                                               max_iterations=1,
                                               resolve_indirect_jumps=False,
                                               keep_state=False,
                                               state_add_options={angr.sim_options.DO_CCALLS, angr.sim_options.REPLACEMENT_SOLVER},
                                               iropt_level=1,
                                               cfg_fast_graph=cfg_fast_graph,
                                               avoid_runs=avoid_runs,
                                               remove_insts=remove_insts,
                                               start_deobfuscation_immediately=self.start_deobfuscation_immediately,
                                               deobfuscation_start_addr=self.deobfuscation_start_addr,
                                               deobfuscation_end_addr = self.deobfuscation_end_addr,
                                               nodes_to_prune=self.nodes_to_prune,
                                               unroll_same_vpc_loop=unroll_same_vpc_loop,
                                               hook_other_functions=self.hook_other_functions,
                                               remove_vmp_semantically_same_branch=self.remove_vmp_semantically_same_branch
                                               # enable_advanced_backward_slicing=True
                                               )
        self.project.prev_symbolic_expr_locations = None
        self.release_memory(cfg, proj)

        return cfg, cfg.to_use_symbolic_exprs

    @logtime
    @detects_changes
    @skip_if_unchanged
    def remove_push_ret(self, cfg, proj, start_addr, start_state=None,options=None, decomp_function_addresses=None):
        # this pass is to simplify push x, retn to x kind of jumps
        for node in cfg.graph.nodes():
            # this is to replace any indirect jumps to a simprocedure with a direct jump, should I do this for all jumps/calls?
            if not node.is_simprocedure and isinstance(node.irsb.next, pyvex.expr.RdTmp) and len(list(cfg.graph.successors(node))) == 1:
                if self.project.arch.bits == 32:
                    node.irsb.next = pyvex.expr.Const(DataSensitiveU32(list(cfg.graph.successors(node))[0].addr, list(cfg.graph.successors(node))[0].block_id))
                elif self.project.arch.bits == 64:
                    node.irsb.next = pyvex.expr.Const(DataSensitiveU64(list(cfg.graph.successors(node))[0].addr, list(cfg.graph.successors(node))[0].block_id))

            # # we are changin the jumpkinds that are IjK_Ret to Ijk_Call so that _process_block_end() in RDA treats the sim_procedures as a function
            # if not node.is_simprocedure and len(list(cfg.graph.successors(node))) == 1 and \
            #         list(cfg.graph.successors(node))[0].is_simprocedure:
            #     if node.irsb.jumpkind == 'Ijk_Ret':
            #         node.irsb.jumpkind = 'Ijk_Boring'

            # this pass is to simplify push x, retn to x kind of jumps
            if not node.is_simprocedure:
                if len(list(cfg.graph.successors(node))) == 1 and node.irsb.jumpkind == "Ijk_Ret":
                    new_jumpkind = node.irsb.jumpkind
                    next_node_addr = list(cfg.graph.successors(node))[0].addr
                    if next_node_addr in decomp_function_addresses:
                        continue
                    new_statements = []
                    cur_ins_addr = None
                    for stmt in node.irsb.statements:
                        if isinstance(stmt, pyvex.stmt.IMark):
                            cur_ins_addr = stmt.addr
                        if isinstance(stmt, pyvex.stmt.Store) and isinstance(stmt.data, pyvex.expr.Const):
                            possible_addr = stmt.data.con.value
                            if possible_addr == next_node_addr:
                                cur_block = angr.Block(node.irsb.addr, project=proj, vex=node.irsb)
                                rd = self.project.analyses.ReachingDefinitions(cur_block,
                                                                               track_tmps=True,
                                                                               track_consts = False,
                                                                               observation_points=[
                                                                                   ('node', node.addr, OP_AFTER)]
                                                                               )
                                all_defs = rd.all_definitions
                                flag = 0

                                for d in all_defs:
                                    if isinstance(d.atom, atoms.MemoryLocation) and d.codeloc.ins_addr == cur_ins_addr:
                                        uses = rd.all_uses.get_uses(d)
                                        if not uses:
                                            flag = 1
                                            break

                                if flag == 1:
                                    new_jumpkind = "Ijk_Boring"
                                    continue

                        new_statements.append(stmt)

                    node.irsb.statements = new_statements
                    node.irsb.jumpkind = new_jumpkind
        return cfg

    @logtime
    @detects_changes
    def keep_only_one_graph(self, cfg, start_addr):
        conn_comps = nx.weakly_connected_components(as_networkx(cfg.graph))
        conn_comps = list(conn_comps)
        if len(conn_comps) == 1:
            return cfg
        sub_graph_to_keep = None
        for comp in conn_comps:
            for node in comp:
                if cfg.graph.in_degree(node) == 0 and node.addr == start_addr:
                    sub_graph_to_keep = comp

        new_model = self.new_model_graph(cfg.graph.subgraph(sub_graph_to_keep), self.project, 'keep_only_one')
        return new_model

    def remove_non_local_variable_dep_branches(self, cfg, proj, start_state, start_addr, user_input, cfg_fast_graph, avoid_runs):
        # This function removes constant guard branches that are not dependent on a local variable that was created in the actual program.
        # e.g. removes constant guard branches that virtual stack tainted but belong to the VM's local variables

        # convert the cfg to a non cross inss optimization cfg because some stack operations were being clubbed
        to_remove_inst_addrs = []
        for cfg_node in cfg.graph.nodes():
            for orig_ins in proj.factory.block(cfg_node.addr, opt_level=1, cross_insn_opt=False).capstone.insns:
                if orig_ins.mnemonic in ['btc', 'bts', 'bt', 'btr']:
                    to_remove_inst_addrs.append(orig_ins.address)


        new_model = self.new_model_graph(cfg.graph, proj, 'remove_non_local_variable_dep_branches')
        for node in list(new_model.graph.nodes()):
            if node.is_simprocedure:
                continue
            node.irsb = proj.factory.block(node.addr, opt_level=1, cross_insn_opt=False).vex

        data_sens_cfg = self.convert_to_data_sensitive_irsb(new_model, proj, start_state)
        new_model = self.new_model_graph(data_sens_cfg.graph, proj, 'remove_non_local_variable_dep_branches')

        # Method 1: using the longest living variable as the local variable
        input_state = proj.factory.blank_state(addr=start_addr, add_options={angr.sim_options.REPLACEMENT_SOLVER, angr.sim_options.DO_CCALLS},
                                        concrete_fs=True, stdin=user_input)
        if proj.arch.bits == 32:
            input_state.registers.store(input_state.arch.registers['ss'][0], 0)
        input_state.globals['prev_rsp'] = 0
        input_state.globals['prev_vsp'] = 0
        input_state.globals['vsp_active'] = False
        input_state.globals['stack_variables_list'] = defaultdict(list)


        # actual_stack_end = input_state.solver.eval(input_state.regs.sp)
        # input_state.regs.sp = input_state.solver.BVS("precon_sp", 64)
        # input_state.preconstrainer.preconstrain(actual_stack_end, input_state.regs.sp)

        def activate_vsp(state):
            state.globals['prev_vsp'] = state.globals['prev_rsp']
            state.globals['vsp_active'] = True

        def deactivate_vsp(state):
            state.globals['prev_rsp'] = state.globals['prev_vsp']
            state.globals['vsp_active'] = False

        def save_vm_vsp(state):
            if state.globals['vsp_active']:
                print(state.solver.eval(state.registers.load(self.vsp_reg))-state.solver.eval(state.globals['prev_vsp']))
                stack_diff = state.solver.eval(state.registers.load(self.vsp_reg)) - state.solver.eval(state.globals['prev_vsp'])
                start_addr=0
                if stack_diff < 0:
                    start_addr = state.solver.eval(state.globals['prev_vsp'])
                    size = stack_diff
                    state.globals['stack_variables_list'][(start_addr, abs(size))].append(('push', state.scratch.ins_addr, state.globals['cur_block_id']))
                elif stack_diff > 0:
                    start_addr = state.solver.eval(state.registers.load(self.vsp_reg))
                    size = stack_diff
                    state.globals['stack_variables_list'][(start_addr, abs(size))].append(('pop', state.scratch.ins_addr, state.globals['cur_block_id']))

                print(state.registers.load(self.vsp_reg))
                print(hex(state.addr))
                print("")
                state.globals['prev_vsp'] = state.registers.load(self.vsp_reg)

        def save_rsp(state):
            if not state.globals['vsp_active']:
                print(state.solver.eval(state.regs.rsp)-state.solver.eval(state.globals['prev_rsp']))
                stack_diff = state.solver.eval(state.regs.rsp) - state.solver.eval(state.globals['prev_rsp'])
                start_addr = 0
                if stack_diff < 0:
                    start_addr = state.solver.eval(state.globals['prev_rsp'])
                    size = stack_diff
                    state.globals['stack_variables_list'][(start_addr, abs(size))].append(('push', state.scratch.ins_addr, state.globals['cur_block_id']))
                elif stack_diff > 0:
                    start_addr = state.solver.eval(state.regs.rsp)
                    size = stack_diff
                    state.globals['stack_variables_list'][(start_addr, abs(size))].append(('pop', state.scratch.ins_addr, state.globals['cur_block_id']))
                print(state.regs.rsp)
                print(hex(state.addr))
                print("")
                state.globals['prev_rsp'] = state.regs.rsp

        input_state.inspect.add_breakpoint('instruction', BP(BP_AFTER, instruction=0x140188D8A, action=activate_vsp))
        input_state.inspect.add_breakpoint('instruction', BP(BP_BEFORE, instruction=0x14018D665, action=deactivate_vsp))

        input_state.inspect.add_breakpoint('reg_write', BP(BP_AFTER, reg_write_offset=input_state.project.arch.registers[self.vsp_reg][0],
                                                     action=save_vm_vsp))

        input_state.inspect.add_breakpoint('reg_write', BP(BP_AFTER, reg_write_offset=input_state.project.arch.registers["rsp"][0],
                                                     action=save_rsp))

        new_model._nodes_by_addr[self.start_addr][0].input_state = input_state


        new_cfg = proj.analyses.CFGConcreteExecution(model=new_model, keep_state=True, iropt_level=1,
                                                   resolve_indirect_jumps=True)

        possible_variable_push_addrs = []
        for node in new_cfg.graph.nodes():
            succs = new_cfg.get_successors(node)
            if len(succs) == 0:
                final_state = node.input_state
                print(final_state.globals['stack_variables_list'])

                for stack_tuple, action_list in final_state.globals['stack_variables_list'].items():
                    print(action_list)
                    if action_list[-1][0] == 'push':
                        # (ins_addr, block_id, size)
                        possible_variable_push_addrs.append((action_list[-1][1], action_list[-1][2], stack_tuple[1]))
                        print(hex(stack_tuple[0]))
                        print(action_list[-1][1])

                print(possible_variable_push_addrs)

        def mark_stack_var(state):
            # (ins_addr, block_id, size) = stack_var_loc
            for stack_var_loc in state.globals['stack_variable_locs']:
                print(hex(stack_var_loc[0]))
                print(hex(state.inspect.instruction))
                print(state.globals['cur_block_id'])
                print(stack_var_loc[1])
                if stack_var_loc[0] == state.inspect.instruction and state.globals['cur_block_id'] == stack_var_loc[1]:
                    # code to mark the stack, with annotations
                    for i in range(stack_var_loc[2]//8):
                        annotated_stack_var = annotate_with_new_replacements(state, state.memory.load(state.registers.load(self.vsp_reg)+(i*8), 8), VMStackVariableAnnotation(1))
                        state.memory.store(state.registers.load(self.vsp_reg)+(i*8), annotated_stack_var)
                    print("lola")

        start_state_copy = copy.deepcopy(start_state)
        start_state_copy.globals['stack_variable_locs'] = possible_variable_push_addrs

        for addr, block_id, size in possible_variable_push_addrs:
            start_state_copy.inspect.add_breakpoint('instruction',
                                               BP(BP_AFTER, instruction=addr, action=mark_stack_var))

        cfg, proj = self.data_sensitive_graph(self.project.filename, start_addr=start_addr, start_state=start_state_copy, cfg_fast_graph=cfg_fast_graph, avoid_runs=avoid_runs)
        cfg = self.new_model_without_terminator_graph(cfg.graph, proj, 'without_path_terminator')

        cfg = self.convert_to_data_sensitive_irsb(cfg, proj, start_state_copy)

        print("Done")

        return cfg

    @logtime
    # this is to remove those vex jump insts that will always to the same location. This is after the data sensitive analysis
    @skip_if_unchanged
    def remove_useless_jump_instructions(self, cfg, keep_sp_changes_dae=None):
        print("Remove useless jmp insts")
        #new_model = self.new_model_graph(cfg.graph, proj, 'remove_useless_jumps')

        cfg = self.remove_redundant_ip_assignement(cfg)
        new_model = cfg
        for node in list(new_model.graph.nodes()):
            if node.is_simprocedure:
                continue

            if len(list(new_model.graph.successors(node))) == 1 and isinstance(node.irsb.statements[-1], pyvex.stmt.Exit):
                self._note_change(node)
                if node.irsb.statements[-1].dst.value == list(new_model.graph.successors(node))[0].addr:
                    new_statements = node.irsb.statements[:-1]
                    new_next = pyvex.expr.Const(DataSensitiveU64(node.irsb.statements[-1].dst.value, node.irsb.statements[-1].dst.block_id))
                    node.irsb = pyvex.IRSB.empty_block(node.irsb.arch,
                                                       node.irsb.addr,
                                                       statements=new_statements,
                                                       tyenv=node.irsb.tyenv,
                                                       nxt=new_next,
                                                       direct_next=node.irsb.direct_next,
                                                       jumpkind=node.irsb.jumpkind,
                                                       size=node.irsb.size)

                else:
                    new_statements = node.irsb.statements[:-1]
                    node.irsb = pyvex.IRSB.empty_block(node.irsb.arch,
                                                       node.irsb.addr,
                                                       statements=new_statements,
                                                       tyenv=node.irsb.tyenv,
                                                       nxt=node.irsb.next,
                                                       direct_next=node.irsb.direct_next,
                                                       jumpkind=node.irsb.jumpkind,
                                                       size=node.irsb.size)

        # if start_state:
        #     initial_input_state = start_state
        # else:
        #     initial_input_state = proj.factory.blank_state(addr=self.start_addr,
        #                                                    mode='fastpath',
        #                                                    add_options={'REPLACEMENT_SOLVER','DO_CCALLS', 'SYMBOL_FILL_UNCONSTRAINED_REGISTERS', 'SYMBOL_FILL_UNCONSTRAINED_MEMORY'})

        # initial_input_state = proj.factory.blank_state(addr=self.start_addr,
        #                                                mode='fastpath')
        # initial_input_state.options.remove('REPLACEMENT_SOLVER')
        #
        # new_model._nodes_by_addr[self.start_addr][0].input_state = initial_input_state
        # new_cfg = proj.analyses.CFGVMDeobfuscation(model=new_model, keep_state=True, iropt_level=1,
        #                                            resolve_indirect_jumps=True, max_iterations=1,
        #                                            vm_vpc_addr=self.vm_vpc_addr)
        print("Done")
        return new_model


    # remove the unnecessary obfuscation added by VEX for the bts, bt and btc instructions
    def remove_vex_bs(self, cfg, proj, start_addr, start_state, orig_cfg):
        print("Remove VEX bs insts")
        to_remove_inst_addrs = []
        for orig_cfg_node in orig_cfg.graph.nodes():
            for orig_ins in proj.factory.block(orig_cfg_node.addr).capstone.insns:
                if orig_ins.mnemonic in ['btc', 'bts', 'bt', 'btr']:
                    to_remove_inst_addrs.append(orig_ins.address)

        new_model = self.new_model_graph(cfg.graph, proj, 'remove_vex_bs')
        for node in list(new_model.graph.nodes()):
            if node.is_simprocedure:
                continue

            to_remove_stmt_idxs = []
            add_to_list = 0
            for ind, stmt in enumerate(node.irsb.statements):
                if isinstance(stmt, pyvex.stmt.IMark) and stmt.addr in to_remove_inst_addrs:
                    add_to_list = 1
                elif isinstance(stmt, pyvex.stmt.IMark) and stmt.addr not in to_remove_inst_addrs:
                    add_to_list = 0

                if add_to_list == 1 and isinstance(stmt, pyvex.stmt.Store):
                    to_remove_stmt_idxs.append(ind)


            new_statements = []
            for idx, stmt in enumerate(node.irsb.statements):
                if idx in to_remove_stmt_idxs:
                    continue

                new_statements.append(stmt)

            node.irsb = pyvex.IRSB.empty_block(node.irsb.arch,
                                               node.irsb.addr,
                                               statements=new_statements,
                                               tyenv=node.irsb.tyenv,
                                               nxt=node.irsb.next,
                                               direct_next=node.irsb.direct_next,
                                               jumpkind=node.irsb.jumpkind,
                                               size=node.irsb.size)

        if start_state:
            initial_input_state = start_state
        else:
            initial_input_state = proj.factory.blank_state(addr=self.start_addr,
                                                           mode='fastpath',
                                                           add_options=angr.sim_options.refs | {
                                                               angr.sim_options.REPLACEMENT_SOLVER,
                                                               angr.sim_options.DO_CCALLS})
        # new_model._nodes_by_addr[self.start_addr][0].input_state = initial_input_state
        # new_cfg = proj.analyses.CFGVMDeobfuscation(model=new_model, keep_state=True, iropt_level=1,
        #                                            resolve_indirect_jumps=True, max_iterations=1,
        #                                            vm_vpc_addr=self.vm_vpc_addr)
        print("Done")
        return new_model


    @logtime
    @detects_changes
    @skip_if_unchanged
    def join_basic_blocks(self, cfg, proj, start_addr, start_state, skip_call_ret=False):
        print("Join Basic blocks")
        #new_model = self.new_model_graph(cfg.graph, proj, 'join_basic_blocks')
        new_model = cfg

        for node in list(new_model.graph.nodes()):
            # This is to check if the node was deleted or not
            if node in new_model.graph.nodes():
                if not node.is_simprocedure and len(list(new_model.graph.successors(node))) == 1:
                    if node.addr == 0x1401f1572 and node.block_id.vm_vpc == 10737664954:
                        import ipdb;ipdb.set_trace()
                    if skip_call_ret and node.irsb.jumpkind in ['Ijk_Call', 'Ijk_Ret']:
                        continue
                    succ = list(new_model.graph.successors(node))[0]
                    if len(list(new_model.graph.predecessors(succ))) == 1 and not succ.is_simprocedure:
                        new_stmts = []
                        new_types = {}
                        tmps_used_cur_block = []
                        tmps_used_succ_block = []
                        tmp_replace_map = {}
                        tmp_no_to_use = 0
                        for stmt in node.irsb.statements:
                            new_stmts.append(stmt)
                            if isinstance(stmt, pyvex.stmt.WrTmp):
                                tmps_used_cur_block.append(stmt.tmp)
                                new_types[stmt.tmp] = node.irsb.tyenv.lookup(stmt.tmp)
                            elif isinstance(stmt, pyvex.stmt.CAS):
                                tmps_used_cur_block.append(stmt.oldLo)
                                new_types[stmt.oldLo] = node.irsb.tyenv.lookup(stmt.oldLo)
                        for stmt in succ.irsb.statements:
                            if isinstance(stmt, pyvex.stmt.WrTmp):
                                tmps_used_succ_block.append(stmt.tmp)
                            elif isinstance(stmt, pyvex.stmt.CAS):
                                tmps_used_succ_block.append(stmt.oldLo)

                        if len(tmps_used_cur_block+tmps_used_succ_block) == 0:
                            tmp_no_to_use = 0
                        else:
                            tmp_no_to_use = max(tmps_used_cur_block+tmps_used_succ_block) + 1

                        for stmt in succ.irsb.statements:
                            if isinstance(stmt, pyvex.stmt.WrTmp):
                                if stmt.tmp in tmps_used_cur_block:
                                    tmp_replace_map[pyvex.expr.RdTmp(stmt.tmp)] = pyvex.expr.RdTmp(tmp_no_to_use)
                                    new_types[tmp_no_to_use] = succ.irsb.tyenv.lookup(stmt.tmp)
                                    stmt.tmp = tmp_no_to_use
                                    tmp_no_to_use = tmp_no_to_use + 1
                                else:
                                    new_types[stmt.tmp] = succ.irsb.tyenv.lookup(stmt.tmp)
                            elif isinstance(stmt, pyvex.stmt.CAS):
                                if stmt.oldLo in tmps_used_cur_block:
                                    tmp_replace_map[pyvex.expr.RdTmp(stmt.oldLo)] = pyvex.expr.RdTmp(tmp_no_to_use)
                                    new_types[tmp_no_to_use] = succ.irsb.tyenv.lookup(stmt.oldLo)
                                    stmt.oldLo = tmp_no_to_use
                                    tmp_no_to_use = tmp_no_to_use + 1
                                else:
                                    new_types[stmt.oldLo] = succ.irsb.tyenv.lookup(stmt.oldLo)

                            if not isinstance(stmt, pyvex.stmt.IMark):
                                for rd_tmp in tmp_replace_map:
                                    for expr in stmt.expressions:
                                        if expr == rd_tmp:
                                            stmt.replace_expression({expr: tmp_replace_map[rd_tmp]})
                            new_stmts.append(stmt)
                        new_next = succ.irsb.next
                        if isinstance(succ.irsb.next, pyvex.expr.RdTmp):
                            for tmp in tmp_replace_map:
                                if succ.irsb.next.tmp == tmp.tmp:
                                    new_next = DataSensitiveRdTmp(tmp_replace_map[tmp].tmp, succ.irsb.next.block_id)

                        #convert types dict to list, with 'None' str for the missing tmps
                        new_types_list = []
                        if len(new_types) != 0:
                            for i in range(max(new_types.keys())+1):
                                if i in new_types:
                                    new_types_list.append(new_types[i])
                                else:
                                    new_types_list.append("tmp removed")

                        node.irsb = pyvex.IRSB.empty_block(node.irsb.arch,
                                                          node.irsb.addr,
                                                          statements=new_stmts,
                                                          tyenv=pyvex.block.IRTypeEnv(node.irsb.arch,types=new_types_list),
                                                          nxt=new_next,
                                                          direct_next=succ.irsb.direct_next,
                                                          jumpkind=succ.irsb.jumpkind,
                                                          size=node.irsb.size+succ.irsb.size)

                        for succ_of_succ in new_model.graph.successors(succ):
                            edge_data = cfg.graph.get_edge_data(node, succ)
                            new_model.graph.add_edge(node, succ_of_succ, jumpkind=edge_data['jumpkind'])
                        new_model.graph.remove_node(succ)

        # if start_state:
        #     initial_input_state = start_state
        # else:
        #     # initial_input_state = proj.factory.blank_state(addr=self.start_addr,
        #     #                                                mode='fastpath',
        #     #                                                add_options=angr.sim_options.refs | {
        #     #                                                    angr.sim_options.REPLACEMENT_SOLVER,
        #     #                                                    angr.sim_options.DO_CCALLS})
        #
        #     initial_input_state = proj.factory.blank_state(addr=self.start_addr,
        #                                                    mode='fastpath')
        #     initial_input_state.options.remove('REPLACEMENT_SOLVER')
        # new_model._nodes_by_addr[self.start_addr][0].input_state = initial_input_state
        # new_cfg = proj.analyses.CFGVMDeobfuscation(model=new_model, keep_state=True, iropt_level=1,
        #                                            resolve_indirect_jumps=True, max_iterations=1,
        #                                            vm_vpc_addr=self.vm_vpc_addr)
        print("Done")
        return new_model

    @logtime
    def convert_to_data_sensitive_irsb(self, cfg, proj, start_state):
        print("Convert to data sensisitve irsb")
        #new_model = self.new_model_graph(cfg.graph, proj, 'data_sensitive_irsb')
        new_model = cfg
        for node in new_model.nodes():
            if node.is_simprocedure:
                continue

            new_stmts = node.irsb.statements
            block_id_for_next = None
            for ind, poss_exit_stmt in enumerate(new_stmts):
                if isinstance(poss_exit_stmt, pyvex.stmt.Exit):
                    # Matching the successors with the correct block_id
                    succs = cfg.get_successors(node)
                    if len(succs) > 2:
                        raise Exception("Greater than 2 successors!")
                    branch_block_id = None
                    for succ in succs:
                        if succ.addr == poss_exit_stmt.dst.value:
                            branch_block_id = succ.block_id
                        elif not isinstance(node.irsb.next, pyvex.expr.RdTmp):
                            if succ.addr == node.irsb.next.con.value:
                                block_id_for_next = succ.block_id

                    # if block_id is None then it's probably some weird VEX instruction......
                    if isinstance(poss_exit_stmt.dst, pyvex.const.U64):
                        new_stmts[ind] = pyvex.stmt.Exit(poss_exit_stmt.guard,
                                                            DataSensitiveU64(poss_exit_stmt.dst.value, branch_block_id),
                                                            poss_exit_stmt.jk,
                                                            poss_exit_stmt.offsIP)
                    elif isinstance(poss_exit_stmt.dst, pyvex.const.U32):
                        new_stmts[ind] = pyvex.stmt.Exit(poss_exit_stmt.guard,
                                                            DataSensitiveU32(poss_exit_stmt.dst.value, branch_block_id),
                                                            poss_exit_stmt.jk,
                                                            poss_exit_stmt.offsIP)

            if block_id_for_next is None:
                succs = cfg.get_successors(node)
                if len(succs) == 0: # Last node in the graph
                    block_id_for_next = None
                elif len(succs) == 1:
                    block_id_for_next = succs[0].block_id
                elif len(succs) == 2:
                    for succ in succs:
                        if succ.block_id != branch_block_id:
                            block_id_for_next = succ.block_id
                else:
                    block_id_for_next = None

            if isinstance(node.irsb.next, pyvex.expr.RdTmp):
                new_next = DataSensitiveRdTmp(node.irsb.next.tmp, block_id_for_next)
            elif isinstance(node.irsb.next.con, pyvex.const.U64):
                new_next = pyvex.expr.Const(DataSensitiveU64(node.irsb.next.con.value, block_id_for_next))
            elif isinstance(node.irsb.next.con, pyvex.const.U32):
                new_next = pyvex.expr.Const(DataSensitiveU32(node.irsb.next.con.value, block_id_for_next))

            node.irsb = pyvex.IRSB.empty_block(node.irsb.arch,
                                               node.irsb.addr,
                                               statements=new_stmts,
                                               tyenv=node.irsb.tyenv,
                                               nxt=new_next,
                                               direct_next=node.irsb.direct_next,
                                               jumpkind=node.irsb.jumpkind,
                                               size=node.irsb.size)

        # if start_state:
        #     start_state.options.remove('DO_CCALLS')
        #     start_state.options.remove('AVOID_MULTIVALUED_WRITES'n)
        #     initial_input_state = start_state
        #
        # else:
        initial_input_state = proj.factory.blank_state(addr=self.start_addr,
                                                       mode='fastpath',)
                                                       #add_options=angr.sim_options.refs)# | {
                                                                   #angr.sim_options.REPLACEMENT_SOLVER})
                                                           #angr.sim_options.DO_CCALLS}) # removed CCALLS fom options because, the final call to CFGVMDe... is just a sanity check... it doesn't have to be sound/correct?
        #initial_input_state.options.remove('DO_CCALLS')
        #initial_input_state.options.remove('AVOID_MULTIVALUED_WRITES')
        #
        # initial_input_state.options.remove('REPLACEMENT_SOLVER')
        # new_model._nodes_by_addr[self.start_addr][0].input_state = initial_input_state
        # new_cfg = proj.analyses.CFGVMDeobfuscation(model=new_model, keep_state=True, iropt_level=1,starts=[self.start_addr],
        #                                            resolve_indirect_jumps=True, max_iterations=1,
        #                                            vm_vpc_addr=self.vm_vpc_addr)
        print("Done")
        return new_model

    def perform_semantic_verification(self, cfg, proj, start_state=None, start_addr=None,semantic_verf_hooks=None):
        print("Performing semantic verification")
        new_model = self.new_model_graph(cfg.graph, proj, 'semantic_verification')
        chroot = os.path.dirname(self.project.filename)

        if semantic_verf_hooks:
            for symbol_addr, proc in semantic_verf_hooks:
                if isinstance(symbol_addr, str):
                    proj.hook_symbol(symbol_addr,proc, replace=True)
                else:
                    proj.hook(symbol_addr, proc, replace=True)



        if start_state:
            start_state.options.add(angr.sim_options.CONCRETIZE)
            start_state.options.add(angr.sim_options.INITIALIZE_ZERO_REGISTERS)
            start_state.options.add(angr.sim_options.DO_CCALLS)
            new_model._nodes_by_addr[self.start_addr][0].input_state = start_state
        else:
            new_model._nodes_by_addr[self.start_addr][0].input_state = proj.factory.blank_state(addr=start_addr, add_options={angr.sim_options.DO_CCALLS, angr.sim_options.CONCRETIZE, angr.sim_options.INITIALIZE_ZERO_REGISTERS},
                                            concrete_fs=True, chroot=chroot, stdin=input)
            if proj.arch.bits == 32:
                new_model._nodes_by_addr[self.start_addr][0].input_state.registers.store(new_model._nodes_by_addr[self.start_addr][0].input_state.arch.registers['ss'][0], 0)


        print("Initial SP value:"+str(hex(new_model._nodes_by_addr[self.start_addr][0].input_state.regs.sp.args[0])))
        new_cfg = proj.analyses.CFGConcreteExecution(model=new_model, keep_state=True, iropt_level=1,
                                                   resolve_indirect_jumps=True)

        for node in new_cfg.graph.nodes():
            succs = new_cfg.get_successors(node)
            if len(succs) == 0 and node.input_state is not None:
                final_state = node.final_states[0]
                print(node)
                print(final_state.posix.dumps(1))
        print("Done")
        import ipdb;ipdb.set_trace()
        if semantic_verf_hooks:
            for symbol_addr, proc in semantic_verf_hooks:
                if isinstance(symbol_addr, str):
                    sym = proj.loader.find_symbol(symbol_addr)
                    if sym.owner is proj.loader._extern_object:
                        proj.hook_symbol(symbol_addr, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'](cc=proj.factory._default_cc(start_state.arch), prototype=proc.prototype),replace=True)
                    else:
                        proj.unhook_symbol(symbol_addr)
                else:
                    proj.hook(symbol_addr, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'](cc=proj.factory._default_cc(start_state.arch), prototype=proc.prototype),replace=True)
                    #proj.unhook(symbol_addr)


    def convert_to_atom(self, vex_inst, tyenv, byte_width):
        if isinstance(vex_inst, pyvex.expr.RdTmp):
            atom = Tmp(vex_inst.tmp, vex_inst.result_size(tyenv) // byte_width)
        elif isinstance(vex_inst, pyvex.stmt.WrTmp):
            atom = Tmp(vex_inst.tmp, vex_inst.data.result_size(tyenv) // byte_width)
        else:
            atom = None
        return atom

    def simplify_vex_expr_to_ast(self, expr, tyenv, byte_width, node, sub_graph, cur_stmt_node):
        ### This method assumes that expressions are in their most simplified form and don't contain expressions within expressions e.g. Add(Get(rsp), 0x8)

        if isinstance(expr, pyvex.expr.Binop) and expr.op == "Iop_Sub64":
            if isinstance(expr.args[0], pyvex.expr.Const):
                left_arg_atom = expr.args[0].con.value
            else:
                left_arg_atom = self.convert_to_atom(expr.args[0], tyenv, byte_width)

            if isinstance(expr.args[1], pyvex.expr.Const):
                right_arg_atom = expr.args[1].con.value
            else:
                right_arg_atom = self.convert_to_atom(expr.args[1], tyenv, byte_width)

            successors = list(sub_graph.graph.successors(cur_stmt_node))

            ### match the arguments with the successors nodes, to get the simplified expr for each
            left_arg_node = None
            right_arg_node = None
            for succ in successors:
                if succ.def_atom == left_arg_atom:
                    left_arg_node = succ
                elif succ.def_atom == right_arg_atom:
                    right_arg_node = succ

            if left_arg_node:
                left_simplified_ast = sub_graph.simplified_asts[left_arg_node]
            else:
                ## probably a constant
                left_simplified_ast = left_arg_atom

            if right_arg_node:
                right_simplified_ast = sub_graph.simplified_asts[right_arg_node]
            else:
                ## probably a constant
                right_simplified_ast = right_arg_atom

            ## Using the input state shouldn't make a difference here since these asts were created specifically for simplification
            return node.input_state.solver.simplify(left_simplified_ast - right_simplified_ast)
        elif isinstance(expr, pyvex.expr.RdTmp):
            successors = list(sub_graph.graph.successors(cur_stmt_node))
            return node.input_state.solver.simplify(sub_graph.simplified_asts[successors[0]])
        elif isinstance(expr, pyvex.expr.Get):
            return claripy.BVS(f'reg_{expr.offset}', expr.result_size(tyenv))
        elif isinstance(expr, pyvex.expr.Const):
            return expr.con.value

    @logtime
    @skip_if_unchanged
    def remove_redundant_Get_Put(self, cfg, proj, start_state=None):
        print("Remove redundant Get Put")
        #PUT(rsp) = t334        ===>      PUT(rsp) = t334
        #t116 = GET:I64(rsp)               t116 = t334

        #dsa_new_model = self.new_model_graph(cfg.graph, proj, 'redun_Get_Put')
        dsa_new_model = cfg
        for node in dsa_new_model.nodes():
            if node.addr == self.vm_start_addr:
                start_node = node
                break

        for node in dsa_new_model.nodes():
            if node.is_simprocedure:
                continue
            if self._node_is_clean("remove_redundant_Get_Put", node):
                continue
            _clean_epoch, _clean_counter = self._coarse_epoch, self._change_counter

            cur_block = angr.Block(node.irsb.addr, project=proj, vex=node.irsb)
            rd = self.project.analyses.ReachingDefinitions(cur_block,
                                                           track_tmps=True,
                                                           track_consts=False,
                                                           observation_points=[('node', node.addr, OP_AFTER)]
                                                           )

            # Find redundant loads
            live_defs = rd.one_result
            to_remove = []
            replace_get_dict = {}
            all_defs = rd.all_definitions
            for d in all_defs:
                # skip the definitions that are added for function calls after the current block
                if d.codeloc.block_addr != node.irsb.addr:
                    continue
                if isinstance(d.codeloc, ExternalCodeLocation) or d.dummy:
                    continue

                if isinstance(d.atom, atoms.Tmp):
                    uses = live_defs.tmp_uses[d.atom.tmp_idx]
                else:
                    uses = rd.all_uses.get_uses(d)

                if isinstance(d.atom, atoms.Register) and isinstance(node.irsb.statements[d.codeloc.stmt_idx], pyvex.stmt.Put):
                    for use in uses:
                        if use.stmt_idx is None:
                            # this is a sim procedure function use
                            continue
                        #make sure that other stmts don't define parts of a register e.g. put(cl) i.e. there's only one definition used at the location of the use
                        if len(rd.all_uses.get_uses_by_location(use)) == 1:
                            # This is an internal function or a sim procedure for which I have not written a rda handler
                            if isinstance(node.irsb.statements[use.stmt_idx], pyvex.stmt.WrTmp) and isinstance(node.irsb.statements[use.stmt_idx].data, pyvex.expr.Get) and (node.irsb.statements[d.codeloc.stmt_idx].data.result_size(node.irsb.tyenv) == node.irsb.statements[use.stmt_idx].data.result_size(node.irsb.tyenv)):
                                replace_get_dict[use.stmt_idx] = node.irsb.statements[d.codeloc.stmt_idx].data

                # elif isinstance(d.atom, atoms.Tmp) and isinstance(node.irsb.statements[d.codeloc.stmt_idx], pyvex.stmt.WrTmp) and isinstance(node.irsb.statements[d.codeloc.stmt_idx].data, pyvex.expr.Get):
                #     ## THIS IS WRONG WE CANNOT REMOVE THE PUT WITHOUT CHANGING THE SEMANTICS. DO NOT USE THIS!
                #     if node.irsb.statements[d.codeloc.stmt_idx].data.offset == self.project.arch.sp_offset:
                #         # we skip this for sp since we need to keep the Put(rsp) as this is required by the sp tracker in the decompiler
                #         continue
                #     for use in uses:
                #         if use.stmt_idx is None:
                #             continue
                #         # This is an internal function or a sim procedure for which I have not written a rda handler
                #         if isinstance(node.irsb.statements[use.stmt_idx], pyvex.stmt.Put) and node.irsb.statements[use.stmt_idx].offset == node.irsb.statements[d.codeloc.stmt_idx].data.offset and (node.irsb.statements[use.stmt_idx].data.result_size(node.irsb.tyenv) == node.irsb.statements[d.codeloc.stmt_idx].data.result_size(node.irsb.tyenv)):
                #             to_remove.append(use.stmt_idx)

            if replace_get_dict or to_remove:
                self._note_change(node)

            new_statements = []
            for idx, stmt in enumerate(cur_block.vex.statements):
                if idx in replace_get_dict:
                    replaced_stmt = pyvex.stmt.WrTmp(stmt.tmp, replace_get_dict[idx])
                    new_statements.append(replaced_stmt)
                elif idx not in to_remove:
                    new_statements.append(stmt)

            node.irsb = pyvex.IRSB.empty_block(node.irsb.arch,
                                               node.irsb.addr,
                                               statements=new_statements,
                                               tyenv=node.irsb.tyenv,
                                               nxt=node.irsb.next,
                                               direct_next=node.irsb.direct_next,
                                               jumpkind=node.irsb.jumpkind,
                                               size=node.irsb.size)

            self._mark_node_clean("remove_redundant_Get_Put", node, _clean_epoch, _clean_counter)

        # Returning a new CFGVMDeobfuscation object with the updated graph
        # if start_state:
        #     initial_input_state = start_state
        # else:
        #     initial_input_state = proj.factory.blank_state(addr=self.start_addr,
        #                                                    mode='fastpath',
        #                                                    add_options=angr.sim_options.refs | {
        #                                                        angr.sim_options.REPLACEMENT_SOLVER,
        #                                                        angr.sim_options.DO_CCALLS})
        # dsa_new_model._nodes_by_addr[self.start_addr][0].input_state = initial_input_state
        # new_cfg = proj.analyses.CFGVMDeobfuscation(model=dsa_new_model, keep_state=True, iropt_level=1,
        #                                            resolve_indirect_jumps=True, max_iterations=1,
        #                                            vm_vpc_addr=self.vm_vpc_addr)
        # print("Done")
        # return new_cfg

        return dsa_new_model



    @staticmethod
    def _vex_const_value(expr):
        return expr.con.value if isinstance(expr, pyvex.expr.Const) else None

    @staticmethod
    def _vex_expr_key(expr):
        if isinstance(expr, pyvex.expr.RdTmp):
            return ("tmp", expr.tmp)
        if isinstance(expr, pyvex.expr.Const):
            return ("const", expr.con.__class__.__name__, expr.con.value)
        if isinstance(expr, pyvex.expr.Unop):
            arg_keys = tuple(VMDeobfuscation._vex_expr_key(arg) for arg in expr.args)
            return None if any(arg_key is None for arg_key in arg_keys) else ("unop", expr.op, arg_keys)
        if isinstance(expr, pyvex.expr.Binop):
            arg_keys = tuple(VMDeobfuscation._vex_expr_key(arg) for arg in expr.args)
            return None if any(arg_key is None for arg_key in arg_keys) else ("binop", expr.op, arg_keys)
        return None

    @staticmethod
    def _vex_zero_const_for_tmp(tyenv, tmp_idx):
        const_class = pyvex.const.ty_to_const_class(tyenv.lookup(tmp_idx))
        return pyvex.expr.Const(const_class(0))

    @staticmethod
    def _vex_bits_for_tmp(tyenv, tmp_idx):
        ty = tyenv.lookup(tmp_idx)
        if isinstance(ty, str) and ty.startswith("Ity_I"):
            return int(ty[5:])
        return None

    @staticmethod
    def _vex_mask_for_tmp(tyenv, tmp_idx):
        bits = VMDeobfuscation._vex_bits_for_tmp(tyenv, tmp_idx)
        return (1 << bits) - 1 if bits is not None else None

    @staticmethod
    def _vex_make_const_like(const_expr, value):
        const_class = const_expr.con.__class__
        ty = getattr(const_expr.con, "type", None)
        if isinstance(ty, str) and ty.startswith("Ity_I"):
            value &= (1 << int(ty[5:])) - 1
        return pyvex.expr.Const(const_class(value))

    @staticmethod
    def _vex_const_and_var_arg(expr):
        if not isinstance(expr, pyvex.expr.Binop):
            return None, None
        arg0, arg1 = expr.args
        if isinstance(arg0, pyvex.expr.Const):
            return arg0, arg1
        if isinstance(arg1, pyvex.expr.Const):
            return arg1, arg0
        return None, None

    @staticmethod
    def _vex_expr_depth(expr):
        if isinstance(expr, (pyvex.expr.RdTmp, pyvex.expr.Const)):
            return 1
        if isinstance(expr, (pyvex.expr.Unop, pyvex.expr.Binop)):
            return 1 + max((VMDeobfuscation._vex_expr_depth(arg) for arg in expr.args), default=0)
        return 99

    @staticmethod
    def _vex_inline_expr_children(expr):
        if isinstance(expr, pyvex.expr.ITE):
            return [expr.cond, expr.iftrue, expr.iffalse]
        if isinstance(expr, pyvex.expr.Load):
            return [expr.addr]
        args = getattr(expr, "args", None)
        return list(args) if args is not None else []

    @staticmethod
    def _vex_inline_expr_depth(expr):
        if isinstance(expr, (pyvex.expr.RdTmp, pyvex.expr.Const, pyvex.expr.Get)):
            return 1
        children = VMDeobfuscation._vex_inline_expr_children(expr)
        if children:
            return 1 + max((VMDeobfuscation._vex_inline_expr_depth(child) for child in children), default=0)
        return 99

    @staticmethod
    def _vex_inline_expr_size(expr):
        if isinstance(expr, (pyvex.expr.RdTmp, pyvex.expr.Const, pyvex.expr.Get)):
            return 1
        children = VMDeobfuscation._vex_inline_expr_children(expr)
        if children:
            return 1 + sum(VMDeobfuscation._vex_inline_expr_size(child) for child in children)
        return 99

    @staticmethod
    def _vex_pure_operand_inline_allowed(expr):
        if isinstance(expr, pyvex.expr.Binop):
            if not expr.op.startswith(("Iop_Add", "Iop_Sub", "Iop_Xor", "Iop_Or", "Iop_And", "Iop_Shl", "Iop_Shr", "Iop_Sar")):
                return False
            return all(VMDeobfuscation._vex_pure_operand_inline_allowed(arg) for arg in expr.args)
        if isinstance(expr, pyvex.expr.Unop):
            if not expr.op.startswith((
                "Iop_Not",
                "Iop_8Uto",
                "Iop_16Uto",
                "Iop_32Uto",
                "Iop_64to",
                "Iop_32to",
                "Iop_16to",
                "Iop_8Sto",
                "Iop_16Sto",
                "Iop_32Sto",
            )):
                return False
            return all(VMDeobfuscation._vex_pure_operand_inline_allowed(arg) for arg in expr.args)
        return isinstance(expr, (pyvex.expr.RdTmp, pyvex.expr.Const, pyvex.expr.Get))

    @staticmethod
    def _vex_get_offsets(expr):
        offsets = set()
        if isinstance(expr, pyvex.expr.Get):
            offsets.add(expr.offset)
        for child in VMDeobfuscation._vex_inline_expr_children(expr):
            offsets.update(VMDeobfuscation._vex_get_offsets(child))
        return offsets

    @staticmethod
    def _vex_has_put_barrier(statements, start_idx, end_idx, get_offsets):
        if not get_offsets:
            return False
        for stmt in statements[start_idx + 1:end_idx]:
            if isinstance(stmt, pyvex.stmt.Put) and stmt.offset in get_offsets:
                return True
        return False

    @staticmethod
    def _vex_const_binop_inline_allowed(expr):
        if not isinstance(expr, pyvex.expr.Binop):
            return False
        if not expr.op.startswith(("Iop_Add", "Iop_Sub", "Iop_Xor", "Iop_Or", "Iop_And", "Iop_Shl", "Iop_Shr")):
            return False
        const_expr, _ = VMDeobfuscation._vex_const_and_var_arg(expr)
        return const_expr is not None

    def _vex_same_value_exprs(self, expr0, expr1, tmp_expr_keys):
        key0 = self._vex_expr_key(expr0)
        key1 = self._vex_expr_key(expr1)
        if key0 is not None and key0 == key1:
            return True

        if isinstance(expr0, pyvex.expr.RdTmp):
            key0 = tmp_expr_keys.get(expr0.tmp, key0)
        if isinstance(expr1, pyvex.expr.RdTmp):
            key1 = tmp_expr_keys.get(expr1.tmp, key1)
        return key0 is not None and key0 == key1

    def _vex_identity_replacement(self, stmt, tmp_expr_keys, tyenv):
        if not isinstance(stmt, pyvex.stmt.WrTmp) or not isinstance(stmt.data, pyvex.expr.Binop):
            return None

        op = stmt.data.op
        arg0, arg1 = stmt.data.args
        arg0_const = self._vex_const_value(arg0)
        arg1_const = self._vex_const_value(arg1)

        if op.startswith(("Iop_Or", "Iop_Add", "Iop_Xor")):
            if arg0_const == 0:
                return arg1
            if arg1_const == 0:
                return arg0

        if op.startswith("Iop_Sub") and arg1_const == 0:
            return arg0

        if op.startswith(("Iop_Shl", "Iop_Shr", "Iop_Sar")) and arg1_const == 0:
            return arg0

        if op.startswith(("Iop_Or", "Iop_And")) and self._vex_same_value_exprs(arg0, arg1, tmp_expr_keys):
            return arg0

        if op.startswith("Iop_Xor") and self._vex_same_value_exprs(arg0, arg1, tmp_expr_keys):
            return self._vex_zero_const_for_tmp(tyenv, stmt.tmp)

        if op.startswith("Iop_And") and (arg0_const == 0 or arg1_const == 0):
            return self._vex_zero_const_for_tmp(tyenv, stmt.tmp)

        return None

    def _vex_const_chain_replacement(self, stmt, tmp_exprs, tyenv):
        if not isinstance(stmt, pyvex.stmt.WrTmp) or not isinstance(stmt.data, pyvex.expr.Binop):
            return None

        op = stmt.data.op
        if not op.startswith(("Iop_Or", "Iop_And", "Iop_Xor")):
            return None

        const_expr, var_expr = self._vex_const_and_var_arg(stmt.data)
        if const_expr is None or not isinstance(var_expr, pyvex.expr.RdTmp):
            return None

        pred_expr = tmp_exprs.get(var_expr.tmp)
        if not isinstance(pred_expr, pyvex.expr.Binop) or pred_expr.op != op:
            return None

        pred_const_expr, pred_var_expr = self._vex_const_and_var_arg(pred_expr)
        if pred_const_expr is None:
            return None

        const_value = const_expr.con.value
        pred_const_value = pred_const_expr.con.value

        if op.startswith("Iop_Or"):
            combined_value = pred_const_value | const_value
            mask = self._vex_mask_for_tmp(tyenv, stmt.tmp)
            if combined_value == pred_const_value:
                return var_expr
            if mask is not None and combined_value == mask:
                return self._vex_make_const_like(const_expr, combined_value)
        elif op.startswith("Iop_And"):
            combined_value = pred_const_value & const_value
            mask = self._vex_mask_for_tmp(tyenv, stmt.tmp)
            if combined_value == pred_const_value:
                return var_expr
            if combined_value == 0:
                return self._vex_zero_const_for_tmp(tyenv, stmt.tmp)
            if mask is not None and combined_value == mask:
                return pred_var_expr
        else:
            combined_value = pred_const_value ^ const_value
            if combined_value == 0:
                return pred_var_expr

        return pyvex.expr.Binop(op, [pred_var_expr, self._vex_make_const_like(const_expr, combined_value)])

    def _vex_shift_expr(self, expr, tmp_exprs):
        if not isinstance(expr, pyvex.expr.RdTmp):
            return None

        pred_expr = tmp_exprs.get(expr.tmp)
        if not isinstance(pred_expr, pyvex.expr.Binop) or len(pred_expr.args) != 2:
            return None

        if pred_expr.op.startswith("Iop_Shl"):
            direction = "left"
        elif pred_expr.op.startswith("Iop_Shr"):
            direction = "right"
        else:
            return None

        value_expr, shift_expr = pred_expr.args
        if not isinstance(shift_expr, pyvex.expr.Const):
            return None

        return direction, pred_expr.op, value_expr, shift_expr

    def _vex_rotate_replacement(self, stmt, tmp_exprs, tyenv):
        if not isinstance(stmt, pyvex.stmt.WrTmp) or not isinstance(stmt.data, pyvex.expr.Binop):
            return None
        if not stmt.data.op.startswith("Iop_Or"):
            return None

        bits = self._vex_bits_for_tmp(tyenv, stmt.tmp)
        if bits not in (8, 16, 32, 64):
            return None

        left_shift = self._vex_shift_expr(stmt.data.args[0], tmp_exprs)
        right_shift = self._vex_shift_expr(stmt.data.args[1], tmp_exprs)
        if left_shift is None or right_shift is None:
            return None

        direction0, op0, value0, amount_expr0 = left_shift
        direction1, op1, value1, amount_expr1 = right_shift
        amount0 = amount_expr0.con.value
        amount1 = amount_expr1.con.value
        if direction0 == direction1 or amount0 <= 0 or amount1 <= 0 or amount0 + amount1 != bits:
            return None

        value0_key = self._vex_expr_key(value0)
        value1_key = self._vex_expr_key(value1)
        if value0_key is None or value0_key != value1_key:
            return None

        return pyvex.expr.Binop(
            stmt.data.op,
            [
                pyvex.expr.Binop(op0, [value0, amount_expr0]),
                pyvex.expr.Binop(op1, [value1, amount_expr1]),
            ],
        )

    def _vex_masked_shift_replacement(self, stmt, tmp_exprs):
        if not isinstance(stmt, pyvex.stmt.WrTmp) or not isinstance(stmt.data, pyvex.expr.Binop):
            return None
        if not stmt.data.op.startswith("Iop_And"):
            return None

        const_expr, var_expr = self._vex_const_and_var_arg(stmt.data)
        if const_expr is None or not isinstance(var_expr, pyvex.expr.RdTmp):
            return None

        pred_expr = tmp_exprs.get(var_expr.tmp)
        if not isinstance(pred_expr, pyvex.expr.Binop) or not pred_expr.op.startswith(("Iop_Shl", "Iop_Shr")):
            return None
        if len(pred_expr.args) != 2 or not isinstance(pred_expr.args[1], pyvex.expr.Const):
            return None

        return pyvex.expr.Binop(stmt.data.op, [pred_expr, const_expr])

    def _vex_inline_single_use_const_binop_predecessors(self, node):
        defs = {}
        use_counts = Counter()

        for idx, stmt in enumerate(node.irsb.statements):
            if isinstance(stmt, pyvex.stmt.WrTmp):
                defs[stmt.tmp] = (idx, stmt)
            for expr in getattr(stmt, "expressions", []):
                if isinstance(expr, pyvex.expr.RdTmp):
                    use_counts[expr.tmp] += 1
        if isinstance(node.irsb.next, pyvex.expr.RdTmp):
            use_counts[node.irsb.next.tmp] += 1

        new_statements = list(node.irsb.statements)
        inline_count = 0

        for idx, stmt in enumerate(new_statements):
            if not isinstance(stmt, pyvex.stmt.WrTmp) or not self._vex_const_binop_inline_allowed(stmt.data):
                continue

            candidate_arg_idx = None
            candidate_tmp = None
            for arg_idx, arg in enumerate(stmt.data.args):
                if isinstance(arg, pyvex.expr.RdTmp) and use_counts[arg.tmp] == 1 and arg.tmp in defs:
                    candidate_arg_idx = arg_idx
                    candidate_tmp = arg.tmp
                    break
            if candidate_tmp is None:
                continue

            pred_idx, pred_stmt = defs[candidate_tmp]
            if pred_idx >= idx or not self._vex_const_binop_inline_allowed(pred_stmt.data):
                continue
            if self._vex_expr_depth(pred_stmt.data) > 2:
                continue

            new_args = list(stmt.data.args)
            new_args[candidate_arg_idx] = copy.deepcopy(pred_stmt.data)
            new_expr = pyvex.expr.Binop(stmt.data.op, new_args)
            if self._vex_expr_depth(new_expr) > 4:
                continue

            new_stmt = pyvex.stmt.WrTmp(stmt.tmp, new_expr)
            new_statements[idx] = new_stmt
            defs[stmt.tmp] = (idx, new_stmt)
            inline_count += 1

        if inline_count:
            node.irsb = pyvex.IRSB.empty_block(
                node.irsb.arch,
                node.irsb.addr,
                statements=new_statements,
                tyenv=node.irsb.tyenv,
                nxt=node.irsb.next,
                direct_next=node.irsb.direct_next,
                jumpkind=node.irsb.jumpkind,
                size=node.irsb.size,
            )

        return inline_count

    def _vex_inline_single_use_pure_operands(
            self,
            node,
            max_pred_depth=4,
            max_result_depth=7,
            max_result_size=18,
            max_replacements_per_stmt=4):
        defs = {}
        use_counts = Counter()
        statements = list(node.irsb.statements)

        for idx, stmt in enumerate(statements):
            if isinstance(stmt, pyvex.stmt.WrTmp):
                defs[stmt.tmp] = (idx, stmt)
            for expr in getattr(stmt, "expressions", []):
                if isinstance(expr, pyvex.expr.RdTmp):
                    use_counts[expr.tmp] += 1
        if isinstance(node.irsb.next, pyvex.expr.RdTmp):
            use_counts[node.irsb.next.tmp] += 1

        inline_count = 0
        changed = False

        for idx, stmt in enumerate(statements):
            replacements = {}
            replacement_count = 0
            for expr in list(getattr(stmt, "expressions", [])):
                if not isinstance(expr, pyvex.expr.RdTmp) or use_counts[expr.tmp] != 1 or expr.tmp not in defs:
                    continue

                pred_idx, pred_stmt = defs[expr.tmp]
                if pred_idx >= idx:
                    continue

                pred_expr = pred_stmt.data
                if not self._vex_pure_operand_inline_allowed(pred_expr):
                    continue
                if self._vex_inline_expr_depth(pred_expr) > max_pred_depth:
                    continue
                if self._vex_inline_expr_size(pred_expr) > max_result_size:
                    continue
                if self._vex_has_put_barrier(statements, pred_idx, idx, self._vex_get_offsets(pred_expr)):
                    continue

                replacements[expr] = copy.deepcopy(pred_expr)
                replacement_count += 1
                if replacement_count >= max_replacements_per_stmt:
                    break

            if not replacements:
                continue

            if isinstance(stmt, pyvex.stmt.WrTmp):
                new_data = copy.deepcopy(stmt.data)
                new_data.replace_expression(replacements)
                if self._vex_inline_expr_depth(new_data) > max_result_depth:
                    continue
                if self._vex_inline_expr_size(new_data) > max_result_size:
                    continue
                new_stmt = pyvex.stmt.WrTmp(stmt.tmp, new_data)
                statements[idx] = new_stmt
                defs[stmt.tmp] = (idx, new_stmt)
            else:
                stmt.replace_expression(replacements)

            inline_count += len(replacements)
            changed = True

        if changed:
            node.irsb = pyvex.IRSB.empty_block(
                node.irsb.arch,
                node.irsb.addr,
                statements=statements,
                tyenv=node.irsb.tyenv,
                nxt=node.irsb.next,
                direct_next=node.irsb.direct_next,
                jumpkind=node.irsb.jumpkind,
                size=node.irsb.size,
            )

        return inline_count

    @logtime
    def simplify_or_zero_vex_inst(self, cfg):
        print("Simplify VEX identity instructions")
        simplified_count = 0
        rewritten_count = 0
        rotate_count = 0
        masked_shift_count = 0
        single_use_inline_count = 0
        pure_operand_inline_count = 0

        for node in cfg.nodes():
            if node.is_simprocedure:
                continue

            tmp_replace_dict = {}
            tmp_expr_keys = {}
            tmp_exprs = {}
            new_statements = []

            for stmt in node.irsb.statements:
                if not isinstance(stmt, pyvex.stmt.IMark):
                    replacements = {}
                    for expr in stmt.expressions:
                        if isinstance(expr, pyvex.expr.RdTmp) and expr.tmp in tmp_replace_dict:
                            replacements[expr] = tmp_replace_dict[expr.tmp]
                    if replacements:
                        stmt.replace_expression(replacements)

                replacement = self._vex_identity_replacement(stmt, tmp_expr_keys, node.irsb.tyenv)
                if replacement is not None:
                    if not isinstance(replacement, (pyvex.expr.RdTmp, pyvex.expr.Const)):
                        new_statements.append(pyvex.stmt.WrTmp(stmt.tmp, replacement))
                        tmp_expr_keys[stmt.tmp] = self._vex_expr_key(replacement)
                        tmp_exprs[stmt.tmp] = replacement
                        continue
                    while isinstance(replacement, pyvex.expr.RdTmp) and replacement.tmp in tmp_replace_dict:
                        replacement = tmp_replace_dict[replacement.tmp]
                    tmp_replace_dict[stmt.tmp] = replacement
                    tmp_expr_keys[stmt.tmp] = self._vex_expr_key(replacement)
                    tmp_exprs[stmt.tmp] = replacement
                    simplified_count += 1
                    continue

                replacement = self._vex_const_chain_replacement(stmt, tmp_exprs, node.irsb.tyenv)
                if replacement is not None:
                    if isinstance(replacement, (pyvex.expr.RdTmp, pyvex.expr.Const)):
                        while isinstance(replacement, pyvex.expr.RdTmp) and replacement.tmp in tmp_replace_dict:
                            replacement = tmp_replace_dict[replacement.tmp]
                        tmp_replace_dict[stmt.tmp] = replacement
                        tmp_expr_keys[stmt.tmp] = self._vex_expr_key(replacement)
                        tmp_exprs[stmt.tmp] = replacement
                        simplified_count += 1
                        continue

                    stmt = pyvex.stmt.WrTmp(stmt.tmp, replacement)
                    rewritten_count += 1

                replacement = self._vex_rotate_replacement(stmt, tmp_exprs, node.irsb.tyenv)
                if replacement is not None:
                    stmt = pyvex.stmt.WrTmp(stmt.tmp, replacement)
                    rotate_count += 1

                replacement = self._vex_masked_shift_replacement(stmt, tmp_exprs)
                if replacement is not None:
                    stmt = pyvex.stmt.WrTmp(stmt.tmp, replacement)
                    masked_shift_count += 1

                if isinstance(stmt, pyvex.stmt.WrTmp):
                    tmp_expr_keys[stmt.tmp] = self._vex_expr_key(stmt.data)
                    tmp_exprs[stmt.tmp] = stmt.data

                new_statements.append(stmt)

            new_next = node.irsb.next
            if isinstance(new_next, pyvex.expr.RdTmp) and new_next.tmp in tmp_replace_dict:
                replacement = tmp_replace_dict[new_next.tmp]
                if isinstance(replacement, pyvex.expr.RdTmp):
                    block_id = getattr(new_next, "block_id", None)
                    new_next = DataSensitiveRdTmp(replacement.tmp, block_id) if block_id is not None else replacement

            if len(new_statements) != len(node.irsb.statements) or new_next is not node.irsb.next:
                node.irsb = pyvex.IRSB.empty_block(
                    node.irsb.arch,
                    node.irsb.addr,
                    statements=new_statements,
                    tyenv=node.irsb.tyenv,
                    nxt=new_next,
                    direct_next=node.irsb.direct_next,
                    jumpkind=node.irsb.jumpkind,
                    size=node.irsb.size,
                )

        self.simplified_vex_or_identities = simplified_count
        self.simplified_vex_const_chains = rewritten_count
        self.simplified_vex_rotates = rotate_count
        self.simplified_vex_masked_shifts = masked_shift_count

        for node in cfg.nodes():
            if not node.is_simprocedure:
                single_use_inline_count += self._vex_inline_single_use_const_binop_predecessors(node)
        self.simplified_vex_single_use_const_binop_inlines = single_use_inline_count

        for node in cfg.nodes():
            if not node.is_simprocedure:
                pure_operand_inline_count += self._vex_inline_single_use_pure_operands(node)
        self.simplified_vex_single_use_pure_operand_inlines = pure_operand_inline_count
        return cfg

    @logtime
    def run_pre_decompilation_vex_simplifications(self, cfg, proj, start_state=None, keep_sp_changes_dae=False):
        cfg = self.simplify_or_zero_vex_inst(cfg)
        cfg = self.remove_overwritten_sp_updates(cfg, proj)
        cfg = self.run_post_sp_cleanup_dae(
            cfg,
            proj,
            keep_sp_changes_dae=keep_sp_changes_dae,
            iterations=_project_int_attr(proj, "vm_deobf_post_sp_cleanup_dae_iterations", 25),
        )
        cfg = self.remove_redundant_store_load(cfg, proj, start_state=start_state)
        cfg = self.run_post_sp_cleanup_dae(
            cfg,
            proj,
            keep_sp_changes_dae=keep_sp_changes_dae,
            iterations=_project_int_attr(proj, "vm_deobf_post_store_load_dae_iterations", 5),
        )
        cfg = self.remove_conservative_local_memory_redundancies(cfg)
        cfg = self.run_post_sp_cleanup_dae(
            cfg,
            proj,
            keep_sp_changes_dae=keep_sp_changes_dae,
            iterations=_project_int_attr(proj, "vm_deobf_post_local_memory_dae_iterations", 15),
        )
        return self.remove_segment_selector_vex_inst(cfg)

    @staticmethod
    def _vex_expr_uses_get_offset(expr, reg_offset):
        if expr is None:
            return False
        if isinstance(expr, pyvex.expr.Get):
            return expr.offset == reg_offset
        if isinstance(expr, pyvex.expr.ITE):
            return any(
                VMDeobfuscation._vex_expr_uses_get_offset(child, reg_offset)
                for child in (expr.cond, expr.iftrue, expr.iffalse)
            )
        if isinstance(expr, pyvex.expr.Load):
            return VMDeobfuscation._vex_expr_uses_get_offset(expr.addr, reg_offset)
        args = getattr(expr, "args", None)
        if args is not None:
            return any(VMDeobfuscation._vex_expr_uses_get_offset(arg, reg_offset) for arg in args)
        return False

    @staticmethod
    def _vex_stmt_uses_get_offset(stmt, reg_offset):
        return any(
            VMDeobfuscation._vex_expr_uses_get_offset(expr, reg_offset)
            for expr in getattr(stmt, "expressions", ())
        )

    @staticmethod
    def _vex_stmt_may_observe_sp(stmt):
        return isinstance(stmt, (pyvex.stmt.Dirty, pyvex.stmt.CAS, pyvex.stmt.LLSC))

    @logtime
    def remove_overwritten_sp_updates(self, cfg, proj):
        print("Remove overwritten stack pointer updates")
        sp_offset = proj.arch.sp_offset
        removed_count = 0
        removed_by_block = Counter()

        for node in cfg.nodes():
            if node.is_simprocedure or getattr(node, "irsb", None) is None:
                continue

            statements = list(node.irsb.statements)
            keep_statement = [True] * len(statements)
            sp_live = True

            for stmt_idx in range(len(statements) - 1, -1, -1):
                stmt = statements[stmt_idx]

                if isinstance(stmt, pyvex.stmt.Put) and stmt.offset == sp_offset:
                    if not sp_live:
                        keep_statement[stmt_idx] = False
                        removed_count += 1
                        block_id = getattr(node, "block_id", None)
                        removed_by_block[(node.addr, getattr(block_id, "vm_vpc", None))] += 1

                    sp_live = self._vex_expr_uses_get_offset(stmt.data, sp_offset)
                    continue

                if self._vex_stmt_uses_get_offset(stmt, sp_offset) or self._vex_stmt_may_observe_sp(stmt):
                    sp_live = True

            if all(keep_statement):
                continue

            node.irsb = pyvex.IRSB.empty_block(
                node.irsb.arch,
                node.irsb.addr,
                statements=[stmt for stmt, keep in zip(statements, keep_statement) if keep],
                tyenv=node.irsb.tyenv,
                nxt=node.irsb.next,
                direct_next=node.irsb.direct_next,
                jumpkind=node.irsb.jumpkind,
                size=node.irsb.size,
            )

        self.removed_overwritten_sp_updates = removed_count
        self.removed_overwritten_sp_updates_by_block = removed_by_block
        return cfg

    @staticmethod
    def _vex_stmt_count(cfg):
        return sum(
            len(node.irsb.statements)
            for node in cfg.nodes()
            if not node.is_simprocedure and getattr(node, "irsb", None) is not None
        )

    @logtime
    def run_post_sp_cleanup_dae(self, cfg, proj, keep_sp_changes_dae=False, iterations=3):
        print("Run post-SP-cleanup dead assignment elimination")
        pass_counts = []

        for iteration in range(iterations):
            before_count = self._vex_stmt_count(cfg)
            cfg = self._eliminate_dead_assignments(cfg, proj, keep_sp_changes_dae=keep_sp_changes_dae)
            after_count = self._vex_stmt_count(cfg)
            pass_counts.append((before_count, after_count))
            print("post-SP cleanup DAE iteration %d: %d -> %d" % (iteration, before_count, after_count))

            if after_count == before_count:
                break

        self.post_sp_cleanup_dae_counts = pass_counts
        return cfg

    def _vex_type_size(self, ty):
        if isinstance(ty, str) and ty.startswith("Ity_I"):
            bits = int(ty[5:])
            if bits % 8 != 0:
                return None
            return bits // 8
        return None

    def _vex_expr_size(self, expr, tyenv):
        try:
            return self._vex_type_size(expr.result_type(tyenv))
        except (AttributeError, TypeError):
            return None

    @staticmethod
    def _vex_expr_has_load(expr):
        if isinstance(expr, pyvex.expr.Load):
            return True
        return any(
            VMDeobfuscation._vex_expr_has_load(child)
            for child in VMDeobfuscation._vex_inline_expr_children(expr)
        )

    @staticmethod
    def _vex_stmt_has_load(stmt):
        return any(
            VMDeobfuscation._vex_expr_has_load(expr)
            for expr in getattr(stmt, "expressions", ())
        )

    @staticmethod
    def _vex_get_ranges(expr, tyenv):
        ranges = set()
        if isinstance(expr, pyvex.expr.Get):
            try:
                size = expr.result_size(tyenv) // 8
            except (AttributeError, TypeError):
                size = None
            ranges.add((expr.offset, size))
        for child in VMDeobfuscation._vex_inline_expr_children(expr):
            ranges.update(VMDeobfuscation._vex_get_ranges(child, tyenv))
        return ranges

    @staticmethod
    def _vex_put_may_overlap_get_ranges(put_offset, put_size, get_ranges):
        for get_offset, get_size in get_ranges:
            if put_size is None or get_size is None:
                if put_offset == get_offset:
                    return True
                continue

            if put_offset < get_offset + get_size and get_offset < put_offset + put_size:
                return True

        return False

    def _invalidate_local_memory_facts_for_put(self, pending_stores, stmt, tyenv):
        put_size = self._vex_expr_size(stmt.data, tyenv)
        for addr_key, store_info in list(pending_stores.items()):
            if self._vex_put_may_overlap_get_ranges(stmt.offset, put_size, store_info["addr_get_ranges"]):
                del pending_stores[addr_key]

    def _collect_conservative_local_memory_rewrites(self, irsb):
        pending_stores = {}
        remove_store_stmt_idxs = set()
        load_replacements = {}
        store_generation = 0

        for idx, stmt in enumerate(irsb.statements):
            if isinstance(stmt, (pyvex.stmt.Dirty, pyvex.stmt.CAS, pyvex.stmt.LLSC)):
                pending_stores.clear()
                continue

            if isinstance(stmt, pyvex.stmt.Put):
                self._invalidate_local_memory_facts_for_put(pending_stores, stmt, irsb.tyenv)

            if isinstance(stmt, pyvex.stmt.WrTmp) and isinstance(stmt.data, pyvex.expr.Load):
                addr_key = str(stmt.data.addr)
                store_info = pending_stores.get(addr_key)
                load_size = self._vex_type_size(stmt.data.ty)
                if (
                        store_info is not None
                        and store_info["store_generation"] == store_generation
                        and store_info["size"] is not None
                        and load_size is not None
                        and store_info["size"] == load_size
                        and store_info["endness"] == stmt.data.endness):
                    load_replacements[idx] = copy.deepcopy(store_info["data"])

                pending_stores.clear()
                continue

            if self._vex_stmt_has_load(stmt):
                pending_stores.clear()

            if isinstance(stmt, pyvex.stmt.Store):
                addr_key = str(stmt.addr)
                store_size = self._vex_expr_size(stmt.data, irsb.tyenv)
                store_info = pending_stores.get(addr_key)
                if (
                        store_info is not None
                        and store_info["size"] is not None
                        and store_size is not None
                        and store_info["size"] == store_size
                        and store_info["endness"] == stmt.endness):
                    remove_store_stmt_idxs.add(store_info["stmt_idx"])

                store_generation += 1
                if store_size is not None:
                    pending_stores[addr_key] = {
                        "stmt_idx": idx,
                        "size": store_size,
                        "endness": stmt.endness,
                        "data": stmt.data,
                        "addr_get_ranges": self._vex_get_ranges(stmt.addr, irsb.tyenv),
                        "store_generation": store_generation,
                    }

        return remove_store_stmt_idxs, load_replacements

    @logtime
    def remove_conservative_local_memory_redundancies(self, cfg):
        print("Remove conservative local memory redundancies")
        removed_store_count = 0
        forwarded_load_count = 0
        removed_by_block = Counter()
        forwarded_by_block = Counter()

        for node in cfg.nodes():
            if node.is_simprocedure or getattr(node, "irsb", None) is None:
                continue

            remove_store_stmt_idxs, load_replacements = self._collect_conservative_local_memory_rewrites(node.irsb)
            if not remove_store_stmt_idxs and not load_replacements:
                continue

            new_statements = []
            for idx, stmt in enumerate(node.irsb.statements):
                if idx in remove_store_stmt_idxs:
                    removed_store_count += 1
                    block_id = getattr(node, "block_id", None)
                    removed_by_block[(node.addr, getattr(block_id, "vm_vpc", None))] += 1
                    continue

                if idx in load_replacements:
                    forwarded_load_count += 1
                    block_id = getattr(node, "block_id", None)
                    forwarded_by_block[(node.addr, getattr(block_id, "vm_vpc", None))] += 1
                    new_statements.append(pyvex.stmt.WrTmp(stmt.tmp, load_replacements[idx]))
                    continue

                new_statements.append(stmt)

            node.irsb = pyvex.IRSB.empty_block(
                node.irsb.arch,
                node.irsb.addr,
                statements=new_statements,
                tyenv=node.irsb.tyenv,
                nxt=node.irsb.next,
                direct_next=node.irsb.direct_next,
                jumpkind=node.irsb.jumpkind,
                size=node.irsb.size,
            )

        self.local_memory_removed_stores = removed_store_count
        self.local_memory_forwarded_loads = forwarded_load_count
        self.local_memory_removed_stores_by_block = removed_by_block
        self.local_memory_forwarded_loads_by_block = forwarded_by_block
        return cfg

    @logtime
    @skip_if_unchanged
    def remove_redundant_assignment(self, cfg, proj, start_state=None):
        # This looks like
        # t33 = t27
        # or t81 = Add64(t66,0x0000000000000000)
        # or t81 = Sub64(t66,0x0000000000000000)
        # e.g. resulting after the `remove_redundant_store_load` simplification
        print("Remove redundant assignment")
        #dsa_new_model = self.new_model_graph(cfg.graph, proj, 'redun_assignment')
        dsa_new_model = cfg
        for node in dsa_new_model.nodes():
            if node.addr == self.vm_start_addr:
                start_node = node
                break

        for node in dsa_new_model.nodes():
            if node.is_simprocedure:
                continue

            # if node.addr == 0x1400ff7b0 and node.block_id.vm_vpc == 5369364494:
            #     import ipdb;ipdb.set_trace()

            tmp_replace_dict = {}
            new_statements = []
            for stmt in node.irsb.statements:
                #checking for  t33 = t27
                if isinstance(stmt, pyvex.stmt.WrTmp) and isinstance(stmt.data, pyvex.expr.RdTmp):
                    to_be_replaced_with = stmt.data
                    while to_be_replaced_with in tmp_replace_dict:
                        # This is for the recursive replacements
                        to_be_replaced_with = tmp_replace_dict[to_be_replaced_with]
                    tmp_replace_dict[pyvex.expr.RdTmp(stmt.tmp)] = to_be_replaced_with
                    continue
                #checking for t81 = Add64(t66,0x0000000000000000)
                elif isinstance(stmt, pyvex.stmt.WrTmp) and isinstance(stmt.data, pyvex.expr.Binop) and stmt.data.op[4:7] in ['Add', 'Sub']:
                    if stmt.data.op[4:].startswith('Add'):
                        check = False
                        for a in stmt.data.args:
                            if isinstance(a, pyvex.expr.Const) and a.con.value == 0:
                                check = True
                            if isinstance(a, pyvex.expr.RdTmp):
                                to_be_replaced_with = a
                        if check:
                            while to_be_replaced_with in tmp_replace_dict:
                                # This is for the recursive replacements
                                to_be_replaced_with = tmp_replace_dict[to_be_replaced_with]
                            tmp_replace_dict[pyvex.expr.RdTmp(stmt.tmp)] = to_be_replaced_with
                            continue
                    elif stmt.data.op[4:].startswith('Sub'):
                        #making sure that for Sub it looks like this only Sub(t3,0) and not like Sub(0,t3)
                        if isinstance(stmt.data.args[1], pyvex.expr.Const) and stmt.data.args[1].con.value == 0 and isinstance(stmt.data.args[0], pyvex.expr.RdTmp):
                            to_be_replaced_with = stmt.data.args[0]
                            while to_be_replaced_with in tmp_replace_dict:
                                # This is for the recursive replacements
                                to_be_replaced_with = tmp_replace_dict[to_be_replaced_with]
                            tmp_replace_dict[pyvex.expr.RdTmp(stmt.tmp)] = to_be_replaced_with
                            continue


                if not isinstance(stmt, pyvex.stmt.IMark):
                    for tmp in tmp_replace_dict:
                        for expr in stmt.expressions:
                            if expr == tmp:
                                stmt.replace_expression({expr: tmp_replace_dict[tmp]})
                new_statements.append(stmt)

            #also make sure the replacements happen for next
            new_next = node.irsb.next
            if isinstance(node.irsb.next, pyvex.expr.RdTmp):
                for tmp in tmp_replace_dict:
                    if node.irsb.next.tmp == tmp.tmp:
                        new_next = DataSensitiveRdTmp(tmp_replace_dict[tmp].tmp, node.irsb.next.block_id)

            if tmp_replace_dict or new_next is not node.irsb.next:
                self._note_change(node)

            node.irsb = pyvex.IRSB.empty_block(node.irsb.arch,
                                               node.irsb.addr,
                                               statements=new_statements,
                                               tyenv=node.irsb.tyenv,
                                               nxt=new_next,
                                               direct_next=node.irsb.direct_next,
                                               jumpkind=node.irsb.jumpkind,
                                               size=node.irsb.size)

        # Returning a new CFGVMDeobfuscation object with the updated graph
        # if start_state:
        #     initial_input_state = start_state
        # else:
        #     initial_input_state = proj.factory.blank_state(addr=self.start_addr,
        #                                                    mode='fastpath',
        #                                                    add_options=angr.sim_options.refs | {
        #                                                        angr.sim_options.REPLACEMENT_SOLVER,
        #                                                        angr.sim_options.DO_CCALLS})
        # dsa_new_model._nodes_by_addr[self.start_addr][0].input_state = initial_input_state
        # new_cfg = proj.analyses.CFGVMDeobfuscation(model=dsa_new_model, keep_state=True, iropt_level=1,
        #                                            resolve_indirect_jumps=True, max_iterations=1,
        #                                            vm_vpc_addr=self.vm_vpc_addr)
        print("Done")
        return dsa_new_model

    def _vex_type_size(self, ty):
        if isinstance(ty, str) and ty.startswith("Ity_I"):
            bits = int(ty[5:])
            if bits % 8 != 0:
                return None
            return bits // 8
        return None

    @staticmethod
    def _memory_atom_addr_key(atom):
        if not isinstance(atom, atoms.MemoryLocation):
            return None

        addr = atom.addr
        if isinstance(addr, SpOffset):
            return "stack", addr.offset
        if isinstance(addr, int):
            return "const", addr
        if hasattr(addr, "value"):
            return "const", addr.value
        return None

    @staticmethod
    def _is_zero_vex_expr(expr):
        return isinstance(expr, pyvex.expr.Const) and expr.con.value == 0

    @staticmethod
    def _is_same_vex_addr(a, b):
        return a == b or str(a) == str(b)

    def _vex_expr_size(self, expr, tyenv):
        try:
            return self._vex_type_size(expr.result_type(tyenv))
        except (AttributeError, TypeError):
            return None

    def _vex_const_signed_value(self, const):
        size = self._vex_type_size(getattr(const, "type", None))
        if size is None or size <= 0:
            size = 8
        bits = size * 8
        value = const.value
        sign_bit = 1 << (bits - 1)
        if value & sign_bit:
            value -= 1 << bits
        return value

    def _vex_const_expr_signed_value(self, expr, tmp_constants):
        if isinstance(expr, pyvex.expr.Const):
            return self._vex_const_signed_value(expr.con)
        if isinstance(expr, pyvex.expr.RdTmp):
            return tmp_constants.get(expr.tmp, None)
        return None

    def _vex_stack_addr_offset(self, expr, tmp_stack_offsets, reg_stack_offsets, tmp_constants):
        if isinstance(expr, pyvex.expr.RdTmp):
            return tmp_stack_offsets.get(expr.tmp, None)

        if isinstance(expr, pyvex.expr.Get):
            return reg_stack_offsets.get(expr.offset, None)

        if isinstance(expr, pyvex.expr.Binop) and expr.op.startswith("Iop_Add"):
            first, second = expr.args
            first_const = self._vex_const_expr_signed_value(first, tmp_constants)
            second_const = self._vex_const_expr_signed_value(second, tmp_constants)
            if first_const is not None:
                offset = self._vex_stack_addr_offset(second, tmp_stack_offsets, reg_stack_offsets, tmp_constants)
                const_value = first_const
            elif second_const is not None:
                offset = self._vex_stack_addr_offset(first, tmp_stack_offsets, reg_stack_offsets, tmp_constants)
                const_value = second_const
            else:
                return None

            if offset is not None:
                return offset + const_value

        if isinstance(expr, pyvex.expr.Binop) and expr.op.startswith("Iop_Sub"):
            first, second = expr.args
            second_const = self._vex_const_expr_signed_value(second, tmp_constants)
            if second_const is not None:
                offset = self._vex_stack_addr_offset(first, tmp_stack_offsets, reg_stack_offsets, tmp_constants)
                if offset is not None:
                    return offset - second_const

        return None

    @staticmethod
    def _remove_overlapping_stack_stores(stores, offset, size):
        end = offset + size
        for key in list(stores.keys()):
            store_offset, store_size = key
            store_end = store_offset + store_size
            if offset < store_end and store_offset < end:
                del stores[key]

    def _try_make_local_stack_replacement(self, stores, offset, load_size, load_endness):
        if load_endness != "Iend_LE":
            return None

        same_size_store = stores.get((offset, load_size))
        if same_size_store is not None:
            return same_size_store.data

        containing_qword_store = stores.get((offset, 8))
        if load_size == 4 and containing_qword_store is not None:
            return pyvex.expr.Unop("Iop_64to32", [containing_qword_store.data])

        low_store = stores.get((offset, 4))
        high_store = stores.get((offset + 4, 4))
        if load_size == 8 and low_store is not None and high_store is not None:
            if self._is_zero_vex_expr(high_store.data):
                return pyvex.expr.Unop("Iop_32Uto64", [low_store.data])

        return None

    def _collect_local_store_load_replacements(self, irsb):
        tmp_stack_offsets = {}
        tmp_constants = {}
        reg_stack_offsets = {self.project.arch.sp_offset: 0}
        stores = {}
        replacements = {}

        for idx, stmt in enumerate(irsb.statements):
            if isinstance(stmt, pyvex.stmt.WrTmp):
                if isinstance(stmt.data, pyvex.expr.Load):
                    load_offset = self._vex_stack_addr_offset(
                        stmt.data.addr,
                        tmp_stack_offsets,
                        reg_stack_offsets,
                        tmp_constants,
                    )
                    load_size = self._vex_type_size(stmt.data.ty)
                    if load_offset is not None and load_size is not None:
                        replacement = self._try_make_local_stack_replacement(
                            stores,
                            load_offset,
                            load_size,
                            stmt.data.endness,
                        )
                        if replacement is not None:
                            replacements[idx] = replacement

                tmp_stack_offsets[stmt.tmp] = self._vex_stack_addr_offset(
                    stmt.data,
                    tmp_stack_offsets,
                    reg_stack_offsets,
                    tmp_constants,
                )
                tmp_constants[stmt.tmp] = self._vex_const_expr_signed_value(stmt.data, tmp_constants)

            elif isinstance(stmt, pyvex.stmt.Put):
                stack_offset = self._vex_stack_addr_offset(
                    stmt.data,
                    tmp_stack_offsets,
                    reg_stack_offsets,
                    tmp_constants,
                )
                if stack_offset is None:
                    reg_stack_offsets.pop(stmt.offset, None)
                else:
                    reg_stack_offsets[stmt.offset] = stack_offset

            elif isinstance(stmt, pyvex.stmt.Store):
                store_offset = self._vex_stack_addr_offset(
                    stmt.addr,
                    tmp_stack_offsets,
                    reg_stack_offsets,
                    tmp_constants,
                )
                store_size = self._vex_expr_size(stmt.data, irsb.tyenv)
                if store_offset is None or store_size is None:
                    stores.clear()
                else:
                    self._remove_overlapping_stack_stores(stores, store_offset, store_size)
                    stores[(store_offset, store_size)] = stmt

            elif isinstance(stmt, (pyvex.stmt.CAS, pyvex.stmt.LLSC, pyvex.stmt.Dirty)):
                stores.clear()

        return replacements

    def _try_make_redundant_store_load_replacement(self, irsb, defs_at_use, use_stmt_idx):
        use_stmt = irsb.statements[use_stmt_idx]
        if not isinstance(use_stmt, pyvex.stmt.WrTmp) or not isinstance(use_stmt.data, pyvex.expr.Load):
            return None

        load = use_stmt.data
        load_size = self._vex_type_size(load.ty)
        if load_size is None:
            return None

        store_defs = []
        for d in defs_at_use:
            if not isinstance(d.atom, atoms.MemoryLocation):
                continue
            if isinstance(d.codeloc, ExternalCodeLocation) or d.dummy or d.codeloc.stmt_idx is None:
                return None
            if d.codeloc.stmt_idx >= use_stmt_idx:
                return None

            store_stmt = irsb.statements[d.codeloc.stmt_idx]
            if not isinstance(store_stmt, pyvex.stmt.Store):
                return None

            addr_key = self._memory_atom_addr_key(d.atom)
            if addr_key is None:
                return None

            store_defs.append((d, store_stmt, addr_key))

        if len(store_defs) == 1:
            d, store_stmt, _ = store_defs[0]
            if d.atom.size == load_size:
                return store_stmt.data

            if d.atom.size == 8 and load_size == 4 and load.endness == "Iend_LE":
                if self._is_same_vex_addr(store_stmt.addr, load.addr):
                    return pyvex.expr.Unop("Iop_64to32", [store_stmt.data])

            return None

        if len(store_defs) == 2 and load_size == 8 and load.endness == "Iend_LE":
            first_def, first_store, first_key = store_defs[0]
            second_def, second_store, second_key = store_defs[1]

            if first_key[0] != second_key[0] or first_def.atom.size != 4 or second_def.atom.size != 4:
                return None

            low_def, low_store = (first_def, first_store)
            high_def, high_store = (second_def, second_store)
            if first_key[1] == second_key[1] + 4:
                low_def, low_store = (second_def, second_store)
                high_def, high_store = (first_def, first_store)
            elif second_key[1] != first_key[1] + 4:
                return None

            if low_def.atom.size == 4 and high_def.atom.size == 4 and self._is_zero_vex_expr(high_store.data):
                return pyvex.expr.Unop("Iop_32Uto64", [low_store.data])

        return None

    @logtime
    @skip_if_unchanged
    def remove_redundant_store_load(self, cfg, proj, start_state=None):
        # removing redundant store and loads in a block that look like this
        #------ IMark(0x401212, 0, 0) ------
        # t29 = Add64(t12,0xfffffffffffffe80)
        # STle(t29) = t27
        # ....
        # ....
        # ------ IMark(0x4016bf, 0, 0) ------
        # t31 = Add64(t23,0xfffffffffffffe80)
        # t33 = LDle:I64(t31)
        # the last LDle can be replaced directly with the first t27 giving t33 = t27
        # only doing this block wise to be conservative

        print("Remove redundant store load")
        #dsa_new_model = self.new_model_graph(cfg.graph, proj, 'redun_store_load')
        dsa_new_model = cfg
        for node in dsa_new_model.nodes():
            if node.addr == self.vm_start_addr:
                start_node = node
                break

        for node in dsa_new_model.nodes():
            if node.is_simprocedure:
                continue
            if self._node_is_clean("remove_redundant_store_load", node):
                continue
            _clean_epoch, _clean_counter = self._coarse_epoch, self._change_counter

            cur_block = angr.Block(node.irsb.addr, project=proj, vex=node.irsb)
            rd = self.project.analyses.ReachingDefinitions(cur_block,
                                                           track_tmps=True,
                                                           track_consts=False,
                                                           observation_points=[('node', node.addr, OP_AFTER)]
                                                           )

            # Find redundant loads
            replace_stle_dict = self._collect_local_store_load_replacements(node.irsb)
            all_defs = rd.all_definitions
            for d in all_defs:
                if isinstance(d.codeloc, ExternalCodeLocation) or d.dummy:
                    continue
                if d.codeloc.stmt_idx and isinstance(node.irsb.statements[d.codeloc.stmt_idx], pyvex.stmt.CAS):
                    continue
                uses = rd.all_uses.get_uses(d)

                if isinstance(d.atom, atoms.MemoryLocation) and isinstance(d.atom.addr, SpOffset):
                    for use in uses:
                        # # This is an enternal function or a sim procedure for which I have not written a rda handler
                        # if use.block_id is None:
                        #     continue
                        if use.stmt_idx == DEFAULT_STATEMENT:
                            continue
                        if isinstance(node.irsb.statements[use.stmt_idx], pyvex.stmt.CAS):
                            continue
                        if use.sim_procedure:
                            import ipdb;ipdb.set_trace()

                        if len(rd.all_uses.get_uses_by_location(use)) == 1:
                            replacement = self._try_make_redundant_store_load_replacement(
                                node.irsb,
                                rd.all_uses.get_uses_by_location(use),
                                use.stmt_idx,
                            )
                            if replacement is not None:
                                replace_stle_dict[use.stmt_idx] = replacement

                elif isinstance(d.atom, atoms.MemoryLocation) and \
                    isinstance(node.irsb.statements[d.codeloc.stmt_idx], pyvex.stmt.Store) and \
                    isinstance(node.irsb.statements[d.codeloc.stmt_idx].addr, pyvex.expr.Const):
                    for use in uses:
                        if len(rd.all_uses.get_uses_by_location(use)) == 1:
                            replacement = self._try_make_redundant_store_load_replacement(
                                node.irsb,
                                rd.all_uses.get_uses_by_location(use),
                                use.stmt_idx,
                            )
                            if replacement is not None:
                                replace_stle_dict[use.stmt_idx] = replacement





            if replace_stle_dict:
                self._note_change(node)

            new_statements = []
            # Remove dead assignments
            for idx, stmt in enumerate(cur_block.vex.statements):
                # if isinstance(stmt, pyvex.stmt.WrTmp):
                #     if stmt.tmp not in used_tmp_indices:
                #         continue

                # is it a dead virgin?
                if idx in replace_stle_dict:
                    replaced_stmt = pyvex.stmt.WrTmp(stmt.tmp, replace_stle_dict[idx])
                    new_statements.append(replaced_stmt)
                else:
                    new_statements.append(stmt)

            node.irsb = pyvex.IRSB.empty_block(node.irsb.arch,
                                               node.irsb.addr,
                                               statements=new_statements,
                                               tyenv=node.irsb.tyenv,
                                               nxt=node.irsb.next,
                                               direct_next=node.irsb.direct_next,
                                               jumpkind=node.irsb.jumpkind,
                                               size=node.irsb.size)

            self._mark_node_clean("remove_redundant_store_load", node, _clean_epoch, _clean_counter)

        # Returning a new CFGVMDeobfuscation object with the updated graph
        # if start_state:
        #     initial_input_state = start_state
        # else:
        #     initial_input_state = proj.factory.blank_state(addr=self.start_addr,
        #                                                    mode='fastpath',
        #                                                    add_options=angr.sim_options.refs | {
        #                                                        angr.sim_options.REPLACEMENT_SOLVER,
        #                                                        angr.sim_options.DO_CCALLS})
        # dsa_new_model._nodes_by_addr[self.start_addr][0].input_state = initial_input_state
        # new_cfg = proj.analyses.CFGVMDeobfuscation(model=dsa_new_model, keep_state=True, iropt_level=1,
        #                                            resolve_indirect_jumps=True, max_iterations=1,
        #                                            vm_vpc_addr=self.vm_vpc_addr)
        print("Done")
        return dsa_new_model



# Eliminated dead stack-memdefs and regdefs in the whoel CFG
    @logtime
    @skip_if_unchanged
    def testing_new_improved_whole_vm_RDA_deadassignment_elimination(self, cfg, proj, keep_sp_changes_dae=False):
        print("Whole CFG RDA based dead ass elimination")
        #dsa_new_model = self.new_model_graph(cfg.graph, proj, 'test_rda_dae')
        dsa_new_model =cfg
        # start_state = ReachingDefinitionsState()
        for node in dsa_new_model.nodes():
            if node.addr == self.vm_start_addr:
                start_node = node
                break

        node_dict = {}
        for node in cfg.nodes():
            node_dict[node.block_id] = node

        leaf_nodes_list = []
        for node in list(dsa_new_model.graph.nodes()):
            if not node.is_simprocedure and len(list(dsa_new_model.graph.successors(node))) == 0:
                leaf_nodes_list.append(('node', (node.addr, node.block_id), OP_AFTER))
            elif node.is_simprocedure and node.name == "exit":
                for pred_node in list(dsa_new_model.graph.predecessors(node)):
                    if not (pred_node.is_simprocedure and pred_node.name == "exit"):
                        leaf_nodes_list.append(('node', (pred_node.addr, pred_node.block_id), OP_AFTER))


        rd = self.project.analyses.ReachingDefinitions(subject=Subject((dsa_new_model.graph, start_node)),
                                                       track_tmps=True,
                                                       track_consts=False,
                                                       max_iterations=3,
                                                       observation_points=leaf_nodes_list
                                                       )
        rd.model.liveness.def_to_liveness = None
        rd.model.liveness.loc_to_defs = None
        all_live_defs = list(rd.observed_results.values())
        merged_live_defs, merge_occured= all_live_defs[0].merge(*[live_definitions for live_definitions in all_live_defs[1:]])

        # live_defs = rd.one_result

        # Find dead assignments
        dead_defs_locs = set()
        all_defs = rd.all_definitions

        # There can be multiple memory definitions for the same location with different stack offset because of rd_state merging
        for d in all_defs:
            if isinstance(d.codeloc, ExternalCodeLocation) or d.dummy:
                continue

            uses = rd.all_uses.get_uses(d)
            vs = None
            # if isinstance(d.atom, atoms.MemoryLocation):
            #     no_uses = 0
            #     for use in uses:
            #         # making sure we only count the uses that are Loads, not just any variable having that memory adddress
            #         if use.sim_procedure or use.block_id is None:
            #             no_uses = no_uses + 1
            #         elif isinstance(cfg.get_node(use.block_id).irsb.statements[use.stmt_idx], pyvex.stmt.WrTmp):
            #             if isinstance(cfg.get_node(use.block_id).irsb.statements[use.stmt_idx].data,
            #                           pyvex.expr.Load):
            #                 no_uses = no_uses + 1
            #
            #     if no_uses == 0 and d.atom.is_on_stack:
            #
            #         stack_addr = merged_live_defs.stack_offset_to_stack_addr(d.atom.addr.offset)
            #         vs: 'MultiValues' = merged_live_defs.stack.load(stack_addr, size=d.atom.size,
            #                                                              endness=d.atom.endness)

            # is entirely possible that at the end of the block, a register definition is not used.
            # however, it might be used in future blocks.
            # so we only remove a definition if the definition is not alive anymore at the end of the block

            if not uses:
                if isinstance(d.atom, atoms.Register):
                    ## SKIP removing PUT(rsp) for huffman binary... cdcel ... all args on stack causing probs with decompiler
                    if keep_sp_changes_dae:
                        if d.atom.reg_offset == self.project.arch.sp_offset:
                            continue
                    try:
                        vs: 'MultiValues' = merged_live_defs.registers.load(d.atom.reg_offset, size=d.atom.size)
                    except:
                        vs = None
                # ##THIS IS AN UNSAFE SIMPLIFICATION, ASSUMES ALL CONSTANT ADDRESSES HAVE BEEN PROPAGATED CORRECTLY AND COMPLETELY
                elif self.allow_global_mem_simplifications and isinstance(d.atom, atoms.MemoryLocation) and \
                    isinstance(node_dict[d.codeloc.block_id].irsb.statements[d.codeloc.stmt_idx], pyvex.stmt.Store) and \
                    isinstance(node_dict[d.codeloc.block_id].irsb.statements[d.codeloc.stmt_idx].addr, pyvex.expr.Const):
                    #Only for store at const address in the binary, cannot check d.atom.addr since it's values are not correct for whole cfg rda

                    try:
                        vs: 'MultiValues' = merged_live_defs.memory.load(d.atom.addr, size=d.atom.size,
                                                                              endness=d.atom.endness)
                    except SimMemoryMissingError:
                        vs = None
                else:
                    continue
                if vs is None:
                    continue
                defs_ = set()

                for values in vs.values():
                    for value in values:
                        defs_.update(merged_live_defs.extract_defs(value))

                if d not in defs_:
                    dead_defs_locs.add(d.codeloc)


        #Remove dead assignments
        for node in dsa_new_model.nodes():
            new_statements = []
            if not node.is_simprocedure:
                for idx, stmt in enumerate(node.irsb.statements):
                    if isinstance(stmt, pyvex.stmt.IMark):
                        cur_ins_addr = stmt.addr

                    stmt_loc = CodeLocation(node.irsb.addr,
                                            idx,
                                            block_id=node.block_id,
                                            ins_addr=cur_ins_addr,
                                            context=None)

                    # is it a dead virgin?
                    if stmt_loc in dead_defs_locs:
                        continue

                    new_statements.append(stmt)

                if len(new_statements) != len(node.irsb.statements):
                    self._note_change(node)

                node.irsb = pyvex.IRSB.empty_block(node.irsb.arch,
                                                   node.irsb.addr,
                                                   statements=new_statements,
                                                   tyenv=node.irsb.tyenv,
                                                   nxt=node.irsb.next,
                                                   direct_next=node.irsb.direct_next,
                                                   jumpkind=node.irsb.jumpkind,
                                                   size=node.irsb.size)

            # Returning a new CFGVMDeobfuscation object with the updated graph
        # if start_state:
        #     initial_input_state = start_state
        # else:
        #     initial_input_state = proj.factory.blank_state(addr=self.start_addr,
        #                                                    mode='fastpath',
        #                                                    add_options=angr.sim_options.refs | {
        #                                                        angr.sim_options.REPLACEMENT_SOLVER,
        #                                                        angr.sim_options.DO_CCALLS})
        # dsa_new_model._nodes_by_addr[self.start_addr][0].input_state = initial_input_state
        # new_cfg = proj.analyses.CFGVMDeobfuscation(model=dsa_new_model, keep_state=True, iropt_level=1,
        #                                            resolve_indirect_jumps=True, max_iterations=1,
        #                                            vm_vpc_addr=self.vm_vpc_addr)
        # print("Done")
        # return new_cfg

        return dsa_new_model

    def eliminate_dead_simprocedures(self, cfg, proj, simprocedures_to_remove):
        for node in simprocedures_to_remove:
            if node.is_simprocedure and node.name == "read":
                if len(list(cfg.graph.successors(node))) >0:
                    succ = cfg.graph.successors(node)
                    succ = next(succ)
                    preds = cfg.graph.predecessors(node)
                    to_remove = False
                    for pred in preds:
                        pred_edge_data = cfg.graph.get_edge_data(pred, node)
                        # Reassigning the next expression of the previous
                        if not pred.is_simprocedure:
                            next_val = None
                            if self.project.arch.bits == 32:
                                next_val = pyvex.expr.Const(
                                    DataSensitiveU32(succ.addr,
                                                     succ.block_id))
                            elif self.project.arch.bits == 64:
                                next_val = pyvex.expr.Const(
                                    DataSensitiveU64(succ.addr,
                                                     succ.block_id))
                            cfg.graph.add_edge(pred, succ, jumpkind=pred_edge_data['jumpkind'])
                            if len(pred.irsb.statements) > 0 and isinstance(pred.irsb.statements[-1], pyvex.stmt.Exit):
                                if pred.irsb.statements[-1].dst.block_id == node.block_id:
                                    pred.irsb.statements[-1].dst = next_val.con
                                else:
                                    pred.irsb.next = next_val
                                if pred.irsb.next.con.block_id == pred.irsb.statements[-1].dst.block_id and pred.irsb.statements[-1].dst.value == pred.irsb.next.con.value:
                                    # remove the redundant if cond, if both targets become same
                                    pred.irsb.statements = pred.irsb.statements[:-1]
                            else:
                                pred.irsb.next = next_val
                            to_remove = True
                        else:
                            print("Not removing this block, since there the previous block is a Sim Procedure")
                    if to_remove:
                        cfg.graph.remove_node(node)
        return cfg

    # Eliminates dead memdefs, tmpdefs and regdefs in a single basic block
    @logtime
    @skip_if_unchanged
    def _eliminate_dead_assignments(self, cfg, proj, keep_sp_changes_dae=False):

        def remove_path(cur_cfg, start_node):
            reachable = set(networkx.dfs_preorder_nodes(as_networkx(cur_cfg.graph), source= start_node))
            # Nodes dominated by the edge are now unreachable
            to_prune = [n for n in cur_cfg.graph.nodes if n not in reachable]
            return to_prune

        #dsa_new_model = self.new_model_graph(cfg.graph, proj, 'dae')
        dsa_new_model = cfg
        for node in dsa_new_model.nodes():
            if node.addr == self.vm_start_addr:
                start_node = node
                break

        nodes_to_remove = set()
        for node in list(dsa_new_model.nodes()):
            if node.is_simprocedure:
                continue
            if self._node_is_clean("_eliminate_dead_assignments", node):
                continue
            _clean_epoch, _clean_counter = self._coarse_epoch, self._change_counter

            cur_block = angr.Block(node.irsb.addr, project=proj, vex=node.irsb)
            rd = self.project.analyses.ReachingDefinitions(cur_block,
                                                           track_tmps=True,
                                                           track_consts=False,
                                                           observation_points=[('node', node.addr, OP_AFTER)]
                                                           )
            rd.model.liveness.def_to_liveness = None
            rd.model.liveness.loc_to_defs = None

            used_tmp_indices = set(rd.one_result.tmp_uses.keys())
            live_defs = rd.one_result

            # Find dead assignments
            dead_defs_stmt_idx = defaultdict(int)
            all_defs = rd.all_definitions
            for d in all_defs:
                if isinstance(d.codeloc, ExternalCodeLocation) or d.dummy:
                    continue

                if isinstance(d.atom, atoms.Tmp):
                    uses = live_defs.tmp_uses[d.atom.tmp_idx]
                    if not uses:
                        if isinstance(node.irsb.next, DataSensitiveRdTmp):
                            if node.irsb.next.tmp != d.atom.tmp_idx:
                                dead_defs_stmt_idx[d.codeloc.stmt_idx] +=1
                            else:
                                used_tmp_indices.add(d.atom.tmp_idx)
                        else:
                            dead_defs_stmt_idx[d.codeloc.stmt_idx] += 1

                else:
                    uses = rd.all_uses.get_uses(d)
                    if not uses:
                        # is entirely possible that at the end of the block, a register definition is not used.
                        # however, it might be used in future blocks.
                        # so we only remove a definition if the definition is not alive anymore at the end of the block
                        defs_ = set()
                        vs = None
                        if isinstance(d.atom, atoms.Register):
                            ## SKIP removing PUT(rsp) for huffman binary... cdcel ... all args on stack causing probs with decompiler
                            if keep_sp_changes_dae:
                                if d.atom.reg_offset == self.project.arch.sp_offset:
                                    continue
                            try:
                                vs: 'MultiValues' = live_defs.registers.load(d.atom.reg_offset, size=d.atom.size)
                            except SimMemoryMissingError:
                                vs = None

                        elif isinstance(d.atom, atoms.MemoryLocation) and isinstance(d.atom.addr, SpOffset):
                            stack_addr = live_defs.stack_offset_to_stack_addr(d.atom.addr.offset)
                            if isinstance(node.irsb.statements[d.codeloc.stmt_idx], pyvex.stmt.Store) and \
                                    str(node.irsb.statements[d.codeloc.stmt_idx]) == "STle(t464) = t120":
                                import ipdb;
                                ipdb.set_trace()
                            try:
                                vs: 'MultiValues' = live_defs.stack.load(stack_addr, size=d.atom.size,
                                                                                 endness=d.atom.endness)
                            except SimMemoryMissingError:
                                vs = None
                        elif isinstance(d.atom, atoms.MemoryLocation) and \
                            isinstance(node.irsb.statements[d.codeloc.stmt_idx], pyvex.stmt.Store) and \
                            isinstance(node.irsb.statements[d.codeloc.stmt_idx].addr, pyvex.expr.Const):
                            try:
                                vs: 'MultiValues' = live_defs.memory.load(d.atom.addr, size=d.atom.size,
                                                                                 endness=d.atom.endness)
                            except SimMemoryMissingError:
                                vs = None
                        else:
                            continue

                        if vs is not None:
                            for values in vs.values():
                                for value in values:
                                    defs_.update(live_defs.extract_defs(value))
                        else:
                            continue


                        if d not in defs_:
                            # additonal aliasing check for mem locs with const addr
                            if isinstance(d.atom, atoms.MemoryLocation) and not isinstance(d.atom.addr,
                                                                                           SpOffset):
                                possible_alias = False
                                #check if there is a symbolic load between the two defs, if so then do not eliminate the def
                                for n_def in defs_:
                                    assert d.codeloc.stmt_idx < n_def.codeloc.stmt_idx
                                    for i in range(d.codeloc.stmt_idx, n_def.codeloc.stmt_idx):
                                        if isinstance(node.irsb.statements[i], pyvex.stmt.WrTmp) and isinstance(node.irsb.statements[i].data, pyvex.expr.Load):
                                            if not isinstance(node.irsb.statements[i].data.addr, pyvex.IRExpr.Const):
                                                possible_alias = True
                                                break
                                if not possible_alias:
                                    dead_defs_stmt_idx[d.codeloc.stmt_idx] += 1
                            else:
                                dead_defs_stmt_idx[d.codeloc.stmt_idx] += 1

            new_statements = []
            # Remove dead assignments
            for idx, stmt in enumerate(cur_block.vex.statements):
                if isinstance(stmt, pyvex.stmt.WrTmp):
                    # this does not affect CAS
                    if stmt.tmp not in used_tmp_indices:
                        continue

                # special check for CAS stmt to make sure both defs are daed beore removing
                if isinstance(stmt, pyvex.stmt.CAS):
                    if dead_defs_stmt_idx[idx] >= 2:
                        continue
                    else:
                        new_statements.append(stmt)
                        continue

                # is it a dead virgin?
                if idx in dead_defs_stmt_idx:
                    continue

                if isinstance(stmt, pyvex.stmt.IMark) and idx == len(cur_block.vex.statements) - 1:
                    continue
                elif isinstance(stmt, pyvex.stmt.AbiHint) and idx == len(cur_block.vex.statements) - 1:
                    continue
                elif isinstance(stmt, pyvex.stmt.IMark) and isinstance(cur_block.vex.statements[idx + 1], pyvex.stmt.IMark):
                    continue
                elif isinstance(stmt, pyvex.stmt.IMark) and isinstance(cur_block.vex.statements[idx + 1], pyvex.stmt.AbiHint):
                    continue
                elif isinstance(stmt, pyvex.stmt.Exit) and type(stmt.guard) == pyvex.expr.Const:
                    # Removing conditional statements that depend on a constant
                    if stmt.guard.con.value == 0:
                        edge_to_remove_node = None
                        # Remove the edge that is no longer required
                        succs = list(dsa_new_model.graph.successors(node))
                        if len(succs) == 2:
                            for succ in succs:
                                if succ.addr == stmt.dst.value and stmt.dst.block_id == succ.block_id:
                                    edge_to_remove_node = succ
                            if not edge_to_remove_node:
                                # this is probably some sort of vex error checking, to go back to the beginning of the inst
                                # we remove it
                                for succ in succs:
                                    #double check
                                    if succ.addr == stmt.dst.value:
                                        import ipdb;ipdb.set_trace()
                                continue

                            dsa_new_model.graph.remove_edge(node, edge_to_remove_node)
                            self._note_change()
                            nodes_to_remove = nodes_to_remove.union(remove_path(dsa_new_model, start_node))
                        continue
                    elif stmt.guard.con.value == 1:
                        # Remove the edge that is no longer required
                        succs = list(dsa_new_model.graph.successors(node))
                        if len(succs) == 2:
                            for succ in succs:
                                if succ.addr == node.irsb.next.con.value and node.irsb.next.con.block_id == succ.block_id:
                                    edge_to_remove_node = succ
                            dsa_new_model.graph.remove_edge(node, edge_to_remove_node)
                            self._note_change()
                            nodes_to_remove = nodes_to_remove.union(remove_path(dsa_new_model, start_node))
                        # else:
                        #     print("Hmmmmm")
                        #     import ipdb;ipdb.set_trace()
                        node.irsb.next = pyvex.expr.Const(stmt.dst)
                        continue
                new_statements.append(stmt)

            # Dealing with empty blocks i.e. removing them
            if len(new_statements) == 0:
                if len(list(dsa_new_model.graph.successors(node))) >0:
                    succ = dsa_new_model.graph.successors(node)
                    succ = next(succ)
                    preds = dsa_new_model.graph.predecessors(node)
                    to_remove = False
                    for pred in preds:
                        succ_of_pred = list(dsa_new_model.graph.successors(pred))

                        if len(succ_of_pred) == 1:
                            pred_edge_data = dsa_new_model.graph.get_edge_data(pred, node)
                            # Reassigning the next expression of the previous
                            if not pred.is_simprocedure:
                                dsa_new_model.graph.add_edge(pred, succ, jumpkind=pred_edge_data['jumpkind'])
                                if len(pred.irsb.statements) > 0 and isinstance(pred.irsb.statements[-1], pyvex.stmt.Exit):
                                    if pred.irsb.statements[-1].dst.block_id == node.block_id:
                                        pred.irsb.statements[-1].dst = node.irsb.next.con
                                    else:
                                        pred.irsb.next = node.irsb.next
                                    if pred.irsb.next.con.block_id == pred.irsb.statements[-1].dst.block_id and pred.irsb.statements[-1].dst.value == pred.irsb.next.con.value:
                                        # remove the redundant if cond, if both targets become same
                                        pred.irsb.statements = pred.irsb.statements[:-1]
                                else:
                                    pred.irsb.next = node.irsb.next
                                to_remove = True
                            else:
                                print("Not removing this block, since there the previous block is a Sim Procedure")
                    if to_remove:
                        dsa_new_model.graph.remove_node(node)
                        self._note_change()
                else:
                    dsa_new_model.graph.remove_node(node)
                    self._note_change()
            else:
                if new_statements != node.irsb.statements:
                    self._note_change(node)
                node.irsb = pyvex.IRSB.empty_block(node.irsb.arch,
                                                   node.irsb.addr,
                                                   statements=new_statements,
                                                   tyenv=node.irsb.tyenv,
                                                   nxt=node.irsb.next,
                                                   direct_next=node.irsb.direct_next,
                                                   jumpkind=node.irsb.jumpkind,
                                                   size=node.irsb.size)

            self._mark_node_clean("_eliminate_dead_assignments", node, _clean_epoch, _clean_counter)

        if nodes_to_remove:
            self._note_change()
        dsa_new_model.graph.remove_nodes_from(nodes_to_remove)
        # Returning a new CFGVMDeobfuscation object with the updated graph
        # if start_state:
        #     initial_input_state = start_state
        # else:
        #     initial_input_state = proj.factory.blank_state(addr=self.start_addr,
        #                                                    mode='fastpath',
        #                                                    add_options=angr.sim_options.refs | {
        #                                                        angr.sim_options.REPLACEMENT_SOLVER,
        #                                                        angr.sim_options.DO_CCALLS})
        # dsa_new_model._nodes_by_addr[self.start_addr][0].input_state = initial_input_state
        # new_cfg = proj.analyses.CFGVMDeobfuscation(model=dsa_new_model, keep_state=True, iropt_level=1,
        #                                            resolve_indirect_jumps=True, max_iterations=1,
        #                                            vm_vpc_addr=self.vm_vpc_addr)
        # return new_cfg


        return dsa_new_model
    def find_index_of_IMark(self, imark_addr, statements, stmt_idx):
        imark_ind = None
        min_gap = len(statements)+1
        for ind, cur_stmt in enumerate(statements):
            if isinstance(cur_stmt, pyvex.stmt.IMark) and cur_stmt.addr == imark_addr:
                if 0 < stmt_idx - ind < min_gap:
                    imark_ind = ind
        return imark_ind

    @logtime
    @skip_if_unchanged
    def block_arithmetic_simplifications_using_dep_graph(self, cfg, proj):
        print("Block arithmetic simplification using dep graph")
        def check_stmt_add_sub(stmt):
            if isinstance(stmt, pyvex.stmt.WrTmp) and isinstance(stmt.data, pyvex.expr.Binop):
                add_sub_prefix = ("Iop_Add32", "Iop_Sub32", "Iop_Sub64", "Iop_Add64")
                if stmt.data.op.startswith(add_sub_prefix):
                    return True
            return False

        def get_single_pred_stmt(tmp_idx, statements):
            cur_stmt_defs = dep_graph.find_definitions(tmp_idx=tmp_idx)
            assert len(cur_stmt_defs) == 1
            pred_defs = list(dep_graph.predecessors(cur_stmt_defs[0]))
            no_pred_defs = 0
            pred_def_to_return = None
            for pred_def in pred_defs:
                if isinstance(pred_def.atom, atoms.Tmp):
                    no_pred_defs +=1
                    pred_def_to_return = pred_def

            if no_pred_defs != 1:
                return False, None, None
            return True, statements[pred_def_to_return.codeloc.stmt_idx], pred_def_to_return.codeloc.stmt_idx

        def one_const(stmt):
            #t465 = Add32(t667,t667)
            # check for the above fails in onle_one_pred
            for arg in stmt.data.args:
                if isinstance(arg, pyvex.expr.Const):
                    return True
            return False

        def get_constant_value_and_class(expr):
            consts = []
            for arg in expr.args:
                if isinstance(arg, pyvex.expr.Const):
                    consts.append(arg)
            assert len(consts) == 1
            return consts[0].con.__class__, consts[0].con.value


        for node in list(cfg.nodes()):
            if node.is_simprocedure:
                continue

            if self._node_is_clean("block_arithmetic_simplifications_using_dep_graph", node):
                continue
            _clean_epoch, _clean_counter = self._coarse_epoch, self._change_counter

            cur_block = angr.Block(node.irsb.addr, project=proj, vex=node.irsb)
            result = proj.analyses.ReachingDefinitions(cur_block, track_tmps=True, track_consts=False,
                                                       observation_points=[('node', node.addr, OP_AFTER)],
                                                       dep_graph=True)
            dep_graph = result.dep_graph
            new_stmts = []
            changed_stmt_idx = []
            for stmt_idx, stmt in enumerate(node.irsb.statements):
                new_stmt = stmt
                if check_stmt_add_sub(stmt):

                    if isinstance(stmt.data.args[0], pyvex.expr.Const) and isinstance(stmt.data.args[1], pyvex.expr.Const):
                        # this was skipped by constant prop because it's outside the VM area so we skip it
                        new_stmts.append(new_stmt)
                        continue

                    only_one_pred, pred_stmt, pred_stmt_idx = get_single_pred_stmt(stmt.tmp, node.irsb.statements)

                    if only_one_pred and check_stmt_add_sub(pred_stmt) and one_const(stmt):
                        #add sub simplifications, where atleast one argument is constant for both
                        only_one_pred, _, _ = get_single_pred_stmt(pred_stmt.tmp, node.irsb.statements)

                        if not only_one_pred or not one_const(pred_stmt):
                            # make sure the pred_stmt has only one arg as tmp
                            # it could have one predecessor but used twice e.g. t465 = Add32(t667,t667) so check for const alllso
                            new_stmts.append(new_stmt)
                            continue

                        if pred_stmt_idx in changed_stmt_idx:
                            # if the pred_stmt has been modified already then skip
                            new_stmts.append(new_stmt)
                            continue

                        if stmt.data.op == pred_stmt.data.op:
                            # make sure one of the args is constant
                            # make sure that both the constnts are the second args if Sub
                            # t1=add324(t2,4)
                            # t3=sub324(t1,4)
                            # both the operations are the same
                            if stmt.data.op.startswith('Iop_Sub'):
                                #make sure that both the constnts are the second args if Sub
                                if not (isinstance(stmt.data.args[1], pyvex.expr.Const) and isinstance(pred_stmt.data.args[1], pyvex.expr.Const)):
                                    new_stmts.append(new_stmt)
                                    continue

                            # this works for both Sub and Add
                            const_class, const_0 = get_constant_value_and_class(stmt.data)
                            _, const_1 = get_constant_value_and_class(pred_stmt.data)
                            for arg in pred_stmt.data.args:
                                if isinstance(arg, pyvex.expr.RdTmp):
                                    pred_data_tmp_idx = arg.tmp
                            new_stmt = pyvex.stmt.WrTmp(stmt.tmp, pyvex.expr.Binop(stmt.data.op,
                                                                            [pyvex.expr.RdTmp(pred_data_tmp_idx),
                                                                             pyvex.expr.Const(const_class(((const_0+const_1)&(1<<self.project.arch.bits)-1)))]))
                            changed_stmt_idx.append(stmt_idx)

                        else:
                            #both the operations are different, and const in the second arg for both
                            #t14 = Add32(t11, 0xfffffff8)
                            #t10 = Sub32(t11, 0x00000004)

                             #make sure that both the second args are consts
                            if not (isinstance(stmt.data.args[1], pyvex.expr.Const) and isinstance(pred_stmt.data.args[1], pyvex.expr.Const)):
                                new_stmts.append(new_stmt)
                                continue

                            const_class = stmt.data.args[1].con.__class__

                            if stmt.data.op.startswith("Iop_Sub"):
                                const_0 = -stmt.data.args[1].con.value
                            else:
                                const_0 = stmt.data.args[1].con.value

                            if pred_stmt.data.op.startswith("Iop_Sub"):
                                const_1 = -pred_stmt.data.args[1].con.value
                            else:
                                const_1 = pred_stmt.data.args[1].con.value

                            new_stmt = pyvex.stmt.WrTmp(stmt.tmp, pyvex.expr.Binop("Iop_Add" + stmt.data.op[-2:],
                                                                           [pyvex.expr.RdTmp(pred_stmt.data.args[0].tmp),
                                                                            pyvex.expr.Const(const_class(((const_0 + const_1) & (1 << self.project.arch.bits) - 1)))]))
                            changed_stmt_idx.append(stmt_idx)


                    elif not only_one_pred:
                        # t1492 = Sub32(t1491, t1458)
                        # t1493 = Add32(t1492, t1458)
                        # For Themida

                        cur_stmt_tmp_arg1 = stmt.data.args[0].tmp
                        cur_stmt_tmp_arg2 = stmt.data.args[1].tmp

                        pred_stmt_idx = dep_graph.find_definitions(tmp_idx=cur_stmt_tmp_arg1)[0].codeloc.stmt_idx
                        pred_stmt = node.irsb.statements[pred_stmt_idx]


                        if pred_stmt_idx in changed_stmt_idx:
                            # if the pred_stmt has been modified already then skip
                            new_stmts.append(new_stmt)
                            continue

                        #make sure both the pred args are tmps
                        if check_stmt_add_sub(pred_stmt) and isinstance(pred_stmt.data.args[0], pyvex.expr.RdTmp) and \
                                isinstance(pred_stmt.data.args[1], pyvex.expr.RdTmp):
                            pred_stmt_tmp_arg1 = pred_stmt.data.args[0].tmp
                            pred_stmt_tmp_arg2 = pred_stmt.data.args[1].tmp

                            # check if the second tmp arg is same for both and the operations or opposites i.e add/sub
                            if cur_stmt_tmp_arg2 == pred_stmt_tmp_arg2 and stmt.data.op != pred_stmt.data.op:
                                new_stmt = pyvex.stmt.WrTmp(stmt.tmp, pyvex.expr.RdTmp(pred_stmt_tmp_arg1))
                                changed_stmt_idx.append(stmt_idx)

                        elif check_stmt_add_sub(pred_stmt) and isinstance(pred_stmt.data.args[0], pyvex.expr.Const) and \
                                isinstance(pred_stmt.data.args[1], pyvex.expr.RdTmp):
                            # t1143 = Sub32(0xfffff7fc,t1089)
                            # t34 = Add32(t1143,t1089)

                            pred_stmt_tmp_arg2 = pred_stmt.data.args[1].tmp
                            # check if the second tmp arg is same for both and the operations or opposites i.e add/sub
                            if cur_stmt_tmp_arg2 == pred_stmt_tmp_arg2 and stmt.data.op != pred_stmt.data.op:
                                new_stmt = pyvex.stmt.WrTmp(stmt.tmp, pyvex.expr.Const(pred_stmt.data.args[0]).con)
                                changed_stmt_idx.append(stmt_idx)
                        else:
                            # t76 = Add32(t855,0xfe604eee)
                            # t1209 = Add32(t855, 0x208780e0)
                            # t247 = Sub32(t1209, t76)
                            cur_stmt_tmp_arg1 = stmt.data.args[0].tmp
                            cur_stmt_tmp_arg2 = stmt.data.args[1].tmp

                            pred_stmt_idx_1 = dep_graph.find_definitions(tmp_idx=cur_stmt_tmp_arg1)[0].codeloc.stmt_idx
                            pred_stmt_1 = node.irsb.statements[pred_stmt_idx_1]

                            pred_stmt_idx_2 = dep_graph.find_definitions(tmp_idx=cur_stmt_tmp_arg2)[0].codeloc.stmt_idx
                            pred_stmt_2 = node.irsb.statements[pred_stmt_idx_2]

                            if (pred_stmt_idx_1 in changed_stmt_idx) or  (pred_stmt_idx_2 in changed_stmt_idx):
                                # if the pred_stmt has been modified already then skip
                                new_stmts.append(new_stmt)
                                continue

                            if check_stmt_add_sub(pred_stmt_1) and check_stmt_add_sub(pred_stmt_2) and \
                                    stmt.data.op.startswith("Iop_Sub") and \
                                    pred_stmt_1.data.op.startswith("Iop_Add") and \
                                    pred_stmt_2.data.op.startswith("Iop_Add") and \
                                    isinstance(pred_stmt_1.data.args[1], pyvex.expr.Const) and \
                                    isinstance(pred_stmt_2.data.args[1], pyvex.expr.Const) and \
                                    isinstance(pred_stmt_1.data.args[0], pyvex.expr.RdTmp) and \
                                    isinstance(pred_stmt_2.data.args[0], pyvex.expr.RdTmp) and \
                                pred_stmt_1.data.args[0].tmp == pred_stmt_2.data.args[0].tmp:
                                const_class = pred_stmt_1.data.args[1].con.__class__
                                new_stmt = pyvex.stmt.WrTmp(stmt.tmp, pyvex.expr.Const(const_class(((pred_stmt_1.data.args[1].con.value - pred_stmt_2.data.args[1].con.value) & (1 << self.project.arch.bits) - 1))))
                                changed_stmt_idx.append(stmt_idx)



                elif isinstance(stmt, pyvex.stmt.WrTmp) and isinstance(stmt.data, pyvex.expr.Binop) and stmt.data.op.startswith("Iop_Xor"):
                    # XOR simplification
                    # t154 = Xor32(t151,t26)
                    # t158 = Xor32(t26,t154)
                    cur_stmt_defs = dep_graph.find_definitions(tmp_idx=stmt.tmp)
                    assert len(cur_stmt_defs) == 1
                    pred_defs = list(dep_graph.predecessors(cur_stmt_defs[0]))
                    if len(pred_defs) == 1:
                        # at least one arg is constant
                        # t154 = Xor32(t151, 3)
                        # t158 = Xor32(3 ,t154)
                        pred_def = pred_defs[0]
                        pred_stmt = node.irsb.statements[pred_def.codeloc.stmt_idx]

                        if pred_def.codeloc.stmt_idx in changed_stmt_idx:
                            # if the pred_stmt has been modified already then skip
                            new_stmts.append(new_stmt)
                            continue

                        cur_stmt_const_arg = None
                        for arg in stmt.data.args:
                            if isinstance(arg, pyvex.expr.Const):
                                cur_stmt_const_arg = arg.con.value

                        if cur_stmt_const_arg and isinstance(pred_stmt, pyvex.stmt.WrTmp) and isinstance(pred_stmt.data, pyvex.expr.Binop) and \
                            pred_stmt.data.op.startswith(stmt.data.op):
                            #check if the pred stmt is also XOR

                            pred_stmt_const_arg = None
                            pred_stmt_tmp_arg = None
                            for arg in pred_stmt.data.args:
                                if isinstance(arg, pyvex.expr.Const):
                                    pred_stmt_const_arg = arg.con.value
                                    const_class = arg.con.__class__
                                elif isinstance(arg, pyvex.expr.RdTmp):
                                    pred_stmt_tmp_arg = arg.tmp

                            if pred_stmt_const_arg and pred_stmt_tmp_arg:
                                #make sure one arg is tmp and one is constant
                                if pred_stmt_const_arg == cur_stmt_const_arg:
                                    new_stmt = pyvex.stmt.WrTmp(stmt.tmp, pyvex.expr.RdTmp(pred_stmt_tmp_arg))
                                    changed_stmt_idx.append(stmt_idx)
                                else:
                                    new_stmt = pyvex.stmt.WrTmp(stmt.tmp,
                                                                pyvex.expr.Binop(stmt.data.op,
                                                                                 [pyvex.expr.RdTmp(
                                                                                     pred_stmt_tmp_arg),
                                                                                  pyvex.expr.Const(
                                                                                      const_class(pred_stmt_const_arg ^ cur_stmt_const_arg))]))
                                    changed_stmt_idx.append(stmt_idx)
                        elif isinstance(stmt.data.args[0], pyvex.expr.RdTmp) and isinstance(stmt.data.args[1], pyvex.expr.RdTmp) and stmt.data.args[0].tmp == stmt.data.args[1].tmp:
                            # t89 = Xor32(t355,t355)
                            const_class = pyvex.const.ty_to_const_class(node.irsb.tyenv.lookup(stmt.tmp))
                            new_stmt = pyvex.stmt.WrTmp(stmt.tmp, pyvex.expr.Const(const_class(0)))
                            changed_stmt_idx.append(stmt_idx)

                    elif len(pred_defs) == 2:
                        # both args are temps
                        # t154 = Xor32(t151,t26)
                        # t158 = Xor32(t26,t154)
                        pred_def_1 = pred_defs[0]
                        pred_def_2 = pred_defs[1]

                        pred_stmt_1_idx = pred_def_1.codeloc.stmt_idx
                        pred_stmt_2_idx = pred_def_2.codeloc.stmt_idx

                        pred_stmt_1 = node.irsb.statements[pred_stmt_1_idx]
                        pred_stmt_2 = node.irsb.statements[pred_stmt_2_idx]


                        if pred_stmt_1_idx in changed_stmt_idx or pred_stmt_2_idx in changed_stmt_idx:
                            # if the pred_stmt has been modified already then skip
                            new_stmts.append(new_stmt)
                            continue


                        if isinstance(pred_stmt_1, pyvex.stmt.WrTmp) and isinstance(pred_stmt_1.data, pyvex.expr.Binop) and \
                            pred_stmt_1.data.op.startswith(stmt.data.op):
                            #make sure its a XOR
                            if isinstance(pred_stmt_1.data.args[0], pyvex.expr.RdTmp) and \
                                    isinstance(pred_stmt_1.data.args[1], pyvex.expr.RdTmp):
                                #make sure both the args are tmps as well
                                if pred_stmt_2.tmp == pred_stmt_1.data.args[0].tmp:
                                    new_stmt = pyvex.stmt.WrTmp(stmt.tmp, pyvex.expr.RdTmp(pred_stmt_1.data.args[1].tmp))
                                    changed_stmt_idx.append(stmt_idx)
                                elif pred_stmt_2.tmp == pred_stmt_1.data.args[1].tmp:
                                    new_stmt = pyvex.stmt.WrTmp(stmt.tmp, pyvex.expr.RdTmp(pred_stmt_1.data.args[0].tmp))
                                    changed_stmt_idx.append(stmt_idx)
                            elif isinstance(pred_stmt_1.data.args[0], pyvex.expr.RdTmp) and \
                                    isinstance(pred_stmt_1.data.args[1], pyvex.expr.Const):
                                #onc is constant and other is tmp
                                if pred_stmt_2.tmp == pred_stmt_1.data.args[0].tmp:
                                    new_stmt = pyvex.stmt.WrTmp(stmt.tmp, pyvex.expr.Const(pred_stmt_1.data.args[1]).con)
                                    changed_stmt_idx.append(stmt_idx)
                            elif isinstance(pred_stmt_1.data.args[0], pyvex.expr.Const) and \
                                 isinstance(pred_stmt_1.data.args[1], pyvex.expr.RdTmp):
                                #onc is constant and other is tmp
                                if pred_stmt_2.tmp == pred_stmt_1.data.args[1].tmp:
                                    new_stmt = pyvex.stmt.WrTmp(stmt.tmp, pyvex.expr.Const(pred_stmt_1.data.args[0]).con)
                                    changed_stmt_idx.append(stmt_idx)

                        if stmt_idx not in changed_stmt_idx and isinstance(pred_stmt_2, pyvex.stmt.WrTmp) and isinstance(pred_stmt_2.data, pyvex.expr.Binop) and \
                            pred_stmt_2.data.op.startswith(stmt.data.op):
                            #make sure its a XOR
                            if isinstance(pred_stmt_2.data.args[0], pyvex.expr.RdTmp) and \
                                    isinstance(pred_stmt_2.data.args[1], pyvex.expr.RdTmp):
                                #make sure both the args are tmps as well
                                if pred_stmt_1.tmp == pred_stmt_2.data.args[0].tmp:
                                    new_stmt = pyvex.stmt.WrTmp(stmt.tmp, pyvex.expr.RdTmp(pred_stmt_2.data.args[1].tmp))
                                    changed_stmt_idx.append(stmt_idx)
                                elif pred_stmt_1.tmp == pred_stmt_2.data.args[1].tmp:
                                    new_stmt = pyvex.stmt.WrTmp(stmt.tmp, pyvex.expr.RdTmp(pred_stmt_2.data.args[0].tmp))
                                    changed_stmt_idx.append(stmt_idx)

                            elif isinstance(pred_stmt_2.data.args[0], pyvex.expr.RdTmp) and \
                                    isinstance(pred_stmt_2.data.args[1], pyvex.expr.Const):
                                #onc is constant and other is tmp
                                if pred_stmt_1.tmp == pred_stmt_2.data.args[0].tmp:
                                    new_stmt = pyvex.stmt.WrTmp(stmt.tmp, pyvex.expr.Const(pred_stmt_2.data.args[1]).con)
                                    changed_stmt_idx.append(stmt_idx)

                            elif isinstance(pred_stmt_2.data.args[0], pyvex.expr.Const) and \
                                 isinstance(pred_stmt_2.data.args[1], pyvex.expr.RdTmp):
                                #onc is constant and other is tmp
                                if pred_stmt_1.tmp == pred_stmt_2.data.args[1].tmp:
                                    new_stmt = pyvex.stmt.WrTmp(stmt.tmp, pyvex.expr.Const(pred_stmt_2.data.args[0]).con)
                                    changed_stmt_idx.append(stmt_idx)

                        if stmt_idx not in changed_stmt_idx:
                            if isinstance(pred_stmt_1, pyvex.stmt.WrTmp) and isinstance(pred_stmt_1.data,
                                                                                        pyvex.expr.Binop) and \
                                    pred_stmt_1.data.op.startswith(stmt.data.op) and isinstance(pred_stmt_2,
                                                                                                pyvex.stmt.WrTmp) and \
                                    isinstance(pred_stmt_2.data, pyvex.expr.Binop) and pred_stmt_2.data.op.startswith(
                                stmt.data.op) and \
                                    isinstance(pred_stmt_1.data.args[0], pyvex.expr.RdTmp) and isinstance(
                                pred_stmt_2.data.args[0], pyvex.expr.RdTmp) and \
                                    pred_stmt_1.data.args[0].tmp == pred_stmt_2.data.args[0].tmp and isinstance(
                                pred_stmt_1.data.args[1], pyvex.expr.Const) and \
                                    isinstance(pred_stmt_2.data.args[1], pyvex.expr.Const):
                                # t445 = Xor32(t423,0x00cb8c6a)
                                # t447 = Xor32(t423,0x00cb8c03)
                                # t1105 = Xor32(t447,t445)
                                const_class = pred_stmt_1.data.args[1].con.__class__
                                new_const = pred_stmt_2.data.args[1].con.value ^ pred_stmt_1.data.args[1].con.value
                                new_stmt = pyvex.stmt.WrTmp(stmt.tmp, pyvex.expr.Const(const_class(new_const)))
                                changed_stmt_idx.append(stmt_idx)


                    if stmt_idx not in changed_stmt_idx:
                        if isinstance(stmt.data.args[1], pyvex.expr.Const) and stmt.data.args[1].con.value == 0:
                            #t135 = Xor8(t138, 0x00)
                            new_stmt = pyvex.stmt.WrTmp(stmt.tmp, pyvex.expr.RdTmp(stmt.data.args[0].tmp))
                            changed_stmt_idx.append(stmt_idx)
                        elif isinstance(stmt.data.args[0], pyvex.expr.Const) and stmt.data.args[0].con.value == 0:
                            #t135 = Xor8(0x00, t138)
                            new_stmt = pyvex.stmt.WrTmp(stmt.tmp, pyvex.expr.RdTmp(stmt.data.args[1].tmp))
                            changed_stmt_idx.append(stmt_idx)


                # elif isinstance(stmt, pyvex.stmt.WrTmp) and isinstance(stmt.data, pyvex.expr.Binop) and stmt.data.op.startswith("Iop_Or"):
                #     cur_stmt_defs = dep_graph.find_definitions(tmp_idx=stmt.tmp)
                #     assert len(cur_stmt_defs) == 1
                #     pred_defs = list(dep_graph.predecessors(cur_stmt_defs[0]))
                #     if len(pred_defs) == 2:
                #         # t518 = Not32(t147)
                #         # ------ IMark(0x454b26, 2, 0) ------
                #         # t528 = Not32(t147)
                #         # ------ IMark(0x454b2d, 2, 0) ------
                #         # t33 = Or32(t518,t528)
                #         #
                #         pred_def_1 = pred_defs[0]
                #         pred_def_2 = pred_defs[1]
                #
                #         pred_stmt_1_idx = pred_def_1.codeloc.stmt_idx
                #         pred_stmt_2_idx = pred_def_2.codeloc.stmt_idx
                #
                #         pred_stmt_1 = node.irsb.statements[pred_stmt_1_idx]
                #         pred_stmt_2 = node.irsb.statements[pred_stmt_2_idx]
                #
                #
                #         if pred_stmt_1_idx in changed_stmt_idx or pred_stmt_2_idx in changed_stmt_idx:
                #             # if the pred_stmt has been modified already then skip
                #             new_stmts.append(new_stmt)
                #             continue
                #
                #         if isinstance(pred_stmt_2, pyvex.stmt.WrTmp) and isinstance(pred_stmt_1, pyvex.stmt.WrTmp) and \
                #             pred_stmt_2.data == pred_stmt_1.data:
                #             new_stmt = pyvex.stmt.WrTmp(stmt.tmp, pyvex.expr.RdTmp(stmt.data.args[1].tmp))
                #             changed_stmt_idx.append(stmt_idx)
                #
                #     elif isinstance(stmt.data.args[0], pyvex.expr.RdTmp) and isinstance(stmt.data.args[1], pyvex.expr.RdTmp) and \
                #             stmt.data.args[0] == stmt.data.args[1]:
                #         # t33 = Or32(t518,t518)
                #         new_stmt = pyvex.stmt.WrTmp(stmt.tmp, pyvex.expr.RdTmp(stmt.data.args[1].tmp))
                #         changed_stmt_idx.append(stmt_idx)
                #     elif isinstance(stmt.data.args[1], pyvex.expr.Const) and stmt.data.args[1].con.value == 0:
                #         #t135 = Or8(t138, 0x00)
                #         new_stmt = pyvex.stmt.WrTmp(stmt.tmp, pyvex.expr.RdTmp(stmt.data.args[0].tmp))
                #         changed_stmt_idx.append(stmt_idx)
                # elif isinstance(stmt, pyvex.stmt.WrTmp) and isinstance(stmt.data, pyvex.expr.Binop) and stmt.data.op.startswith("Iop_Shl"):
                #     if isinstance(stmt.data.args[1], pyvex.expr.Const) and stmt.data.args[1].con.value == 0:
                #         # t160 = Shl32(t161,0x00)
                #         new_stmt = pyvex.stmt.WrTmp(stmt.tmp, pyvex.expr.RdTmp(stmt.data.args[0].tmp))
                #         changed_stmt_idx.append(stmt_idx)

                new_stmts.append(new_stmt)

            if changed_stmt_idx:
                self._note_change(node)

            node.irsb = pyvex.IRSB.empty_block(node.irsb.arch,
                                               node.irsb.addr,
                                               statements=new_stmts,
                                               tyenv=node.irsb.tyenv,
                                               nxt=node.irsb.next,
                                               direct_next=node.irsb.direct_next,
                                               jumpkind=node.irsb.jumpkind,
                                               size=node.irsb.size)

            self._mark_node_clean("block_arithmetic_simplifications_using_dep_graph", node, _clean_epoch, _clean_counter)

        return cfg


    def block_arithmetic_simplifications(self, cfg, proj, start_state=None):
        # Naming this this CFGEmulated so that certain other analysis can uses the results from this
        print("Block arithmetic simplification")
        #new_model = self.new_model_graph(cfg.graph, proj, 'CFGEmulated')
        new_model = cfg
        for node in list(new_model.nodes()):
            if not node.is_simprocedure:
                cur_block = angr.Block(node.irsb.addr, project=proj, vex=node.irsb)
                result = proj.analyses.ReachingDefinitions(cur_block, track_tmps=True, track_consts=False, observation_points=[('node', node.addr, OP_AFTER)], dep_graph=DepGraph())
                import ipdb;ipdb.set_trace()
                ## create stmt dependency graph
                stmt_graph = StatementGraph()
                cur_ins_addr = None
                cur_ins_ind = None
                for ind, stmt in enumerate(node.irsb.statements):
                    if isinstance(stmt, pyvex.stmt.IMark):
                        cur_ins_addr = stmt.addr
                        cur_ins_ind = ind
                        continue
                    # if cur_ins_addr == 0x6f98b3:
                    #     import ipdb;ipdb.set_trace()

                    code_loc = CodeLocation(node.addr, ind, ins_addr=cur_ins_addr)
                    ins_ind_sens_code_loc = IndSensitiveCodeLocation(node.addr, ind, ins_addr=cur_ins_addr, ins_ind=cur_ins_ind)

                    if code_loc in result.all_uses_by_code_loc:
                        # if code_loc.ins_addr == 0x1400ab26d and code_loc.stmt_idx == 44:
                        #     import ipdb;ipdb.set_trace()
                        for use in result.all_uses_by_code_loc[code_loc]:
                            if isinstance(use.codeloc, ExternalCodeLocation):
                                use_node = StatementNode(None, use.codeloc, def_atom=use.atom)
                            else:
                                use_stmt = node.irsb.statements[use.codeloc.stmt_idx]
                                tmp_atom = self.convert_to_atom(use_stmt, node.irsb.tyenv, node.irsb.arch.byte_width)
                                imark_ins_ind = self.find_index_of_IMark(use.codeloc.ins_addr, node.irsb.statements,
                                                                         use.codeloc.stmt_idx)
                                new_ins_ind_sens_codeloc = IndSensitiveCodeLocation(use.codeloc.block_addr,
                                                                                    use.codeloc.stmt_idx,
                                                                                    ins_addr=use.codeloc.ins_addr,
                                                                                    ins_ind=imark_ins_ind)
                                use_node = StatementNode(use_stmt, new_ins_ind_sens_codeloc, def_atom=tmp_atom)
                                # if node.addr == 0x1400ab221 and isinstance(use_node.stmt, pyvex.stmt.Put) and isinstance(use_node.stmt.data, pyvex.expr.RdTmp) and use_node.stmt.data.tmp == 198:
                                #     print(use_node)
                                #     import ipdb;
                                #     ipdb.set_trace()
                            stmt_atom = self.convert_to_atom(stmt, node.irsb.tyenv, node.irsb.arch.byte_width)
                            stmt_node = StatementNode(stmt, ins_ind_sens_code_loc, def_atom=stmt_atom)
                            # if node.addr == 0x1400ab221 and isinstance(stmt_node.stmt, pyvex.stmt.Put) and isinstance(stmt_node.stmt.data, pyvex.expr.RdTmp) and stmt_node.stmt.data.tmp == 198:
                            #     print(stmt_node)
                            #     import ipdb;
                            #     ipdb.set_trace()
                            stmt_graph.add_edge(stmt_node, use_node)
                    else:
                        ## These are leaf nodes or independent statements
                        stmt_atom = self.convert_to_atom(stmt, node.irsb.tyenv, node.irsb.arch.byte_width)
                        stmt_node = StatementNode(stmt, ins_ind_sens_code_loc, def_atom=stmt_atom)
                        stmt_graph.add_node(stmt_node)

                    # This is for symbolic store/loads
                    if code_loc in result.uses_of_store_def_dict:
                        for load_loc in result.uses_of_store_def_dict[code_loc]:
                            load_stmt = node.irsb.statements[load_loc.stmt_idx]
                            tmp_atom = self.convert_to_atom(load_stmt, node.irsb.tyenv, node.irsb.arch.byte_width)
                            if isinstance(load_loc, ExternalCodeLocation):
                                load_node = StatementNode(None, load_loc, def_atom=tmp_atom)
                            else:
                                imark_ins_ind = self.find_index_of_IMark(load_loc.ins_addr, node.irsb.statements,
                                                                         load_loc.stmt_idx)
                                new_ins_ind_sens_codeloc = IndSensitiveCodeLocation(load_loc.block_addr,
                                                                                    load_loc.stmt_idx,
                                                                                    ins_addr=load_loc.ins_addr,
                                                                                    ins_ind=imark_ins_ind)
                                load_node = StatementNode(load_stmt, new_ins_ind_sens_codeloc, def_atom=tmp_atom)
                            store_atom = self.convert_to_atom(stmt, node.irsb.tyenv, node.irsb.arch.byte_width)
                            store_node = StatementNode(stmt, ins_ind_sens_code_loc, def_atom=store_atom)
                            stmt_graph.add_edge(load_node, store_node)

                ## split the graph into connected components
                conn_comps = nx.weakly_connected_components(as_networkx(stmt_graph.graph))
                conn_comps = list(conn_comps)

                sub_graphs = []
                for comp in conn_comps:
                    comp_graph = StatementGraph(graph=copy.deepcopy(stmt_graph.graph.subgraph(comp)))
                    # for temp_node in stmt_graph.graph.subgraph(comp).nodes():
                    #     comp_graph.add_node(copy.deepcopy(temp_node))
                    # for edge in stmt_graph.graph.subgraph(comp).edges():
                    #     comp_graph.add_edge(edge[0], edge[1])
                    sub_graphs.append(comp_graph)

                ## perform arithmetic simplifications on each component individually
                simplified_statements = []
                inst_grouped_simp_stmts = OrderedDict()
                orig_stmt_idx_to_stmt_node = {}
                for sub_graph in sub_graphs:
                    to_simplify_sub_graph = nx.DiGraph(copy.deepcopy(sub_graph.graph))
                    stmt_node_queue = []
                    for stmt_node in to_simplify_sub_graph.nodes():
                        if to_simplify_sub_graph.out_degree(stmt_node) == 0:
                            stmt_node_queue.append(stmt_node)

                    visited_stmt_nodes = {}
                    simplified_statement_nodes = {}
                    simp_flag = 0
                    while len(stmt_node_queue) > 0:
                        cur_stmt_node = stmt_node_queue.pop(0)
                        if cur_stmt_node not in to_simplify_sub_graph.nodes():
                            continue
                        # if node.addr == 0x65eee1 and isinstance(cur_stmt_node.stmt, pyvex.stmt.Put) and isinstance(cur_stmt_node.stmt.data, pyvex.expr.RdTmp) and cur_stmt_node.stmt.data.tmp in [357]:
                        #     import ipdb;ipdb.set_trace()
                        # if node.addr == 0x65eee1 and isinstance(cur_stmt_node.stmt, pyvex.stmt.Store) and isinstance(cur_stmt_node.stmt.addr, pyvex.expr.RdTmp) and cur_stmt_node.stmt.addr.tmp == 334:
                        #     import ipdb;ipdb.set_trace()

                        succs = list(to_simplify_sub_graph.successors(cur_stmt_node))
                        skip = False

                        if cur_stmt_node in visited_stmt_nodes:
                            skip = True
                        for succ in succs:
                            if succ not in visited_stmt_nodes:
                                skip = True

                        if skip:
                            continue
                        visited_stmt_nodes[cur_stmt_node] = True

                        preds = list(to_simplify_sub_graph.predecessors(cur_stmt_node))
                        stmt_node_queue = preds + stmt_node_queue

                        # if node.addr == 0x65eee1:
                        #     print(cur_stmt_node.stmt)
                        #     print(stmt_node_queue)
                        #     print('\n')

                        if isinstance(cur_stmt_node.codeloc, ExternalCodeLocation):
                            continue
                        cur_stmt = cur_stmt_node.stmt
                        if isinstance(cur_stmt, pyvex.stmt.AbiHint) or isinstance(cur_stmt, pyvex.stmt.Exit):
                            continue

                        # using 32 bit registers in 64-bit
                        # x86
                        # add eax,const1         ==> add eax, const1+const2
                        # add eax, const2
                        # VEX
                        # t33 = GET:I64(rax)                                t33 = GET:I64(rax)
                        # t32 = 64to32(t33)                                 t37 = 64to32(t33)
                        # t0 = Add32(t32, 0x00000001)                       t3 = Add32(t37, 0x00000003)
                        # t36 = 32Uto64(t0)                 ==>
                        # t37 = 64to32(t36)
                        # t3 = Add32(t37, 0x00000002)

                        # successors = list(to_simplify_sub_graph.successors(cur_stmt_node))
                        # if isinstance(cur_stmt.data, pyvex.expr.Binop) and cur_stmt.data.op in ["Iop_Add32", "Iop_Sub32"] and len(successors) == 1:
                        #     for arg in cur_stmt.data.args:
                        #         if isinstance(arg, pyvex.expr.Const):
                        #             const_0 = arg.con.value
                        #     if cur_stmt.data.op in ["Iop_Add32", "Iop_Sub32"]:
                        #         const_0 = -const_0
                        #     successor = successors[0]
                        #     successors = list(to_simplify_sub_graph.successors(successor))
                        #     if isinstance(successor.stmt, pyvex.stmt.WrTmp) and isinstance(successor.stmt.data, pyvex.expr.Unop) and successor.stmt.data.op == "Iop_64to32":
                        #         successor = successors[0]
                        #         successors = list(to_simplify_sub_graph.successors(successor))
                        #         if isinstance(successor.stmt, pyvex.stmt.WrTmp) and isinstance(successor.stmt.data, pyvex.expr.Unop) and successor.stmt.data.op == "Iop_32Uto64":
                        #             successor = successors[0]
                        #             successors = list(to_simplify_sub_graph.successors(successor))
                        #             if isinstance(successor.stmt.data, pyvex.expr.Binop) and successor.stmt.data.op in ["Iop_Add32", "Iop_Sub32"] and len(successors) == 1:
                        #                 for arg in successor.stmt.data.args:
                        #                     if isinstance(arg, pyvex.expr.Const):
                        #                         const_1 = arg
                        #                 if successor.stmt.data.op in ["Iop_Add32", "Iop_Sub32"]:
                        #                     const_1 = -const_1
                        #                 successor = successors[0]
                        #                 successors = list(to_simplify_sub_graph.successors(successor))
                        #                 if isinstance(successor.stmt, pyvex.stmt.WrTmp) and isinstance(successor.stmt.data, pyvex.expr.Unop) and successor.stmt.data.op == "Iop_64to32":
                        #                     successor = successors[0]
                        #                     successors = list(to_simplify_sub_graph.successors(successor))
                        #                     if isinstance(successor.stmt, pyvex.stmt.WrTmp) and isinstance(successor.stmt.data, pyvex.expr.Get):
                        #                         simplified_statements[-5] = pyvex.stmt.WrTmp(simplified_statements[-2].tmp, simplified_statements[-5].data)
                        #                         simplified_statements[-1] = pyvex.stmt.WrTmp(cur_stmt.tmp, pyvex.expr.Binop(cur_stmt.data.op, [cur_stmt.data.args[0], pyvex.expr.Const(cur_stmt.data.args[1].__class__(const_0.con.value+const_1.con.value))]))
                        #                         simplified_statements.pop(-4)
                        #                         simplified_statements.pop(-3)
                        #                         simplified_statements.pop(-2)

                        # using the full size register for the respective binary i.e. rax or eax
                        # x86
                        # add eax,const1         ==> add eax, const1+const2
                        # add eax, const2
                        # VEX
                        # t2 = GET:I32(eax)                     t2 = GET:I32(eax)
                        # t0 = Add32(t2, 0x00000001)    ==>     t3 = Add32(t2, 0x00000003)
                        # t3 = Add32(t0, 0x00000002)
                        # THIS IS ONLY IF THE SECOND ARG IS CONSTANT
                        successors = list(to_simplify_sub_graph.successors(cur_stmt_node))
                        if hasattr(cur_stmt, 'data') and isinstance(cur_stmt.data, pyvex.expr.Binop) and cur_stmt.data.op in ["Iop_Add32", "Iop_Add64", "Iop_Sub32", "Iop_Sub64"] and len(successors) == 1:
                            # skip nodes that possible don't exist anymore since they have been simplified away
                            if cur_stmt_node in simplified_statement_nodes:
                                continue
                            if not(isinstance(cur_stmt.data.args[1], pyvex.expr.Const)):
                                continue
                            for arg in cur_stmt.data.args:
                                if isinstance(arg, pyvex.expr.Const):
                                    const_0 = arg.con.value
                                    cur_stmt_const_class = arg.con.__class__
                            if cur_stmt.data.op in ["Iop_Sub32", "Iop_Sub64"]:
                                const_0 = -const_0
                            successor = successors[0]
                            if isinstance(successor.codeloc, ExternalCodeLocation):
                                continue
                            pred_nodes_to_join = list(to_simplify_sub_graph.predecessors(cur_stmt_node))

                            successors = list(to_simplify_sub_graph.successors(successor))
                            predecessors = list(to_simplify_sub_graph.predecessors(successor))
                            if isinstance(successor.stmt.data, pyvex.expr.Binop) and successor.stmt.data.op in ["Iop_Add32", "Iop_Add64", "Iop_Sub32", "Iop_Sub64"] and len(successors) == 1 and len(predecessors) == 1:
                                # skip nodes that possible don't exist anymore since they have been simplified away
                                if successor in simplified_statement_nodes:
                                    continue
                                if not (isinstance(successor.stmt.data.args[1], pyvex.expr.Const)):
                                    continue
                                succ_nodes_to_join = successors # Since only one successor is there
                                simplified_statement_nodes[successor] = True
                                simplified_statement_nodes[cur_stmt_node] = True
                                for arg in successor.stmt.data.args:
                                    if isinstance(arg, pyvex.expr.Const):
                                        const_1 = arg.con.value
                                    if isinstance(arg, pyvex.expr.RdTmp):
                                        tmp_to_keep = arg.tmp

                                if successor.stmt.data.op in ["Iop_Sub32", "Iop_Sub64"]:
                                    const_1 = -const_1

                                #simplified_statements[-1] = pyvex.stmt.WrTmp(cur_stmt.tmp, pyvex.expr.Binop("Iop_Add"+cur_stmt.data.op[-2:], [pyvex.expr.RdTmp(tmp_to_keep), pyvex.expr.Const(cur_stmt.data.args[1].__class__(pyvex.expr.U64(const_0+const_1 if const_0 + const_1 >= 0 else (1<<64)+const_1+const_0)))]))
                                new_simpl_stmt = pyvex.stmt.WrTmp(cur_stmt.tmp, pyvex.expr.Binop("Iop_Add" + cur_stmt.data.op[-2:],
                                                                                [pyvex.expr.RdTmp(tmp_to_keep),
                                                                                 pyvex.expr.Const(cur_stmt_const_class(((const_0+const_1)&(1<<64)-1)))]))
                                import ipdb;ipdb.set_trace()
                                tmp_codeloc = IndSensitiveCodeLocation(successor.codeloc.block_addr,
                                                                       successor.codeloc.stmt_idx,
                                                                       ins_addr=cur_stmt_node.codeloc.ins_addr,
                                                                       ins_ind=cur_stmt_node.codeloc.ins_ind
                                                                       )

                                new_simpl_stmt_node = StatementNode(new_simpl_stmt, tmp_codeloc)
                                # This map is to ensure that if the two VEX insts are from two different x86 insts then after this simp we should treat them as one...... to make our life easier while mapping VEX back to x86
                                # new_address_map[new_simpl_stmt_node] = (cur_stmt_node.codeloc.ins_addr, cur_stmt_node.codeloc.ins_ind)
                                #successor.stmt = pyvex.stmt.WrTmp(cur_stmt.tmp, pyvex.expr.Binop("Iop_Add"+cur_stmt.data.op[-2:], [pyvex.expr.RdTmp(tmp_to_keep), pyvex.expr.Const(cur_stmt.data.args[1].__class__(pyvex.expr.U64(const_0+const_1 if const_0 + const_1 >= 0 else (1<<64)+const_1+const_0)))]))
                                # mark the new node as visited to that it's predecessor can be visited
                                visited_stmt_nodes[new_simpl_stmt_node] = True
                                for pred_node in pred_nodes_to_join:
                                    to_simplify_sub_graph.add_edge(pred_node, new_simpl_stmt_node)
                                for succ_node in succ_nodes_to_join:
                                    to_simplify_sub_graph.add_edge(new_simpl_stmt_node, succ_node)
                                to_simplify_sub_graph.remove_node(successor)
                                to_simplify_sub_graph.remove_node(cur_stmt_node)
                                #simplified_statements.pop(-2)
                                simp_flag = 1

                    # add all the stmts to a dictionary using the original indx
                    for stmt_node in to_simplify_sub_graph.nodes():
                        if stmt_node.codeloc.stmt_idx:
                            orig_stmt_idx_to_stmt_node[stmt_node.codeloc.stmt_idx] = stmt_node.stmt

                    ## reconstrcut the statements from the simplififed graph
                    stmt_node_queue = []
                    visited_stmt_nodes = {}

                    # # insert the leaf nodes into the queue and update the addresses of the modified instructions
                    # for stmt_node in to_simplify_sub_graph.nodes():
                    #     # Updating the new code locs for the stmts
                    #     # if not isinstance(stmt_node.codeloc, ExternalCodeLocation) and stmt_node in new_address_map:
                    #     #     ins_tuple = new_address_map[stmt_node]
                    #     #     new_stmt_node = StatementNode(stmt_node.stmt, )
                    #     #     stmt_node.codeloc.ins_addr = ins_tuple[0]
                    #     #     stmt_node.codeloc.ins_ind = ins_tuple[1]
                    #     if to_simplify_sub_graph.out_degree(stmt_node) == 0:
                    #         stmt_node_queue.append(stmt_node)
                    #
                    # while len(stmt_node_queue) > 0:
                    #     skip = False
                    #     cur_stmt_node = stmt_node_queue.pop(0)
                    #     if cur_stmt_node in visited_stmt_nodes:
                    #         continue
                    #     succs = list(to_simplify_sub_graph.successors(cur_stmt_node))
                    #
                    #     # make sure that all the successors are visited before visiting a node
                    #     for succ in succs:
                    #         if succ not in visited_stmt_nodes:
                    #             skip = True
                    #     if skip:
                    #         continue
                    #     preds = list(to_simplify_sub_graph.predecessors(cur_stmt_node))
                    #     stmt_node_queue = preds + stmt_node_queue
                    #     visited_stmt_nodes[cur_stmt_node] = True
                    #     if isinstance(cur_stmt_node.codeloc, ExternalCodeLocation):
                    #         continue
                    #     #simplified_statements.append(cur_stmt_node.stmt)
                    #     if (cur_stmt_node.codeloc.ins_addr, cur_stmt_node.codeloc.ins_ind) not in inst_grouped_simp_stmts:
                    #         inst_grouped_simp_stmts[(cur_stmt_node.codeloc.ins_addr, cur_stmt_node.codeloc.ins_ind)] = []
                    #     inst_grouped_simp_stmts[(cur_stmt_node.codeloc.ins_addr, cur_stmt_node.codeloc.ins_ind)].append(cur_stmt_node.stmt)

                # add the IMarks also to the dictionary
                for ind, stmt in enumerate(node.irsb.statements):
                    if isinstance(stmt, pyvex.stmt.IMark):
                        orig_stmt_idx_to_stmt_node[ind] = stmt

                for k in sorted(orig_stmt_idx_to_stmt_node.keys()):
                    simplified_statements.append(orig_stmt_idx_to_stmt_node[k])

                # # Making sure that the order of instructions is same as the original binary, though does not necessarily mean the best
                # ordered_ins_addrs = []
                # for ind, stmt in enumerate(node.irsb.statements):
                #     if isinstance(stmt, pyvex.stmt.IMark) and (stmt.addr, ind) in inst_grouped_simp_stmts:
                #         ordered_ins_addrs.append((stmt.addr, ind))
                #
                # for ins_tuple in ordered_ins_addrs:
                #     ins_addr = ins_tuple[0]
                #     ins_ind = ins_tuple[1]
                #     simplified_statements.append(pyvex.stmt.IMark(ins_addr, length=0, delta=0))
                #     for simp_stmt in inst_grouped_simp_stmts[(ins_addr, ins_ind)]:
                #         simplified_statements.append(simp_stmt)

                node.irsb = pyvex.IRSB.empty_block(node.irsb.arch,
                                                   node.irsb.addr,
                                                   statements=simplified_statements,
                                                   tyenv=node.irsb.tyenv,
                                                   nxt=node.irsb.next,
                                                   direct_next=node.irsb.direct_next,
                                                   jumpkind=node.irsb.jumpkind,
                                                   size=node.irsb.size)
                if len(simplified_statements) != len(node.irsb.statements):
                    import ipdb;ipdb.set_trace()
                # if simp_flag == 1:
                #     import ipdb;ipdb.set_trace()
                #     pass

        # # Returning a new CFGVMDeobfuscation object with the updated graph
        # if start_state:
        #     initial_input_state = start_state
        # else:
        #     initial_input_state = proj.factory.blank_state(addr=self.start_addr,
        #                                                    mode='fastpath',
        #                                                    add_options=angr.sim_options.refs | {
        #                                                        angr.sim_options.REPLACEMENT_SOLVER,
        #                                                        angr.sim_options.DO_CCALLS})
        # new_model._nodes_by_addr[self.start_addr][0].input_state = initial_input_state
        # new_cfg = proj.analyses.CFGVMDeobfuscation(model=new_model, keep_state=True, iropt_level=1,
        #                                            resolve_indirect_jumps=True, max_iterations=1,
        #                                            vm_vpc_addr=self.vm_vpc_addr)
        # print("Done")
        # return new_cfg

        return new_model

    def new_model_without_fakeret(self, old_graph, proj, identifier):
        # the CFG graph is owned by its model in modern angr, so take the new model's graph
        # instead of instantiating the graph class directly
        new_nodes = []
        node_map = {}
        node_map_by_addr = defaultdict(list)

        # not setting the attributes for the model since they will *most likely* be not used on the analysis
        new_model = VMCFGModel.from_model(proj.kb.cfgs.new_model(identifier, addr_type="block_id"))
        new_cfg_graph = new_model.graph

        new_edges = []
        for src, dst, data in old_graph.edges(data=True):

            print(data['jumpkind'])
            if "Ijk_FakeRet" != data['jumpkind']:
                new_src = CFGENode(irsb=copy.deepcopy(src.irsb),
                                    block_id=copy.deepcopy(src.block_id),
                                    size=copy.deepcopy(src.size),
                                    vm_vpc=copy.deepcopy(src.vm_vpc),
                                    looping_times=copy.deepcopy(src.looping_times),
                                    callstack_key=copy.deepcopy(src.callstack_key),
                                    simprocedure_name=copy.deepcopy(src.simprocedure_name),
                                    addr=copy.deepcopy(src.addr),
                                    function_address=copy.deepcopy(src.function_address),
                                    input_state=None,
                                    final_states=None,
                                    cfg=new_model)

                new_dst = CFGENode(irsb=copy.deepcopy(dst.irsb),
                                    block_id=copy.deepcopy(dst.block_id),
                                    size=copy.deepcopy(dst.size),
                                    vm_vpc=copy.deepcopy(dst.vm_vpc),
                                    looping_times=copy.deepcopy(dst.looping_times),
                                    callstack_key=copy.deepcopy(dst.callstack_key),
                                    simprocedure_name=copy.deepcopy(dst.simprocedure_name),
                                    addr=copy.deepcopy(dst.addr),
                                    function_address=copy.deepcopy(dst.function_address),
                                    input_state=None,
                                    final_states=None,
                                    cfg=new_model)


                new_edges.append((new_src, new_dst, {'jumpkind': data['jumpkind']}))
                node_map[new_src.block_id] = new_src
                node_map[new_dst.block_id] = new_dst
                node_map_by_addr[new_src.addr].append(new_src)
                node_map_by_addr[new_dst.addr].append(new_dst)


        for block_id, node in node_map.items():
            new_nodes.append(node)

        for block_id, node in node_map.items():
            new_model.add_node(block_id, node)
        new_cfg_graph.add_edges_from(new_edges)

        new_model._nodes_by_addr = node_map_by_addr

        return new_model


    def new_model_without_terminator_graph(self, old_graph, proj, identifier):
        # the CFG graph is owned by its model in modern angr, so take the new model's graph
        # instead of instantiating the graph class directly
        new_nodes = []
        node_map = {}
        node_map_by_addr = defaultdict(list)

        # not setting the attributes for the model since they will *most likely* be not used on the analysis
        new_model = VMCFGModel.from_model(proj.kb.cfgs.new_model(identifier, addr_type="block_id"))
        new_cfg_graph = new_model.graph

        # All four call sites drop the source graph immediately afterwards, so the new nodes can
        # take its irsbs over instead of deep-copying them (CFGENode still copies internally).
        # The rest of the attributes are ints/strs/tuples, where deepcopy was already a no-op.
        copy_irsbs = _project_bool_attr(self.project, "vm_deob_copy_irsbs_on_model_rebuild", False)
        for node in old_graph.nodes():
            if "PathTerminator" not in str(node.name):
                new_node = CFGENode(irsb=copy.deepcopy(node.irsb) if copy_irsbs else node.irsb,
                                    block_id=copy.deepcopy(node.block_id),
                                    size=node.size,
                                    vm_vpc=node.vm_vpc,
                                    looping_times=node.looping_times,
                                    callstack_key=node.callstack_key,
                                    simprocedure_name=node.simprocedure_name,
                                    addr=node.addr,
                                    function_address=node.function_address,
                                    input_state=None,
                                    final_states=None,
                                    cfg=new_model)

                new_nodes.append(new_node)
                node_map[new_node.block_id] = new_node
                node_map_by_addr[new_node.addr].append(new_node)

        new_edges = []
        for src, dst, data in old_graph.edges(data=True):
            if "PathTerminator" not in str(src.name) and "PathTerminator" not in str(dst.name):
                if src.block_id not in node_map or dst.block_id not in node_map:
                    # an edge endpoint that is no longer a node in the graph
                    continue
                new_edges.append((node_map[src.block_id], node_map[dst.block_id], {'jumpkind': data['jumpkind']}))

        for block_id, node in node_map.items():
            new_model.add_node(block_id, node)
        new_cfg_graph.add_edges_from(new_edges)

        new_model._nodes_by_addr = node_map_by_addr

        return new_model
    ## creates a new model which contains a graph that is structurally similar to the old one but resets the states
    ## and keeps certain attributes
    def new_model_graph(self, old_graph, proj, identifier):
        # the CFG graph is owned by its model in modern angr, so take the new model's graph
        # instead of instantiating the graph class directly
        new_nodes = []
        node_map = {}
        node_map_by_addr = defaultdict(list)

        # not setting the attributes for the model since they will *most likely* be not used on the analysis
        new_model = VMCFGModel.from_model(proj.kb.cfgs.new_model(identifier, addr_type="block_id"))
        new_cfg_graph = new_model.graph

        for node in old_graph.nodes():
            new_node = CFGENode(irsb=copy.deepcopy(node.irsb),
                                block_id=copy.deepcopy(node.block_id),
                                size=copy.deepcopy(node.size),
                                vm_vpc=copy.deepcopy(node.vm_vpc),
                                looping_times=copy.deepcopy(node.looping_times),
                                callstack_key=copy.deepcopy(node.callstack_key),
                                simprocedure_name=copy.deepcopy(node.simprocedure_name),
                                addr=copy.deepcopy(node.addr),
                                function_address=copy.deepcopy(node.function_address),
                                input_state=None,
                                final_states=None,
                                cfg=new_model)

            new_nodes.append(new_node)
            node_map[new_node.block_id] = new_node
            node_map_by_addr[new_node.addr].append(new_node)

        new_edges = []
        for src, dst, data in old_graph.edges(data=True):
            new_edges.append((node_map[src.block_id], node_map[dst.block_id], {'jumpkind': data['jumpkind']}))

        for block_id, node in node_map.items():
            new_model.add_node(block_id, node)
        new_cfg_graph.add_edges_from(new_edges)

        new_model._nodes_by_addr = node_map_by_addr

        return new_model

    # def annotate_and_preconstrain_sp(self, start_state):
    #     actual_stack_end = start_state.solver.eval(start_state.regs.sp)
    #     start_state.regs.sp = start_state.solver.BVS("precon_sp", 64)
    #     start_state.regs.sp = start_state.regs.sp.annotate(StackPointerAnnotation(1))
    #     start_state.preconstrainer.preconstrain(actual_stack_end, start_state.regs.sp)
    def release_memory(self, cfg, proj):

        # clear all references of the states to free memory, which is not released other wise
        cfg._initial_state = None
        cfg._symbolic_function_initial_state = None
        cfg._function_input_states = None
        cfg._job_map = None
        proj.factory.default_engine.successors = None
        proj.factory.default_engine.state = None
        return

    ####### Run the data sensisitve, loop unrolling, CFGEmulated analysis
    @logtime
    def data_sensitive_graph(self, filename, start_addr, start_state, cfg_fast_graph, avoid_runs, remove_insts=None, unroll_same_vpc_loop=False):
        #proj = angr.Project(filename)
        proj = self.project

        if start_state is None:
            if start_addr is None:
                main = proj.loader.main_object.get_symbol("main")
                start_addr = main.rebased_addr

            start_state = proj.factory.blank_state(addr=start_addr,
                                                   add_options={angr.sim_options.REPLACEMENT_SOLVER,
                                                                  angr.sim_options.DO_CCALLS})
            if proj.arch.bits == 32:
                start_state.registers.store(start_state.arch.registers['ss'][0], 0)
        # self.annotate_and_preconstrain_sp(start_state)

        self.remove_action_tracking(start_state)

        cfg = proj.analyses.CFGVMDeobfuscation(fail_fast=True,
                                        data_sensitive=True,
                                        starts=(start_addr,),
                                        initial_state=start_state,
                                        max_iterations=1,
                                        resolve_indirect_jumps=False,
                                        keep_state=False,
                                        state_add_options={angr.sim_options.DO_CCALLS, angr.sim_options.REPLACEMENT_SOLVER},
                                        iropt_level=1,
                                        cfg_fast_graph=cfg_fast_graph,
                                        avoid_runs=avoid_runs,
                                        remove_insts=remove_insts,
                                        start_deobfuscation_immediately=self.start_deobfuscation_immediately,
                                        deobfuscation_start_addr=self.deobfuscation_start_addr,
                                        deobfuscation_end_addr=self.deobfuscation_end_addr,
                                        nodes_to_prune=self.nodes_to_prune,
                                        unroll_same_vpc_loop=unroll_same_vpc_loop,
                                        hook_other_functions=self.hook_other_functions,
                                        remove_vmp_semantically_same_branch=self.remove_vmp_semantically_same_branch
                                        # enable_advanced_backward_slicing=True
                                        )
        self.release_memory(cfg, proj)
        return cfg, proj

    ####### Constant Propagation
    def constant_propagation(self, cfg, proj, start_addr, q, start_state=None, options=None, prev_symbolic_expr_locations_blockwise=None, vm_vpc = None, return_symbolic_expr_locations_blockwise=None, new_cfg=None, prev_unroll_vm_addrs = None):
        self.project.prev_symbolic_expr_locations_blockwise = prev_symbolic_expr_locations_blockwise
        print("Doing constant propagation")
        # old_graph = cfg.graph
        # new_model = self.new_model_graph(old_graph, proj, "temporary1")
        # new_cfg_graph = new_model.graph
        new_model = cfg
        new_cfg_graph = cfg.graph

        ## Setting the input state for the first node(need to automNcfg_vmate this)
        if start_addr == None:
            main = proj.loader.main_object.get_symbol("main")
            start_addr = main.rebased_addr
        if start_state:
            initial_input_state = start_state
        else:
            print("Using blank state!")
            # kwargs = {'plugins': {'memory': DefaultListPagesMemory(memory_id="mem")}, 'cle_memory_backer':proj.loader, }#,
            #                       #'registers': TopListPagesMemory(memory_id="reg")}}
            initial_input_state = proj.factory.blank_state(addr=start_addr, mode="fastpath", add_options={'REPLACEMENT_SOLVER','DO_CCALLS', 'SYMBOL_FILL_UNCONSTRAINED_REGISTERS', 'SYMBOL_FILL_UNCONSTRAINED_MEMORY', 'TOP_LIST_REGISTERS_CONSTANT_PROP', 'TOP_LIST_MEMORY_CONSTANT_PROP'})#'REPLACEMENT_SOLVER' removed to test the spped without replacements
            #initial_input_state.register_plugin('partial_symbolic_constraint_solver', angr.state_plugins.solver.SimSolver(solver=claripy.solvers.SolverComposite()))

            initial_input_state.register_plugin('partial_symbolic_constraint_solver',angr.state_plugins.solver.SimSolver(claripy.solvers.SolverReplacement(claripy.Solver(), unsafe_replacement=True, auto_replace=False))) #auto replace needs to be Fals otherwiseit will wrongly replace constraints that start with NOT to False

            if proj.arch.bits == 32:
                initial_input_state.registers.store('ss', 0)

            # preconstrain the stack pointer
            actual_stack_end = initial_input_state.solver.eval(initial_input_state.regs.sp)
            initial_input_state.regs.sp = initial_input_state.solver.BVS("precon_sp", 64)
            initial_input_state.preconstrainer.preconstrain(actual_stack_end, initial_input_state.regs.sp)

            initial_input_state.partial_symbolic_constraint_solver.add(initial_input_state.regs.sp == actual_stack_end)

            initial_input_state.globals['concretized_load_addr_dict'] = {}
            initial_input_state.globals['replaced_asts_str'] = {}
            initial_input_state.globals['existing_mba_split_constraints'] = []

        ####### Adding breakpoints
        def annotate_stack_read_value(state):
            is_stack_touched = False
            if not isinstance(state.inspect.mem_read_address, int):
                for annotation in state.inspect.mem_read_address.annotations:
                    if isinstance(annotation, StackTouchedAnnotation):
                        is_stack_touched = True
                        break
            if is_stack_touched:
                state.inspect.mem_read_expr = annotate_with_new_replacements(state, state.inspect.mem_read_expr, StackTouchedAnnotation(1))

        initial_input_state.inspect.add_breakpoint('mem_read',
                                     BP(
                                         BP_AFTER,
                                         action=annotate_stack_read_value
                                     ))

        def preconstrain_return_value(state):
            if state.inspect.simprocedure_name == "malloc" and state.inspect.simprocedure_result is not None and not state.solver.symbolic(state.inspect.simprocedure_result):
                value = state.solver.eval(state.inspect.simprocedure_result)
                state.inspect.simprocedure_result = state.solver.BVS("return_val", 64)
                state.preconstrainer.preconstrain(value, state.inspect.simprocedure_result)
            return

        ### preconstraining return values of library calls like malloc
        initial_input_state.inspect.add_breakpoint('simprocedure', BP(BP_AFTER, action=preconstrain_return_value))

        ## annotating and preconstraining the stack pointer
        #self.annotate_and_preconstrain_sp(initial_input_state)

        for node in new_model._nodes_by_addr[start_addr]:
            if node.addr == start_addr and node.block_id.vm_vpc == vm_vpc:
                node.input_state = initial_input_state
        ## find the replacements


        # replacing the printf hook with unconstrained return just for constant prop, since it get's a symbolic fmt str poitner
        for func_addr, orig_sim_proc, repl_sim_proc in self.constant_prop_func_replacements:
            proj.unhook(func_addr)
            proj.hook(func_addr, repl_sim_proc)

        prop = proj.analyses.PropagatorEmulated(graph=new_cfg_graph, iropt_level=1, start=start_addr, max_iterations=2)

        for func_addr, orig_sim_proc, repl_sim_proc in self.constant_prop_func_replacements:
            proj.unhook(func_addr)
            proj.hook(func_addr, orig_sim_proc)

        ## do the actual replacements
        for loc, repl_pair in prop.replacements.items():
            key = loc.block_id
            node = new_model.get_node(key)
            if not node.is_simprocedure:
                new_stmts = node.irsb.statements
                if node.addr == 0x44e41b:
                    import ipdb;ipdb.set_trace()
                # for stmt, repl_pair in value.items():
                #     for old, new in repl_pair.items():
                #         ## This is for the next expression
                #         if stmt.stmt_idx == -2:
                #             node.irsb.next = new
                #         else:
                #             new_stmts[stmt.stmt_idx].replace_expression({old: new})
                for old, new in repl_pair.items():
                    if not angr.analyses.propagator_emulated.propagator_emulated.PropagatorState.is_top(new):
                        ## This is for the next expression
                        if loc.stmt_idx == -2:
                            node.irsb.next = new
                        else:
                            new_stmts[loc.stmt_idx].replace_expression({old: new})

        tmp_syb_blockwise = defaultdict(dict)
        for codeloc, expr_list in prop.symbolic_expr_locations_blockwise.items():
            if codeloc in tmp_syb_blockwise[codeloc.block_id]:
                tmp_syb_blockwise[codeloc.block_id][codeloc] = tmp_syb_blockwise[codeloc.block_id][codeloc] + expr_list
            else:
                tmp_syb_blockwise[codeloc.block_id][codeloc] = expr_list

        prop.symbolic_expr_locations_blockwise = tmp_syb_blockwise

        print("Done")
        return new_model, prop.symbolic_expr_locations_blockwise

    #### This method removes stuff like empty blocks, empty instructions(Imark, AbiHints etc)
    def remove_junk(self, cfg, proj, start_addr, start_state=None):
        print("Doing junk removal")
        if start_addr == None:
            main = proj.loader.main_object.get_symbol("main")
            start_addr = main.rebased_addr

        for node in list(cfg.graph.nodes()):
            if not node.is_simprocedure:
                old_stmts = node.irsb.statements
                new_stmts = []
                for ind, stmt in enumerate(old_stmts):
                    if isinstance(stmt, pyvex.stmt.IMark) or isinstance(stmt, pyvex.stmt.AbiHint)\
                             or isinstance(stmt, pyvex.stmt.Exit):
                        new_stmts.append(stmt)
                        continue

                    location = CodeLocation(node.irsb.addr, ind, node.block_id)
                    if len(ddg._stmt_graph.out_edges([location])) != 0:
                        new_stmts.append(stmt)
                    ## check if there's a Store from a symbolic memory address
                    elif isinstance(stmt, pyvex.stmt.Store) and not type(stmt.addr) == pyvex.expr.Const:
                        new_stmts.append(stmt)

                node.irsb = pyvex.IRSB.empty_block(node.irsb.arch,
                                                   node.irsb.addr,
                                                   statements=new_stmts,
                                                   tyenv=node.irsb.tyenv,
                                                   nxt=node.irsb.next,
                                                   direct_next=node.irsb.direct_next,
                                                   jumpkind=node.irsb.jumpkind,
                                                   size=node.irsb.size)
            else:
                print("This is a SimProcedure")
                print(node)
                print("\n")


        ### Returning a new CFGVMDeobfuscation object with the updated graph
        dce_new_model = self.new_model_graph(cfg.graph, proj, 'dce')
        if start_state:
            initial_input_state = start_state
        else:
            initial_input_state = proj.factory.blank_state(addr=start_addr,
                                                           mode='fastpath',
                                                           add_options=angr.sim_options.refs | {
                                                           angr.sim_options.REPLACEMENT_SOLVER, angr.sim_options.DO_CCALLS})
            if proj.arch.bits == 32:
                initial_input_state.registers.store(initial_input_state.arch.registers['ss'][0], 0)
        dce_new_model._nodes_by_addr[start_addr][0].input_state = initial_input_state
        new_cfg = proj.analyses.CFGVMDeobfuscation(model=dce_new_model, keep_state=True, iropt_level=1, resolve_indirect_jumps=True, max_iterations=1)
        print("Done")
        return new_cfg

    # def simplifications(self, cfg, proj, start_addr, vm_vpc_addr, start_state=None):
    #     if start_addr == None:
    #         main = proj.loader.main_object.get_symbol("main")
    #         start_addr = main.rebased_addr
    #
    #     for node in list(cfg.graph.nodes()):
    #         if not node.is_simprocedure:
    #             manager = Manager("manager",node.irsb.arch)
    #             ail_block = IRSBConverter.convert(node.irsb, manager)
    #             print("Original:")
    #             print(ail_block)
    #             print("\nSimplified:")
    #             simplified_ail_block = proj.analyses.AILBlockSimplifier(ail_block)
    #             print(simplified_ail_block.result_block)
    #             print("\n\n")
    #
    #     ### Returning a new CFGVMDeobfuscation object with the updated graph
    #     simplified_new_model = self.new_model_graph(cfg.graph, proj, 'simplify1')
    #     if start_state:
    #         initial_input_state = start_state
    #     else:
    #         initial_input_state = proj.factory.blank_state(addr=start_addr,
    #                                                        mode='fastpath',
    #                                                        add_options=angr.sim_options.refs | {
    #                                                            angr.sim_options.REPLACEMENT_SOLVER,
    #                                                        angr.sim_options.DO_CCALLS})
    #
    #     simplified_new_model._nodes_by_addr[start_addr][0].input_state = initial_input_state
    #     new_cfg = proj.analyses.CFGVMDeobfuscation(model=simplified_new_model, keep_state=True, iropt_level=1,
    #                                         resolve_indirect_jumps=True, max_iterations=1, vm_vpc_addr=vm_vpc_addr)
    #     return new_cfg

    def add_fake_node_for_DCE(self, cfg):
        # Add a fake node that uses all the registers, so that we do not eliminate them all in DCE
        reg_to_add = ['rax', 'eax', 'ax', 'al', 'ah', 'rcx', 'ecx', 'cx', 'cl', 'ch', 'rdx', 'edx', 'dx', 'dl', 'dh', 'rbx', 'ebx', 'bx', 'bl', 'bh', 'rsp', 'sp', 'esp', 'rbp', 'bp', 'ebp', 'bpl', 'bph', 'rsi', 'esi', 'si', 'sil', 'sih', 'rdi', 'edi', 'di', 'dil', 'dih', 'r8', 'r8d', 'r8w', 'r8b', 'r9', 'r9d', 'r9w', 'r9b', 'r10', 'r10d', 'r10w', 'r10b', 'r11', 'r11d', 'r11w', 'r11b', 'r12', 'r12d', 'r12w', 'r12b', 'r13', 'r13d', 'r13w', 'r13b', 'r14', 'r14d', 'r14w', 'r14b', 'r15', 'r15d', 'r15w', 'r15b', 'cc_op', 'cc_dep1', 'cc_dep2', 'cc_ndep', 'd', 'dflag', 'rip']
        for node in list(cfg.graph.nodes()):
            # Looking for the last node
            if not node.is_simprocedure and len(list(cfg.graph.successors(node))) == 0:
                new_stmts = []
                new_types_list = []
                t_ind = 0
                for reg in reg_to_add:
                    reg_tuple = self.project.arch.registers[reg]
                    new_stmts.append(pyvex.stmt.WrTmp(t_ind, pyvex.expr.Get(reg_tuple[0], 'Ity_I'+str(reg_tuple[1]*self.project.arch.byte_width))))
                    new_types_list.append('Ity_I'+str(reg_tuple[1]*self.project.arch.byte_width))
                    t_ind = t_ind+1
                fake_irsb = pyvex.IRSB.empty_block(node.irsb.arch,
                                                   0xdeadbeef,
                                                   statements=new_stmts,
                                                   tyenv=pyvex.block.IRTypeEnv(self.project.arch, types=new_types_list),
                                                   nxt=node.irsb.next,
                                                   direct_next=node.irsb.direct_next,
                                                   jumpkind='Ijk_Borking',
                                                   size=100)
                fake_node = CFGENode(0xdeadbeef, 100, cfg, irsb=fake_irsb)

                cfg.graph.add_edge(node, fake_node, jumpkind='Ijk_Boring')

        return cfg


    ####### Dead Cod Elimination
    def dead_code_elimination(self, cfg, proj, start_addr, start_state):
        print("Performing dead code elimination")
        if start_addr == None:
            main = proj.loader.main_object.get_symbol("main")
            start_addr = main.rebased_addr
        ddg = proj.analyses.DDG(cfg, start_addr)
        changed = False

        node_replace_dict = {}
        for node in list(cfg.graph.nodes()):
            if not node.is_simprocedure and len(list(cfg.graph.successors(node))) != 0:
                print(node.simprocedure_name)
                old_stmts = node.irsb.statements
                new_stmts = []
                cur_ins_addr = None
                for ind, stmt in enumerate(old_stmts):
                    if isinstance(stmt, pyvex.stmt.IMark):
                        cur_ins_addr = stmt.addr
                    if isinstance(stmt, pyvex.stmt.IMark) and ind == len(old_stmts)-1:
                        continue
                    elif isinstance(stmt, pyvex.stmt.AbiHint) and ind == len(old_stmts)-1:
                        continue
                    elif isinstance(stmt, pyvex.stmt.IMark) and isinstance(old_stmts[ind+1], pyvex.stmt.IMark):
                        continue
                    elif isinstance(stmt, pyvex.stmt.IMark) and isinstance(old_stmts[ind+1], pyvex.stmt.AbiHint):
                        continue
                    elif isinstance(stmt, pyvex.stmt.Exit) and type(stmt.guard) == pyvex.expr.Const:
                        # Removing conditional statements that depend on a constant
                        if stmt.guard.con.value == 0:
                            continue
                        elif stmt.guard.con.value == 1:
                            node.irsb.next =pyvex.expr.Const(stmt.dst)
                            continue
                    elif isinstance(stmt, pyvex.stmt.Exit) and not type(stmt.guard) == pyvex.expr.Const:
                        new_stmts.append(stmt)
                        continue
                    elif isinstance(stmt, pyvex.stmt.IMark) or isinstance(stmt, pyvex.stmt.AbiHint):
                        new_stmts.append(stmt)
                        continue

                    location = CodeLocation(node.irsb.addr , ind, node.block_id)
                    # if isinstance(stmt, pyvex.stmt.Put) and cur_ins_addr == 0x6d32fc and isinstance(stmt.data, pyvex.expr.RdTmp) and stmt.offset == 72:
                    #     import ipdb;
                    #     ipdb.set_trace()
                    # Check for stmts with no outgoing edges for deadcode
                    if len(ddg._stmt_graph.out_edges([location])) != 0:
                        # print("Dependencies of: "+stmt.__str__(arch=node.irsb.arch, tyenv=node.irsb.tyenv))
                        # for out_edges in ddg._stmt_graph.out_edges([location]):
                        #     print(out_edges[1])
                        new_stmts.append(stmt)
                    # check if there's a Store from a symbolic memory address
                    elif (isinstance(stmt, pyvex.stmt.Store) and not type(stmt.addr) == pyvex.expr.Const):
                        new_stmts.append(stmt)
                    # elif isinstance(stmt, pyvex.stmt.WrTmp) and stmt.tmp == 421 and node.addr in [0x6bb92e, 0x6b3241] and node.block_id.vm_vpc in [6736528, 6736645]:
                    #     import ipdb;ipdb.set_trace()

                if new_stmts != node.irsb.statements:
                    changed = True
                # Dealing with empty blocks i.e. removing them
                if len(new_stmts) == 0:
                    succ = cfg.graph.successors(node)
                    succ = next(succ)
                    preds = cfg.graph.predecessors(node)
                    to_remove = False
                    for pred in preds:
                        pred_edge_data = cfg.graph.get_edge_data(pred, node)
                        # Reassigning the next expression of the previous
                        if not pred.is_simprocedure:
                            cfg.graph.add_edge(pred, succ, jumpkind=pred_edge_data['jumpkind'])
                            if isinstance(pred.irsb.statements[-1], pyvex.stmt.Exit):
                                if pred.irsb.statements[-1].dst.block_id == node.block_id:
                                    pred.irsb.statements[-1].dst = node.irsb.next.con
                                else:
                                    pred.irsb.next = node.irsb.next
                            else:
                                pred.irsb.next = node.irsb.next
                            to_remove = True
                        else:
                            print("Not removing this block, since there the previous block is a Sim Procedure")
                    if to_remove:
                        cfg.graph.remove_node(node)
                else:
                    node.irsb = pyvex.IRSB.empty_block(node.irsb.arch,
                                                       node.irsb.addr,
                                                       statements=new_stmts,
                                                       tyenv=node.irsb.tyenv,
                                                       nxt=node.irsb.next,
                                                       direct_next=node.irsb.direct_next,
                                                       jumpkind=node.irsb.jumpkind,
                                                       size=node.irsb.size)

            else:
                print("This is a SimProcedure")
                print(node)
                print("\n")

        # Returning a new CFGVMDeobfuscation object with the updated graph
        dce_new_model = self.new_model_graph(cfg.graph, proj, 'dce')
        if start_state:
            initial_input_state = start_state
        else:
            initial_input_state = proj.factory.blank_state(addr=start_addr,
                                                           mode='fastpath',
                                                           add_options=angr.sim_options.refs | {
                                                           angr.sim_options.REPLACEMENT_SOLVER, angr.sim_options.DO_CCALLS})
            if proj.arch.bits == 32:
                initial_input_state.registers.store(initial_input_state.arch.registers['ss'][0], 0)
        dce_new_model._nodes_by_addr[start_addr][0].input_state = initial_input_state
        new_cfg = proj.analyses.CFGVMDeobfuscation(model=dce_new_model, keep_state=True, iropt_level=1, resolve_indirect_jumps=True, max_iterations=1)
        print("Done")
        return new_cfg, changed

    ### Draw the graph with vex statements

    def super_graph(self, cfg):
        super_graph = cfg.graph.copy()
        all_nodes = list(super_graph.nodes())
        nodes_to_remove = []
        edges_to_add = []
        for node in all_nodes:
            if len(list(super_graph.successors(node))) == 1 and len(list(super_graph.predecessors(node))) == 1 and not node.is_simprocedure:
                succ = list(super_graph.successors(node))[0]
                pred = list(super_graph.predecessors(node))[0]
                if len(list(super_graph.successors(pred))) == 1 and len(list(super_graph.predecessors(succ))) == 1:
                    # edges_to_add.append((list(super_graph.predecessors(node))[0], list(super_graph.successors(node))[0]))
                    # nodes_to_remove.append(node)
                    super_graph.add_edge(list(super_graph.predecessors(node))[0], list(super_graph.successors(node))[0])
                    super_graph.remove_node(node)

        # for node in nodes_to_remove:
        #     super_graph.add_edge(list(super_graph.predecessors(node))[0], list(super_graph.successors(node))[0])
        #     super_graph.remove_node(node)
        # for edge in edges_to_add:
        #     super_graph.add_edge(edge[0], edge[1])
        return super_graph

    def draw_graph(self, cfg, filename, start_node_str=None, without_insts=True, super_graph_only=True):
        if not self.draw_graph_flag:
            print("skip graph drawing")
            return
        # dot layout is the single most expensive thing in the run on large graphs
        # (22% of vmwhere1-uiuctf); set project.vm_deob_draw_graphs = False to skip it.
        if not _project_bool_attr(self.project, "vm_deob_draw_graphs", True):
            return
        node_limit = 10000
        no_nodes = 0
        print("saving graph "+str(filename))

        if start_node_str:
            sub_graph = nx.DiGraph()
            for node in cfg.graph.nodes():
                if str(node) == start_node_str:
                    start_node = node
            queue = [start_node]
            while len(queue) != 0:# and no_nodes < node_limit:
                print(no_nodes)
                no_nodes+=1
                node = queue.pop(0)
                if str(node) == "<CFGENode sprintf0x4300108 ()vm-vpc:`69297812 >":
                    break
                sub_graph.add_node(node)
                for succ in list(cfg.graph.successors(node)):
                    sub_graph.add_edge(node, succ)

                queue = queue + list(cfg.graph.successors(node))

            A = nx.nx_agraph.to_agraph(as_networkx(sub_graph))

            for node in sub_graph.nodes():
                stmt_str = str(node)
                if not without_insts and node.irsb != None:
                    for ind, stmt in enumerate(node.irsb.statements):
                        stmt_str = stmt_str + "\l" + stmt.pp_str(arch=node.irsb.arch, tyenv=node.irsb.tyenv)

                graphviz_node = A.get_node(str(node))
                graphviz_node.attr["label"] = stmt_str
                graphviz_node.attr["shape"] = "box"
        elif super_graph_only:
            sub_graph = self.super_graph(cfg)
            A = nx.nx_agraph.to_agraph(as_networkx(sub_graph))
            for node in sub_graph.nodes():
                stmt_str = str(node)
                if not without_insts and node.irsb != None:
                    for ind, stmt in enumerate(node.irsb.statements):
                        stmt_str = stmt_str + "\l" + stmt.pp_str(arch=node.irsb.arch, tyenv=node.irsb.tyenv)

                graphviz_node = A.get_node(str(node))
                graphviz_node.attr["label"] = stmt_str
                graphviz_node.attr["shape"] = "box"
        else:
            A = nx.nx_agraph.to_agraph(as_networkx(cfg.graph))

            for node in cfg.graph.nodes():
                stmt_str = str(node)
                if not without_insts and node.irsb != None:
                    for ind, stmt in enumerate(node.irsb.statements):
                        stmt_str = stmt_str + "\l" + stmt.pp_str(arch=node.irsb.arch, tyenv=node.irsb.tyenv)

                graphviz_node = A.get_node(str(node))
                graphviz_node.attr["label"] = stmt_str
                graphviz_node.attr["shape"] = "box"
        A.layout(prog="dot")
        A.draw(path=filename, format="svg")

    def draw_png_graph(self, cfg, filename):
        print("saving graph "+str(filename))
        A = nx.nx_agraph.to_agraph(as_networkx(cfg.graph))
        for node in cfg.graph.nodes():
            stmt_str = str(node)
            # if node.irsb != None:
            #     for ind, stmt in enumerate(node.irsb.statements):
            #         stmt_str = stmt_str + "\l" + stmt.__str__(arch=node.irsb.arch, tyenv=node.irsb.tyenv)

            graphviz_node = A.get_node(str(node))
            graphviz_node.attr["label"] = stmt_str
            graphviz_node.attr["shape"] = "box"
        A.layout(prog="dot")
        A.draw(path=filename, format="png")

    ### Drawing a graph comparing the removed x86 instructions vs the instructions that were kept(or a part of their statemnts was left beind after simplifications)
    def draw_original_graph(self, cfg, filename, proj):
        print("Drawing graph")
        A = nx.nx_agraph.to_agraph(as_networkx(cfg.graph))
        for node in cfg.graph.nodes():
            original_addresses = proj.factory.block(node.addr).instruction_addrs
            original_instructions = proj.factory.block(node.addr).capstone.insns
            stmt_str = "<" + str(node).strip("<>")
            if node.irsb != None:
                addresses_left_in_simplified = []
                for ind, stmt in enumerate(node.irsb.statements):
                    if stmt.tag == "Ist_IMark":
                        addresses_left_in_simplified.append(stmt.addr)

                for addr in original_addresses:
                    if addr in addresses_left_in_simplified:
                        ## statements that have been kept
                        stmt_str = stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='blue'>" + str(original_instructions[original_addresses.index(addr)]).replace("\t", " ") + "</FONT>"
                    else:
                        ## statements that have been removed
                        stmt_str = stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='red'>" + str(original_instructions[original_addresses.index(addr)]).replace("\t", " ") + "</FONT>"

            graphviz_node = A.get_node(str(node))
            graphviz_node.attr["label"] = stmt_str+">"
            graphviz_node.attr["shape"] = "box"
        A.layout(prog="dot")
        A.draw(path=filename, format="svg")
        print("Done")

    ############### !!!! This only works under the assumption that no new statements are added to the final graph, i.e. statements are only removed from the final graph ################
    def compare_vex(self, initial_cfg, final_cfg, folder_name):
        print("Comparing VEX")
        A = nx.nx_agraph.to_agraph(as_networkx(initial_cfg.graph))
        B = nx.nx_agraph.to_agraph(as_networkx(final_cfg.graph))

        initial_cfg_node_map = {}
        for node in initial_cfg.graph.nodes():
            initial_cfg_node_map[node.block_id] = node

        final_cfg_node_map = {}
        for node in final_cfg.graph.nodes():
            final_cfg_node_map[node.block_id] = node

        #### Iterating over nodes of the initial graph
        for initial_cfg_node in initial_cfg.graph.nodes():
            if initial_cfg_node.block_id in final_cfg_node_map:
                final_cfg_node = final_cfg_node_map[initial_cfg_node.block_id]
            else:
                continue
            initial_cfg_node_stmt_str = "<" + str(initial_cfg_node).strip("<>")
            final_cfg_node_stmt_str = "<" + str(final_cfg_node).strip("<>")

            initial_cfg_index = 0
            final_cfg_index = 0

            if initial_cfg_node.irsb != None and final_cfg_node.irsb != None:
                initial_cfg_node_stmts = initial_cfg_node.irsb.statements
                final_cfg_node_stmts = final_cfg_node.irsb.statements

                while True:

                    ### End loop if end of statements is reached for one of the nodes
                    if final_cfg_index == len(final_cfg_node_stmts) or initial_cfg_index == len(initial_cfg_node_stmts):
                        break

                    ### if the next instruction(IMark) is reached on the final graph then run through the statements of the initial graph till we find the coresponding instruction(IMark)
                    if isinstance(final_cfg_node_stmts[final_cfg_index], pyvex.stmt.IMark) and not isinstance(initial_cfg_node_stmts[final_cfg_index], pyvex.stmt.IMark):
                        while True:
                            if isinstance(initial_cfg_node_stmts[initial_cfg_index], pyvex.stmt.IMark) and initial_cfg_node_stmts[initial_cfg_index].addr == final_cfg_node_stmts[final_cfg_index].addr:
                                break
                            initial_cfg_node_stmt_str = initial_cfg_node_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='red'>" + \
                                                      initial_cfg_node_stmts[initial_cfg_index].__str__(
                                                          arch=initial_cfg_node.irsb.arch,
                                                          tyenv=initial_cfg_node.irsb.tyenv).replace("\t", " ") + "</FONT>"
                            initial_cfg_index += 1
                    ### If both the statments are the same then make then blue
                    if str(initial_cfg_node_stmts[initial_cfg_index]) == str(final_cfg_node_stmts[final_cfg_index]):
                        initial_cfg_node_stmt_str = initial_cfg_node_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='blue'>" + initial_cfg_node_stmts[initial_cfg_index].__str__(arch=initial_cfg_node.irsb.arch, tyenv=initial_cfg_node.irsb.tyenv).replace("\t", " ") + "</FONT>"
                        final_cfg_node_stmt_str = final_cfg_node_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='blue'>" + final_cfg_node_stmts[final_cfg_index].__str__(arch=final_cfg_node.irsb.arch, tyenv=final_cfg_node.irsb.tyenv).replace("\t", " ") + "</FONT>"
                        initial_cfg_index += 1
                        final_cfg_index += 1
                    ### If both statemnts are WrTmp to the same variable but different value then make it orange, otherwise red
                    elif isinstance(initial_cfg_node_stmts[initial_cfg_index], pyvex.stmt.WrTmp) and isinstance(final_cfg_node_stmts[final_cfg_index], pyvex.stmt.WrTmp):
                        if initial_cfg_node_stmts[initial_cfg_index].tmp == final_cfg_node_stmts[final_cfg_index].tmp:
                            initial_cfg_node_stmt_str = initial_cfg_node_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='orange'>" + \
                                                        initial_cfg_node_stmts[initial_cfg_index].__str__(
                                                            arch=initial_cfg_node.irsb.arch,
                                                            tyenv=initial_cfg_node.irsb.tyenv).replace("\t",
                                                                                                       " ") + "</FONT>"
                            final_cfg_node_stmt_str = final_cfg_node_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='orange'>" + \
                                                      final_cfg_node_stmts[final_cfg_index].__str__(
                                                          arch=final_cfg_node.irsb.arch,
                                                          tyenv=final_cfg_node.irsb.tyenv).replace("\t", " ") + "</FONT>"
                            initial_cfg_index += 1
                            final_cfg_index += 1
                        else:
                            initial_cfg_node_stmt_str = initial_cfg_node_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='red'>" + \
                                                        initial_cfg_node_stmts[initial_cfg_index].__str__(
                                                            arch=initial_cfg_node.irsb.arch,
                                                            tyenv=initial_cfg_node.irsb.tyenv).replace("\t",
                                                                                                       " ") + "</FONT>"
                            initial_cfg_index += 1
                    ### If both statements are Put to the same variable but different value then make it orange, otherwise red
                    elif isinstance(initial_cfg_node_stmts[initial_cfg_index], pyvex.stmt.Put) and isinstance(final_cfg_node_stmts[final_cfg_index], pyvex.stmt.Put):
                        if initial_cfg_node_stmts[initial_cfg_index].offset == final_cfg_node_stmts[final_cfg_index].offset:
                            initial_cfg_node_stmt_str = initial_cfg_node_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='orange'>" + \
                                                        initial_cfg_node_stmts[initial_cfg_index].__str__(
                                                            arch=initial_cfg_node.irsb.arch,
                                                            tyenv=initial_cfg_node.irsb.tyenv).replace("\t",
                                                                                                       " ") + "</FONT>"
                            final_cfg_node_stmt_str = final_cfg_node_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='orange'>" + \
                                                      final_cfg_node_stmts[final_cfg_index].__str__(
                                                          arch=final_cfg_node.irsb.arch,
                                                          tyenv=final_cfg_node.irsb.tyenv).replace("\t", " ") + "</FONT>"
                            initial_cfg_index += 1
                            final_cfg_index += 1
                        else:
                            initial_cfg_node_stmt_str = initial_cfg_node_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='red'>" + \
                                                        initial_cfg_node_stmts[initial_cfg_index].__str__(
                                                            arch=initial_cfg_node.irsb.arch,
                                                            tyenv=initial_cfg_node.irsb.tyenv).replace("\t",
                                                                                                       " ") + "</FONT>"
                            initial_cfg_index += 1
                    ### If both statements are Store to the same variable but different value then make it orange, otherwise red
                    elif isinstance(initial_cfg_node_stmts[initial_cfg_index], pyvex.stmt.Store) and isinstance(final_cfg_node_stmts[final_cfg_index], pyvex.stmt.Store):
                        if (str(initial_cfg_node_stmts[initial_cfg_index].addr) == str(final_cfg_node_stmts[final_cfg_index].addr)) or (str(initial_cfg_node_stmts[initial_cfg_index].data) == str(final_cfg_node_stmts[final_cfg_index].data)):
                            initial_cfg_node_stmt_str = initial_cfg_node_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='orange'>" + \
                                                        initial_cfg_node_stmts[initial_cfg_index].__str__(
                                                            arch=initial_cfg_node.irsb.arch,
                                                            tyenv=initial_cfg_node.irsb.tyenv).replace("\t",
                                                                                                       " ") + "</FONT>"
                            final_cfg_node_stmt_str = final_cfg_node_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='orange'>" + \
                                                      final_cfg_node_stmts[final_cfg_index].__str__(
                                                          arch=final_cfg_node.irsb.arch,
                                                          tyenv=final_cfg_node.irsb.tyenv).replace("\t", " ") + "</FONT>"
                            initial_cfg_index += 1
                            final_cfg_index += 1
                        else:
                            initial_cfg_node_stmt_str = initial_cfg_node_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='red'>" + \
                                                        initial_cfg_node_stmts[initial_cfg_index].__str__(
                                                            arch=initial_cfg_node.irsb.arch,
                                                            tyenv=initial_cfg_node.irsb.tyenv).replace("\t",
                                                                                                       " ") + "</FONT>"
                            initial_cfg_index += 1
                    ### If none of the above conditions are true then just go to the next statement on the initial graph
                    else:
                        initial_cfg_node_stmt_str = initial_cfg_node_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='red'>" + \
                                                    initial_cfg_node_stmts[initial_cfg_index].__str__(
                                                        arch=initial_cfg_node.irsb.arch,
                                                        tyenv=initial_cfg_node.irsb.tyenv).replace("\t",
                                                                                                   " ") + "</FONT>"
                        initial_cfg_index += 1



            graphviz_node = A.get_node(str(initial_cfg_node))
            graphviz_node.attr["label"] = initial_cfg_node_stmt_str+">"
            graphviz_node.attr["shape"] = "box"

            graphviz_node = B.get_node(str(final_cfg_node))
            graphviz_node.attr["label"] = final_cfg_node_stmt_str + ">"
            graphviz_node.attr["shape"] = "box"

        A.layout(prog="dot")
        A.draw(path=os.path.join(folder_name, "vex_comparision_initial_cfg.svg"), format="svg")
        B.layout(prog="dot")
        B.draw(path=os.path.join(folder_name, "vex_comparision_final_cfg.svg"), format="svg")
        print("Done")

    def pattern_match_to_x86_instructions(self, final_cfg, orig_cfg, proj, folder_name):
        print("Pattern match to x86")
        A = nx.nx_agraph.to_agraph(as_networkx(final_cfg.graph))
        original_addresses = []
        original_instructions = []
        for orig_cfg_node in orig_cfg.graph.nodes():
            original_addresses = original_addresses + list(proj.factory.block(orig_cfg_node.addr).instruction_addrs)
            original_instructions = original_instructions + proj.factory.block(orig_cfg_node.addr).capstone.insns

        #### Iterating over nodes of the initial graph
        for final_cfg_node in final_cfg.graph.nodes():
            x86_stmt_str = "<" + str(final_cfg_node).strip("<>")
            if final_cfg_node.irsb != None:
                cur_ins_str = ""
                for ind, stmt in enumerate(final_cfg_node.irsb.statements):
                    if isinstance(stmt, pyvex.stmt.IMark):
                        curr_ins_addr = stmt.addr
                        cur_ins_str = ""
                    else:
                        cur_ins_str = cur_ins_str + "\n" + stmt.__str__(arch=final_cfg_node.irsb.arch, tyenv=final_cfg_node.irsb.tyenv)

                    if ind == len(final_cfg_node.irsb.statements)-1 or isinstance(final_cfg_node.irsb.statements[ind+1], pyvex.stmt.IMark):
                        ###### This is a regex for converting
                        ###### t5 = GET:I64(rbp)
                        ###### t4 = Add64(t5,0xfffffffffffffffc)
                        ###### t0 = t4
                        ###### STle(t0) = 0x00001064
                        ###### to
                        ###### mov dword ptr[reg -constant], constant
                        match_result = re.match("\nt\d+\s=\sGET:I64\((\w+)\)\nt\d+\s=\sAdd64\(t\d+,(0xff+\w+)\)\nt\d+\s=\st\d+\nSTle\(t\d+\)\s=\s(\w{10})",cur_ins_str)
                        if match_result:
                            x86_stmt_str = x86_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='orange'>" + str(hex(curr_ins_addr))+": mov dword ptr [" + match_result.group(1) + " - "+str((int(match_result.group(2), 16)^0xffffffffffffffff)+1) +"], "+match_result.group(3) +"</FONT>"
                            continue

                        ###### This is a regex for converting
                        # ------ IMark(0x400cf3, 0, 0) - -----
                        # t4 = GET:I64(rax)
                        # t5 = Add64(t4, 0x000000000060269f)
                        # STle(t5) = 0x00
                        # to
                        #  mov byte ptr [rax + 0x000000000060269f], 0x00
                        match_result = re.match("\nt\d+\s=\sGET:I64\((\w+)\)\nt\d+\s=\sAdd64\(t\d+,(0x\w+)\)\nSTle\(t\d+\)\s=\s(\w{4})",cur_ins_str)
                        if match_result:
                            x86_stmt_str = x86_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='orange'>" + str(hex(curr_ins_addr))+": mov byte ptr [" + match_result.group(1) + " + "+match_result.group(2) +"], "+match_result.group(3) +"</FONT>"
                            continue

                        ###### This is a regex for converting
                        # ------ IMark(0x40090c, 0, 0) - -----
                        # STle(0x00000000006027a0) = 0x00
                        # to
                        #  mov byte ptr [0x00000000006027a0], 0x00
                        match_result = re.match("\nSTle\((\w+)\)\s=\s(\w+)",cur_ins_str)
                        if match_result:
                            if len(match_result.group(2)) == 4:
                                x86_stmt_str = x86_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='orange'>" + str(hex(curr_ins_addr))+": mov byte ptr [" + match_result.group(1) +"], "+match_result.group(2) +"</FONT>"
                            elif len(match_result.group(2)) == 18:
                                x86_stmt_str = x86_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='orange'>" + str(
                                    hex(curr_ins_addr)) + ": mov [" + match_result.group(
                                    1) + "], " + match_result.group(2) + "</FONT>"
                            continue
                        ###### This is a regex for converting
                        # ------ IMark(0x40085f, 0, 0) ------
                        # t20 = Add64(t17,0xffffffffffffffd8)
                        # STle(t20) = 0x0000000000602320
                        # to
                        # mov byte ptr [rbp - 9], 0x0000000000602320
                        match_result = re.match("\nt\d+\s=\sAdd64\(t\d+,0x\w+\)\nSTle\((\w+)\)\s=\s(\w+)",cur_ins_str)
                        if match_result:
                            if original_instructions[original_addresses.index(curr_ins_addr)].insn.mnemonic != 'push':
                                second_arg = original_instructions[original_addresses.index(curr_ins_addr)].insn.op_str.split(',')[1]
                                is_reg = re.match("\s[a-z]+", second_arg)
                                is_tmp = re.match("\st*", second_arg)
                                if is_reg and not is_tmp:
                                    x86_stmt_str = x86_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='orange'>" + str(original_instructions[original_addresses.index(curr_ins_addr)]).replace("\t", " ")[:-3]+match_result.group(2) + "</FONT>"
                                    continue
                            else:
                                x86_stmt_str = x86_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='orange'>" + "push " + match_result.group(
                                    2) + "</FONT>"
                                continue

                        match_result = re.match("\nt\d+\s=\sGET:I64\((\w+)\)\nt\d+\s=\s64to32\(t\d+\)\nt\d+\s=\st\d+\nt\d+\s=\sAdd32\((\w+),t\d+\)\nt\d+\s=\s32Uto64\(t\d+\)\nPUT\((\w+)\)\s=\st\d+",cur_ins_str)
                        if match_result:
                            x86_stmt_str = x86_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='orange'>" + str(hex(curr_ins_addr)) + ": lea " + match_result.group(3) + ", " + "[" + match_result.group(1) + " + " + match_result.group(2)+"]" +"</FONT>"
                            continue

                        match_result = re.match("\nPUT\((\w+)\)\s=\s(0x\w+)", cur_ins_str)
                        if match_result:
                            x86_stmt_str = x86_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='orange'>" + str(hex(curr_ins_addr)) + ": lea " + match_result.group(1) + ", " + "[" + match_result.group(2)+ "]" + "</FONT>"
                            continue

                        match_result = re.match("\nt\d+\s=\sLDle:I32\((0x\w+)\)\nt\d+\s=\s32Uto64\(t\d+\)\nPUT\((\w+)\)\s=\st\d+", cur_ins_str)
                        if match_result:
                            x86_stmt_str = x86_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='orange'>" + str(
                                hex(curr_ins_addr)) + ": mov " + match_result.group(2) + ", dword ptr " + "[" + match_result.group(1) + "]" + "</FONT>"
                            continue

                        # ------ IMark(0x400cd5, 0, 0) - -----
                        # t7 = LDle:I8(0x00000000006026a0)
                        # t16 = 8Uto32(t7)
                        # t6 = t16
                        # t17 = 32Uto64(t6)
                        # t5 = t17
                        # PUT(rax) = t5
                        # to
                        # movzx rax, byte ptr [0x6026a0]
                        match_result = re.match("\nt\d+\s=\sLDle:I8\((0x\w+)\)\nt\d+\s=\s8Uto32\(t\d+\)\nt\d+\s=\st\d+\nt\d+\s=\s32Uto64\(t\d+\)\nt\d+\s=\st\d+\nPUT\((\w+)\)\s=\st\d+",cur_ins_str)
                        if match_result:
                            x86_stmt_str = x86_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='orange'>" + str(
                                hex(curr_ins_addr)) + ": movzx " + match_result.group(
                                2) + ", byte ptr " + "[" + match_result.group(1) + "]" + "</FONT>"
                            continue


                        # ------ IMark(0x4009e4, 0, 0) - -----
                        # t2 = LDle:I32(0x00000000006010a0)
                        # t1 = 32Sto64(t2)
                        # PUT(rax) = t1
                        # to
                        # movsxd rax, dword ptr [0x00000000006010a0]
                        match_result = re.match("\nt\d+\s=\sLDle:I32\((0x\w+)\)\nt\d+\s=\s32Sto64\(t\d+\)\nPUT\((\w+)\)\s=\st\d+", cur_ins_str)
                        if match_result:
                            x86_stmt_str = x86_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='orange'>" + str(
                                hex(curr_ins_addr)) + ": movsxd " + match_result.group(
                                2) + ", dword ptr " + "[" + match_result.group(1) + "]" + "</FONT>"
                            continue

                        # ------ IMark(0x4009eb, 0, 0) - -----
                        # t5 = GET:I64(rbp)
                        # t2 = Add64(t5, 0x0000000000000140)
                        # t8 = LDle:I8(t2)
                        # t7 = 8Sto32(t8)
                        # t6 = 32Uto64(t7)
                        # PUT(rax) = t6
                        # to
                        # movsx eax, byte ptr [rbp + 0x0000000000000140]
                        match_result = re.match("\nt\d+\s=\sGET:I64\((\w+)\)\nt\d+\s=\sAdd64\(t\d+,(0x\w+)\)\nt\d+\s=\sLDle:I8\(\w+\)\nt\d+\s=\s8Sto32\(t\d+\)\nt\d+\s=\s32Uto64\(t\d+\)\nPUT\((\w+)\)\s=\st\d+", cur_ins_str)
                        if match_result:
                            x86_stmt_str = x86_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='orange'>" + str(
                                hex(curr_ins_addr)) + ": movsx " + match_result.group(3) + ", byte ptr [" + match_result.group(1) + " + " + match_result.group(2)+ "]" + "</FONT>"
                            continue

                        # ------ IMark(0x40092d, 0, 0) - -----
                        # t5 = GET:I64(rbp)
                        # t2 = Add64(t5, 0x0000000000000141)
                        # t6 = GET:I8(dl)
                        # STle(t2) = t6
                        # to
                        # mov byte ptr [rbp + 0x0000000000000141], dl
                        match_result = re.match("\nt\d+\s=\sGET:I64\((\w+)\)\nt\d+\s=\sAdd64\(t\d+,(0x\w+)\)\nt\d+\s=\sGET:I8\((\w+)\)\nSTle\(t\d+\)\s=\s(t\d+)", cur_ins_str)
                        if match_result:
                            x86_stmt_str = x86_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='orange'>" + str(
                                hex(curr_ins_addr)) + ": mov byte ptr " + "[" + match_result.group(1) + " + " + match_result.group(2)+ "], " + match_result.group(3) + "</FONT>"
                            continue


                        # ------ IMark(0x400928, 0, 0) - -----
                        # t31 = LDle:I8(0x00000000006027a0)
                        # t30 = 8Uto32(t31)
                        # t29 = 32Uto64(t30)
                        # PUT(rcx) = t2
                        # to
                        # movzx rcx, byte ptr [0x00000000006027a0]
                        match_result = re.match("\nt\d+\s=\sLDle:I8\((0x\w+)\)\nt\d+\s=\s8Uto32\(t\d+\)\nt\d+\s=\s32Uto64\(t\d+\)\nPUT\((\w+)\)\s=\st\d+",cur_ins_str)
                        if match_result:
                            x86_stmt_str = x86_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='orange'>" + str(
                                hex(curr_ins_addr)) + ": movzx " + match_result.group(
                                2) + ", byte ptr " + "[" + match_result.group(1) + "]" + "</FONT>"
                            continue

                        # # ------ IMark(0x40096c, 0, 0) - -----
                        # # t45 = Add64(t42, 0x00000000006026a0)
                        # # t51 = LDle:I8(t45)
                        # # t50 = 8Uto32(t51)
                        # # t49 = 32Uto64(t50)
                        # # PUT(rcx) = t49
                        # # to
                        # # movzx ecx, byte ptr [0x00000000006026a0]
                        # match_result = re.match("\nt\d+\s=\sAdd64\(t\d+,(0x\w+)\)\nt\d+\s=\sLDle:I8\((0x\w+)\)\nt\d+\s=\s8Uto32\(t\d+\)\nt\d+\s=\s32Uto64\(t\d+\)\nPUT\((\w+)\)\s=\st\d+",cur_ins_str)
                        # if match_result:
                        #     x86_stmt_str = x86_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='orange'>" + str(
                        #         hex(curr_ins_addr)) + ": movzx " + match_result.group(
                        #         3) + ", byte ptr " + "[" + match_result.group(1) + "]" + "</FONT>"
                        #     continue

                        # ------ IMark(0x400939, 0, 0) - -----
                        # t43 = GET:I8(cl)
                        # STle(0x00000000006027a1) = t43
                        # to
                        # mov byte ptr [0x00000000006027a1], cl
                        match_result = re.match("\nt\d+\s=\sGET:I8\((\w+)\)\nSTle\((0x\w+)\)\s=\s(t\d+)", cur_ins_str)
                        if match_result:
                            x86_stmt_str = x86_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='orange'>" + str(
                                hex(curr_ins_addr)) + ": mov " + "byte ptr " + "[" + match_result.group(
                                2) + "], " + match_result.group(1) + "</FONT>"
                            continue

                        match_result = re.match("\nt\d+\s=\sGET:I64\((\w+)\)\nt\d+\s=\s64to32\(t\d+\)\nSTle\((0x\w+)\)\s=\s(t\d+)", cur_ins_str)
                        if match_result:
                            x86_stmt_str = x86_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='orange'>" + str(hex(curr_ins_addr)) + ": mov " + "dword ptr " + "[" + match_result.group(2) + "], " + match_result.group(1)  + "</FONT>"
                            continue

                        # ------ IMark(0x4009cb, 0, 0) - -----
                        # t2 = LDle:I32(0x00000000006010a0)
                        # t0 = Add32(t2, 0x000000f1)
                        # STle(0x00000000006010a0) = t0
                        # to
                        # add dword ptr [0x00000000006010a0], 0x000000f1
                        match_result = re.match("\nt\d+\s=\sLDle:I32\((0x\w+)\)\nt\d+\s=\sAdd32\(t\d+,(0x\w+)\)\nSTle\(0x\w+\)\s=\st\d+", cur_ins_str)
                        if match_result:
                            x86_stmt_str = x86_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='orange'>" + str(
                                hex(curr_ins_addr)) + ": add " + "dword ptr " + "[" + match_result.group(
                                1) + "], " + match_result.group(2) + "</FONT>"
                            continue


                        x86_stmt_str = x86_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='blue'>" + str(original_instructions[original_addresses.index(curr_ins_addr)]).replace("\t", " ") + "</FONT>"


            graphviz_node = A.get_node(str(final_cfg_node))
            graphviz_node.attr["label"] = x86_stmt_str+">"
            graphviz_node.attr["shape"] = "box"

        A.layout(prog="dot")
        A.draw(path=os.path.join(folder_name, "x86_regexd_cfg.svg"), format="svg")
        print("Done")

from angr.analyses import AnalysesHub
AnalysesHub.register_default('VMDeobfuscation', VMDeobfuscation)
