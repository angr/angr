import angr
import logging
import pyvex
import claripy
import networkx as nx
import re
import copy
import os
import pickle
from collections import defaultdict, OrderedDict
from pyvex.stmt import Exit
from angr.code_location import CodeLocation
from angr.analyses.cfg.cfg_job_base import BlockID
from angr.analyses.reaching_definitions.function_handler import FunctionHandler
from angr.analyses.reaching_definitions.subject import Subject
from angr.knowledge_plugins.cfg.cfg_node import CFGENode
from angr.knowledge_plugins.key_definitions.atoms import Tmp, Register, MemoryLocation
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER
from ailment.manager import Manager
from ..reaching_definitions.dep_graph import DepGraph
from ..reaching_definitions.external_codeloc import ExternalCodeLocation
from ..analysis import Analysis
from ..cfg.cfg_vm_deobfuscation import StackPointerAnnotation, StackTouchedAnnotation, DataRegionAnnotation, annotate_with_new_replacements
from ... import BP, BP_BEFORE, BP_AFTER
from ...knowledge_plugins.key_definitions import atoms
from ...engines.light.data import SpOffset
from ...storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from ...knowledge_plugins.key_definitions.undefined import Undefined, UNDEFINED

#logger = logging.getLogger('angr.analyses.cfg.cfg_vm_deobfuscation').setLevel(logging.DEBUG)
#filename = "/media/sf_Security/sample_vm/sample_vm_with_input"
#filename = "/media/sf_Security/sample_vm/a.out"
filename = "/media/sf_Security/sample_vm/simple_vm_set/sample_vm_with_input/samplevm_with_input"
#filename = "/media/sf_Security/sample_vm/simple_vm_set/sample_vm_with_two_input/samplevm_with_two_input"
#filename = "/media/sf_Security/sample_vm/simple_vm_set/sample_vm_with_input_loop/samplevm_with_input_loop"
#filename = "/media/sf_Security/sample_vm/sample_vm_with_input_depend_branch"
#filename="/media/sf_Security/sample_vm/tigress-challenges/Linux-x86_64/0000/challenge-0"

class DataSensitiveU64(pyvex.const.U64):
    def __init__(self, value, block_id):
        super(DataSensitiveU64, self).__init__(value)
        self.block_id = block_id


class DataSensitiveU32(pyvex.const.U32):
    def __init__(self, value, block_id):
        super(DataSensitiveU32, self).__init__(value)
        self.block_id = block_id


class DataSensitiveRdTmp(pyvex.expr.RdTmp):
    def __init__(self, tmp, block_id):
        super(DataSensitiveRdTmp, self).__init__(tmp)
        self.block_id = block_id

class IndSensitiveCodeLocation(CodeLocation):
    def __init__(self, block_addr: int, stmt_idx: int, ins_ind=None, block_id=None, sim_procedure=None, ins_addr=None,
                 context=None, block_idx=None, **kwargs):
        super(IndSensitiveCodeLocation, self).__init__(block_addr, stmt_idx, block_id, sim_procedure, ins_addr,
                 context, block_idx, **kwargs)
        self.ins_ind = ins_ind


class CLibFunctionHandler(FunctionHandler):
    def hook(self, analysis):
        return self

    def handle_local_function(self, state, function_address, call_stack,
                              maximum_local_call_depth, visited_blocks, dep_graph,
                              src_ins_addr=None,
                              codeloc=None):
        executed_rda = True
        return executed_rda, state, visited_blocks, dep_graph

    def handle_external_function_fallback(self, state, codeloc):
        # return address
        sp = state.register_definitions.load(state.arch.sp_offset, state.arch.bytes)
        sp_v = sp.one_value()
        if sp_v is None:
            l.critical('Invalid number of values for stack pointer. Stack is probably unbalanced. This indicates '
                       'serious problems with function handlers. Stack pointer values include: %s.', sp)

        if sp_v is not None and not state.is_top(sp_v):
            stack_offset = state.get_stack_offset(sp_v)
            #sp_addr = state.register_definitions.stack_address(stack_offset)
            atom = MemoryLocation(SpOffset(state.arch.bits,
                                          stack_offset),
                                  sp_v.size())
            state.add_use(atom, codeloc)

            # add use of the rsp
            atom = Register(state.arch.sp_offset, state.arch.bytes)
            state.add_use(atom, codeloc)

            # change stack offset for popped return address
            if isinstance(stack_offset, (int, SpOffset)):
                sp_v -= state.arch.stack_change
            elif isinstance(stack_offset, Undefined):
                pass
            else:
                raise TypeError('Invalid type %s for stack pointer.' % type(stack_offset).__name__)
            atom = Register(state.arch.sp_offset, state.arch.bytes)
            state.kill_and_add_definition(atom, codeloc, MultiValues(offset_to_values={0: {sp_v}}))

            # This handles the function cc
            executed_rda = True
            return executed_rda, state

    def handle_fseek(self, state, codeloc):# this is incomplete
        # return address
        sp = state.register_definitions.load(state.arch.sp_offset, state.arch.bytes)
        sp_v = sp.one_value()
        if sp_v is None:
            l.critical('Invalid number of values for stack pointer. Stack is probably unbalanced. This indicates '
                       'serious problems with function handlers. Stack pointer values include: %s.', sp)

        if sp_v is not None and not state.is_top(sp_v):
            stack_offset = state.get_stack_offset(sp_v)
            #sp_addr = state.register_definitions.stack_address(stack_offset)
            atom = MemoryLocation(SpOffset(state.arch.bits,
                                          stack_offset),
                                  sp_v.size())
            state.add_use(atom, codeloc)

            # add use of the rsp
            atom = Register(state.arch.sp_offset, state.arch.bytes)
            state.add_use(atom, codeloc)

            # change stack offset for popped return address
            if isinstance(stack_offset, (int, SpOffset)):
                sp_v -= state.arch.stack_change
            elif isinstance(stack_offset, Undefined):
                pass
            else:
                raise TypeError('Invalid type %s for stack pointer.' % type(stack_offset).__name__)
            atom = Register(state.arch.sp_offset, state.arch.bytes)
            state.kill_and_add_definition(atom, codeloc, MultiValues(offset_to_values={0: {sp_v}}))

            # This handles the function cc
            executed_rda = True
            return executed_rda, state

    def handle_getchar(self, state, codeloc):
        # return address
        sp = state.register_definitions.load(state.arch.sp_offset, state.arch.bytes)
        sp_v = sp.one_value()
        if sp_v is None:
            l.critical('Invalid number of values for stack pointer. Stack is probably unbalanced. This indicates '
                       'serious problems with function handlers. Stack pointer values include: %s.', sp)

        if sp_v is not None and not state.is_top(sp_v):
            stack_offset = state.get_stack_offset(sp_v)
            #sp_addr = state.register_definitions.stack_address(stack_offset)
            atom = MemoryLocation(SpOffset(state.arch.bits,
                                          stack_offset),
                                  sp_v.size())
            state.add_use(atom, codeloc)

            # add use of the rsp
            atom = Register(state.arch.sp_offset, state.arch.bytes)
            state.add_use(atom, codeloc)

            # change stack offset for popped return address
            if isinstance(stack_offset, (int, SpOffset)):
                sp_v -= state.arch.stack_change
            elif isinstance(stack_offset, Undefined):
                pass
            else:
                raise TypeError('Invalid type %s for stack pointer.' % type(stack_offset).__name__)
            atom = Register(state.arch.sp_offset, state.arch.bytes)
            state.kill_and_add_definition(atom, codeloc, MultiValues(offset_to_values={0: {sp_v}}))

            # This handles the function cc
            executed_rda = True
            return executed_rda, state


        # return value in RAX
        atom = Register(16, 8)
        reg_offset, reg_size = self.arch.registers['rax']
        state.kill_and_add_definition(atom, codeloc, MultiValues(offset_to_values={0: {self.state.top(reg_size * self.arch.byte_width)}}))

        executed_rda = True
        return executed_rda, state

    def handle_free(self, state, codeloc):
        # rdi
        state.add_use(Register(72, 8), codeloc)
        # return address
        sp = state.register_definitions.load(state.arch.sp_offset, state.arch.bytes)
        sp_v = sp.one_value()
        if sp_v is None:
            l.critical('Invalid number of values for stack pointer. Stack is probably unbalanced. This indicates '
                       'serious problems with function handlers. Stack pointer values include: %s.', sp)

        if sp_v is not None and not state.is_top(sp_v):
            stack_offset = state.get_stack_offset(sp_v)
            #sp_addr = state.register_definitions.stack_address(stack_offset)
            atom = MemoryLocation(SpOffset(state.arch.bits,
                                          stack_offset),
                                  sp_v.size())
            state.add_use(atom, codeloc)

            # add use of the rsp
            atom = Register(state.arch.sp_offset, state.arch.bytes)
            state.add_use(atom, codeloc)

            # change stack offset for popped return address
            if isinstance(stack_offset, (int, SpOffset)):
                sp_v -= state.arch.stack_change
            elif isinstance(stack_offset, Undefined):
                pass
            else:
                raise TypeError('Invalid type %s for stack pointer.' % type(stack_offset).__name__)
            atom = Register(state.arch.sp_offset, state.arch.bytes)
            state.kill_and_add_definition(atom, codeloc, MultiValues(offset_to_values={0: {sp_v}}))

            # This handles the function cc
            executed_rda = True
            return executed_rda, state

    def handle_putchar(self, state, codeloc):
        # rdi
        state.add_use(Register(72, 8), codeloc)
        # return address
        sp = state.register_definitions.load(state.arch.sp_offset, state.arch.bytes)
        sp_v = sp.one_value()
        if sp_v is None:
            l.critical('Invalid number of values for stack pointer. Stack is probably unbalanced. This indicates '
                       'serious problems with function handlers. Stack pointer values include: %s.', sp)

        if sp_v is not None and not state.is_top(sp_v):
            stack_offset = state.get_stack_offset(sp_v)
            #sp_addr = state.register_definitions.stack_address(stack_offset)
            atom = MemoryLocation(SpOffset(state.arch.bits,
                                          stack_offset),
                                  sp_v.size())
            state.add_use(atom, codeloc)

            # add use of the rsp
            atom = Register(state.arch.sp_offset, state.arch.bytes)
            state.add_use(atom, codeloc)

            # change stack offset for popped return address
            if isinstance(stack_offset, (int, SpOffset)):
                sp_v -= state.arch.stack_change
            elif isinstance(stack_offset, Undefined):
                pass
            else:
                raise TypeError('Invalid type %s for stack pointer.' % type(stack_offset).__name__)
            atom = Register(state.arch.sp_offset, state.arch.bytes)
            state.kill_and_add_definition(atom, codeloc, MultiValues(offset_to_values={0: {sp_v}}))

            # This handles the function cc
            executed_rda = True
            return executed_rda, state



        # return value in RAX
        atom = Register(16, 8)
        reg_offset, reg_size = self.arch.registers['rax']
        state.kill_and_add_definition(atom, codeloc, MultiValues(offset_to_values={0: {self.state.top(reg_size * self.arch.byte_width)}}))

        executed_rda = True
        return executed_rda, state

    def handle_ptrace(self, state, codeloc):
        # rsi
        state.add_use(Register(64, 8), codeloc)
        # rdi
        state.add_use(Register(72, 8), codeloc)
        # rcx
        state.add_use(Register(24, 8), codeloc)
        # rdx
        state.add_use(Register(32, 8), codeloc)
        # rax
        state.add_use(Register(16, 8), codeloc)

        # return address
        sp = state.register_definitions.load(state.arch.sp_offset, state.arch.bytes)
        sp_v = sp.one_value()
        if sp_v is None:
            l.critical('Invalid number of values for stack pointer. Stack is probably unbalanced. This indicates '
                       'serious problems with function handlers. Stack pointer values include: %s.', sp)

        if sp_v is not None and not state.is_top(sp_v):
            stack_offset = state.get_stack_offset(sp_v)
            #sp_addr = state.register_definitions.stack_address(stack_offset)
            atom = MemoryLocation(SpOffset(state.arch.bits,
                                          stack_offset),
                                  sp_v.size())
            state.add_use(atom, codeloc)

            # add use of the rsp
            atom = Register(state.arch.sp_offset, state.arch.bytes)
            state.add_use(atom, codeloc)

            # change stack offset for popped return address
            if isinstance(stack_offset, (int, SpOffset)):
                sp_v -= state.arch.stack_change
            elif isinstance(stack_offset, Undefined):
                pass
            else:
                raise TypeError('Invalid type %s for stack pointer.' % type(stack_offset).__name__)
            atom = Register(state.arch.sp_offset, state.arch.bytes)
            state.kill_and_add_definition(atom, codeloc, MultiValues(offset_to_values={0: {sp_v}}))

            # This handles the function cc
            executed_rda = True
            return executed_rda, state


    def handle_strcpy(self, state, codeloc):
        # rsi
        state.add_use(Register(64, 8), codeloc)
        # rdi
        state.add_use(Register(72, 8), codeloc)
        # add use of return address
        # return address
        sp = state.register_definitions.load(state.arch.sp_offset, state.arch.bytes)
        sp_v = sp.one_value()
        if sp_v is None:
            l.critical('Invalid number of values for stack pointer. Stack is probably unbalanced. This indicates '
                       'serious problems with function handlers. Stack pointer values include: %s.', sp)

        if sp_v is not None and not state.is_top(sp_v):
            stack_offset = state.get_stack_offset(sp_v)
            #sp_addr = state.register_definitions.stack_address(stack_offset)
            atom = MemoryLocation(SpOffset(state.arch.bits,
                                          stack_offset),
                                  sp_v.size())
            state.add_use(atom, codeloc)

            # add use of the rsp
            atom = Register(state.arch.sp_offset, state.arch.bytes)
            state.add_use(atom, codeloc)

            # change stack offset for popped return address
            if isinstance(stack_offset, (int, SpOffset)):
                sp_v -= state.arch.stack_change
            elif isinstance(stack_offset, Undefined):
                pass
            else:
                raise TypeError('Invalid type %s for stack pointer.' % type(stack_offset).__name__)
            atom = Register(state.arch.sp_offset, state.arch.bytes)
            state.kill_and_add_definition(atom, codeloc, MultiValues(offset_to_values={0: {sp_v}}))

            # This handles the function cc
            executed_rda = True
            return executed_rda, state

    def handle_puts(self, state, codeloc):
        # rdi
        state.add_use(Register(72, 8), codeloc)
        # return address
        sp = state.register_definitions.load(state.arch.sp_offset, state.arch.bytes)
        sp_v = sp.one_value()
        if sp_v is None:
            l.critical('Invalid number of values for stack pointer. Stack is probably unbalanced. This indicates '
                       'serious problems with function handlers. Stack pointer values include: %s.', sp)

        if sp_v is not None and not state.is_top(sp_v):
            stack_offset = state.get_stack_offset(sp_v)
            #sp_addr = state.register_definitions.stack_address(stack_offset)
            atom = MemoryLocation(SpOffset(state.arch.bits,
                                          stack_offset),
                                  sp_v.size())
            state.add_use(atom, codeloc)

            # add use of the rsp
            atom = Register(state.arch.sp_offset, state.arch.bytes)
            state.add_use(atom, codeloc)

            # change stack offset for popped return address
            if isinstance(stack_offset, (int, SpOffset)):
                sp_v -= state.arch.stack_change
            elif isinstance(stack_offset, Undefined):
                pass
            else:
                raise TypeError('Invalid type %s for stack pointer.' % type(stack_offset).__name__)
            atom = Register(state.arch.sp_offset, state.arch.bytes)
            state.kill_and_add_definition(atom, codeloc, MultiValues(offset_to_values={0: {sp_v}}))

            # This handles the function cc
            executed_rda = True
            return executed_rda, state


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


class VMDeobfuscation(Analysis):

    def __init__(self, vm_vpc_addr, start_addr=None, start_state=None, cfg_fast_graph=None, avoid_runs=None, vm_start_addr=None, verification_input=None, remove_insts=None):

        # This is the address of the node where the virtual machine implementation starts
        self.vm_start_addr = vm_start_addr
        self.start_addr = start_addr
        self.vm_vpc_addr = vm_vpc_addr
        cfg, proj = self.data_sensitive_graph(self.project.filename, vm_vpc_addr, start_addr=start_addr, start_state=start_state, cfg_fast_graph=cfg_fast_graph, avoid_runs=avoid_runs)
        folder_name = os.path.dirname(self.project.filename)
        self.draw_graph(cfg, os.path.join(folder_name, "input.svg"))

        # removing path terminators, cause...............they causing problems
        cfg = self.new_model_without_terminator_graph(cfg.graph, proj, 'without_path_terminator')

        cfg = self.convert_to_data_sensitive_irsb(cfg, proj, start_state)

        self.draw_graph(cfg, os.path.join(folder_name, "input.svg"))

        cfg = self.remove_troublesome_instructions(cfg, proj, start_state, remove_insts)

        # all_functions = []
        # for node in cfg.model.nodes():
        #     if not node.is_simprocedure:
        #         if node.irsb.jumpkind == "Ijk_Call":
        #             succs = cfg.model.get_successors(node)
        #             if len(succs) == 1:
        #                 if not succs[0].is_simprocedure:
        #                     all_functions.append(succs[0])
        #             else:
        #                 raise Exception("More than one successor for a call statement? hmmm.........")

        self.vm_instruction_addrs = cfg.vm_instruction_addresses
        initial_cfg = cfg
        print("Doing constant propagation")
        new_cfg = self.constant_propagation(cfg, proj, start_addr=start_addr, vm_vpc_addr=vm_vpc_addr, start_state=start_state)
        self.draw_graph(new_cfg, os.path.join(folder_name, "cp_result.svg"))

        # this is to remove those vex jump insts that will always to the same location. This is after the data sensitive analysis
        new_cfg = self.remove_useless_jump_instructions(new_cfg, proj, start_addr, vm_vpc_addr, start_state, initial_cfg)

        # DCE commented out temporarily to make testing faster for block simplifications
        changed = True
        i = 0
        while changed and i < 11:
            i = i+1
            new_cfg, changed = self.dead_code_elimination(new_cfg, proj, start_addr=start_addr, vm_vpc_addr=vm_vpc_addr, start_state=start_state)
            self.draw_graph(new_cfg, os.path.join(folder_name, str(i)+"_dce_result.svg"))
        self.draw_graph(new_cfg, os.path.join(folder_name, "DCE_result.svg"))

        # Commenting block arithmetic simps because it fuks up the order of VEX insts e.g. btc, btr
        for i in range(2):
            new_cfg = self.block_arithmetic_simplifications(new_cfg, proj, start_state=start_state)
        self.draw_graph(new_cfg, os.path.join(folder_name, "block_arithmetic_simplifications.svg"))

        new_cfg = self._eliminate_dead_assignments(new_cfg, proj, start_state=start_state)
        self.draw_graph(new_cfg, os.path.join("dae_2_result.svg"))

        new_cfg = self.testing_new_improved_whole_vm_RDA_deadassignment_elimination(new_cfg, proj, start_state=start_state)
        self.draw_graph(new_cfg, os.path.join(folder_name, "whole_cfg_deadassignment_elimination.svg"))

                # commented this for test_vmp to show the add eax,1 result
        for i in range(4):
            new_cfg = self.join_basic_blocks(new_cfg, proj, start_addr=start_addr, vm_vpc_addr=vm_vpc_addr, start_state=start_state)
        self.draw_graph(new_cfg, os.path.join(folder_name, "join_basic_blocks.svg"))

        # self.simplifications(new_cfg, proj, start_addr=start_addr, vm_vpc_addr=vm_vpc_addr)
        # Need to copy the arith simplifications back to the node.irsb, for below
        new_cfg = self._eliminate_dead_assignments(new_cfg, proj, start_state=start_state)
        self.draw_graph(new_cfg, os.path.join("dae_1_result.svg"))

        ## Simplification to remove btc, bt, bts instructions..................... useless stuff because of the way VEX implements it
        new_cfg = self.remove_vex_bs(new_cfg, proj, start_addr, vm_vpc_addr, start_state, initial_cfg)
        self.draw_graph(new_cfg, os.path.join(folder_name, "removed_vex_btc_insts.svg"))


        # DCE again to remove the temp variables remaining after dead assignment elimination, should I just do this along with DSA(being lazy is what it is)
        changed = True
        i = 0
        while changed and i < 11:
            i=i+1
            print("DCE round "+str(i))
            new_cfg, changed = self.dead_code_elimination(new_cfg, proj, start_addr=start_addr, vm_vpc_addr=vm_vpc_addr, start_state=start_state)
            self.draw_graph(new_cfg, os.path.join(folder_name, str(i)+"_dce_result.svg"))

        # Commenting remove redun store load simps because it fuks up the order of VEX insts e.g. btc, btr
        new_cfg = self.remove_redundant_store_load(new_cfg, proj, start_state=start_state)
        self.draw_graph(new_cfg, os.path.join(folder_name, "debug_2_result.svg"))
        changed = True
        i = 0
        while changed and i < 3:
            i=i+1
            print("DCE round "+str(i))
            new_cfg, changed = self.dead_code_elimination(new_cfg, proj, start_addr=start_addr, vm_vpc_addr=vm_vpc_addr, start_state=start_state)
        self.draw_graph(new_cfg, os.path.join(folder_name, "debug_3_result.svg"))
        new_cfg = self._eliminate_dead_assignments(new_cfg, proj, start_state=start_state)
        self.draw_graph(new_cfg, os.path.join(folder_name, "debug_1_result.svg"))
        new_cfg = self.remove_redundant_assignment(new_cfg, proj, start_state=start_state)
        self.draw_graph(new_cfg, os.path.join(folder_name, "redun_store_load.svg"))
        changed = True
        i = 0
        while changed and i < 4:
            i=i+1
            print("DCE round "+str(i))
            new_cfg, changed = self.dead_code_elimination(new_cfg, proj, start_addr=start_addr, vm_vpc_addr=vm_vpc_addr, start_state=start_state)

        for i in range(10):
            new_cfg = self.block_arithmetic_simplifications(new_cfg, proj, start_state=start_state)
            self.draw_graph(new_cfg, os.path.join(folder_name, str(i)+"_block_arithmetic_simplifications.svg"))

        changed = True
        i = 0
        while changed and i < 10:
            i=i+1
            print("DCE round "+str(i))
            new_cfg, changed = self.dead_code_elimination(new_cfg, proj, start_addr=start_addr, vm_vpc_addr=vm_vpc_addr, start_state=start_state)
            self.draw_graph(new_cfg, os.path.join(folder_name, str(i) + "final_dce_result.svg"))

        for i in range(10, 15):
            new_cfg = self.block_arithmetic_simplifications(new_cfg, proj, start_state=start_state)
            self.draw_graph(new_cfg, os.path.join(folder_name, str(i)+"_block_arithmetic_simplifications.svg"))


        self.perform_semantic_verification(new_cfg, proj, start_state=start_state, start_addr=start_addr, input=verification_input)

        self.draw_graph(new_cfg, os.path.join(folder_name,  "final_result.svg"))
        self.draw_original_graph(new_cfg, os.path.join(folder_name, "comparision_graph.svg"), proj)
        self.compare_vex(initial_cfg, new_cfg, folder_name)
        self.pattern_match_to_x86_instructions(new_cfg, cfg, proj, folder_name)

    def remove_troublesome_instructions(self, cfg, proj, start_state, remove_insts):
        new_model = self.new_model_graph(cfg.graph, proj, 'remove_trouble_insts')
        for node in list(new_model.graph.nodes()):
            if node.is_simprocedure:
                continue

            to_remove_stmt_idxs = []
            add_to_list = 0
            replace_stmt_map = {}
            for ind, stmt in enumerate(node.irsb.statements):
                if isinstance(stmt, pyvex.stmt.IMark) and stmt.addr in remove_insts:
                    add_to_list = 1
                elif isinstance(stmt, pyvex.stmt.IMark) and stmt.addr not in remove_insts:
                    add_to_list = 0

                if add_to_list == 1:
                    if isinstance(stmt, pyvex.stmt.WrTmp):
                        import ipdb;ipdb.set_trace()
                        replace_stmt_map[ind] = pyvex.stmt.WrTmp(stmt.tmp, pyvex.expr.RdTmp(stmt.data.args[0].tmp))
                    to_remove_stmt_idxs.append(ind)


            new_statements = []
            for idx, stmt in enumerate(node.irsb.statements):
                if idx in to_remove_stmt_idxs:
                    if idx in replace_stmt_map:
                        new_statements.append(replace_stmt_map[idx])
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
        new_model._nodes_by_addr[self.start_addr][0].input_state = initial_input_state
        new_cfg = proj.analyses.CFGVMDeobfuscation(model=new_model, keep_state=True, iropt_level=1,
                                                   resolve_indirect_jumps=True, max_iterations=1,
                                                   vm_vpc_addr=self.vm_vpc_addr)

        return new_cfg

    # this is to remove those vex jump insts that will always to the same location. This is after the data sensitive analysis
    def remove_useless_jump_instructions(self, cfg, proj, start_addr, vm_vpc_addr, start_state, orig_cfg):
        new_model = self.new_model_graph(cfg.graph, proj, 'remove_useless_jumps')

        for node in list(new_model.graph.nodes()):
            if node.is_simprocedure:
                continue

            if len(list(new_model.graph.successors(node))) == 1 and isinstance(node.irsb.statements[-1], pyvex.stmt.Exit):
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

        if start_state:
            initial_input_state = start_state
        else:
            initial_input_state = proj.factory.blank_state(addr=self.start_addr,
                                                           mode='fastpath',
                                                           add_options=angr.sim_options.refs | {
                                                               angr.sim_options.REPLACEMENT_SOLVER,
                                                               angr.sim_options.DO_CCALLS})
        new_model._nodes_by_addr[self.start_addr][0].input_state = initial_input_state
        new_cfg = proj.analyses.CFGVMDeobfuscation(model=new_model, keep_state=True, iropt_level=1,
                                                   resolve_indirect_jumps=True, max_iterations=1,
                                                   vm_vpc_addr=self.vm_vpc_addr)
        return new_cfg


    # remove the unnecessary obfuscation added by VEX for the bts, bt and btc instructions
    def remove_vex_bs(self, cfg, proj, start_addr, vm_vpc_addr, start_state, orig_cfg):
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
        new_model._nodes_by_addr[self.start_addr][0].input_state = initial_input_state
        new_cfg = proj.analyses.CFGVMDeobfuscation(model=new_model, keep_state=True, iropt_level=1,
                                                   resolve_indirect_jumps=True, max_iterations=1,
                                                   vm_vpc_addr=self.vm_vpc_addr)
        return new_cfg


    def join_basic_blocks(self, cfg, proj, start_addr, vm_vpc_addr, start_state):
        new_model = self.new_model_graph(cfg.graph, proj, 'join_basic_blocks')

        for node in list(new_model.graph.nodes()):
            # This is to check if the node was deleted or not
            if node in new_model.graph.nodes():
                if not node.is_simprocedure and len(list(new_model.graph.successors(node))) == 1:
                    if node.irsb.jumpkind in ['Ijk_Call', 'Ijk_Ret']:
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
                        for stmt in succ.irsb.statements:
                            if isinstance(stmt, pyvex.stmt.WrTmp):
                                tmps_used_succ_block.append(stmt.tmp)

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

                            if not isinstance(stmt, pyvex.stmt.IMark):
                                for rd_tmp in tmp_replace_map:
                                    for expr in stmt.expressions:
                                        if expr == rd_tmp:
                                            stmt.replace_expression(expr, tmp_replace_map[rd_tmp])
                            new_stmts.append(stmt)

                        #convert types dict to list, with 'None' str for the missing tmps
                        new_types_list = []
                        for i in range(max(new_types.keys())+1):
                            if i in new_types:
                                new_types_list.append(new_types[i])
                            else:
                                new_types_list.append("tmp removed")

                        node.irsb = pyvex.IRSB.empty_block(node.irsb.arch,
                                                          node.irsb.addr,
                                                          statements=new_stmts,
                                                          tyenv=pyvex.block.IRTypeEnv(node.irsb.arch,types=new_types_list),
                                                          nxt=succ.irsb.next,
                                                          direct_next=succ.irsb.direct_next,
                                                          jumpkind=succ.irsb.jumpkind,
                                                          size=node.irsb.size+succ.irsb.size)

                        for succ_of_succ in new_model.graph.successors(succ):
                            edge_data = cfg.graph.get_edge_data(node, succ)
                            new_model.graph.add_edge(node, succ_of_succ, jumpkind=edge_data['jumpkind'])
                        new_model.graph.remove_node(succ)

        if start_state:
            initial_input_state = start_state
        else:
            initial_input_state = proj.factory.blank_state(addr=self.start_addr,
                                                           mode='fastpath',
                                                           add_options=angr.sim_options.refs | {
                                                               angr.sim_options.REPLACEMENT_SOLVER,
                                                               angr.sim_options.DO_CCALLS})
        new_model._nodes_by_addr[self.start_addr][0].input_state = initial_input_state
        new_cfg = proj.analyses.CFGVMDeobfuscation(model=new_model, keep_state=True, iropt_level=1,
                                                   resolve_indirect_jumps=True, max_iterations=1,
                                                   vm_vpc_addr=self.vm_vpc_addr)

        return new_cfg

    def convert_to_data_sensitive_irsb(self, cfg, proj, start_state):
        new_model = self.new_model_graph(cfg.graph, proj, 'data_sensitive_irsb')
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
                else:
                    block_id_for_next = succs[0].block_id

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

        if start_state:
            initial_input_state = start_state
        else:
            initial_input_state = proj.factory.blank_state(addr=self.start_addr,
                                                           mode='fastpath',
                                                           add_options=angr.sim_options.refs | {
                                                               angr.sim_options.REPLACEMENT_SOLVER,
                                                               angr.sim_options.DO_CCALLS})
        new_model._nodes_by_addr[self.start_addr][0].input_state = initial_input_state
        new_cfg = proj.analyses.CFGVMDeobfuscation(model=new_model, keep_state=True, iropt_level=1,
                                                   resolve_indirect_jumps=True, max_iterations=1,
                                                   vm_vpc_addr=self.vm_vpc_addr)


        return new_cfg

    def perform_semantic_verification(self, cfg, proj, start_state=None, start_addr=None, input=None):
        new_model = self.new_model_graph(cfg.graph, proj, 'semantic_verification')
        chroot = start_state.fs._mountpoints[b"/"].host_path
        # flag = claripy.BVV(b'X-MAS{VMs_ar3_c00l_aNd_1nt3resting}\n')
        # new_model._nodes_by_addr[self.start_addr][0].input_state = proj.factory.blank_state(addr=start_addr, add_options={angr.sim_options.REPLACEMENT_SOLVER, angr.sim_options.DO_CCALLS},
        #                                concrete_fs=True, chroot="/media/sf_PhD/simple_vm_set/sample_vm_x-mas-ctf", stdin=flag)
        # flag = claripy.BVV(b'09a71bf084a93df7ce3def3ab1bd61f6\n')
        # new_model._nodes_by_addr[self.start_addr][0].input_state = proj.factory.blank_state(addr=start_addr, add_options={angr.sim_options.REPLACEMENT_SOLVER, angr.sim_options.DO_CCALLS},
        #                                concrete_fs=True, chroot="/media/sf_PhD/simple_vm_set/simple_vm_RCTF2018/", stdin=flag)
        # flag = claripy.BVV(b'5\n')
        # new_model._nodes_by_addr[self.start_addr][0].input_state = proj.factory.blank_state(addr=start_addr, add_options={angr.sim_options.REPLACEMENT_SOLVER, angr.sim_options.DO_CCALLS},
        #                                concrete_fs=True, chroot="/media/sf_PhD/tigress_tests", stdin=flag)
        new_model._nodes_by_addr[self.start_addr][0].input_state = proj.factory.blank_state(addr=start_addr, add_options={angr.sim_options.REPLACEMENT_SOLVER, angr.sim_options.DO_CCALLS},
                                        concrete_fs=True, chroot=chroot, stdin=input)

        new_cfg = proj.analyses.CFGConcreteExecution(model=new_model, keep_state=True, iropt_level=1,
                                                   resolve_indirect_jumps=True)

        for node in new_cfg.graph.nodes():
            succs = new_cfg.model.get_successors(node)
            if len(succs) == 0:
                final_state = node.input_state
                print(node)
                print(final_state.posix.dumps(1))


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

            print(left_arg_atom)
            print(right_arg_atom)

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

    def remove_redundant_assignment(self, cfg, proj, start_state=None):
        # This looks like
        # t33 = t27
        # e.g. resulting after the `remove_redundant_store_load` simplification
        dsa_new_model = self.new_model_graph(cfg.graph, proj, 'redun_assignment')
        for node in dsa_new_model.nodes():
            if node.addr == self.vm_start_addr:
                start_node = node
                break

        for node in dsa_new_model.nodes():
            if node.is_simprocedure:
                continue

            tmp_replace_dict = {}
            new_statements = []
            for stmt in node.irsb.statements:
                if isinstance(stmt, pyvex.stmt.WrTmp) and isinstance(stmt.data, pyvex.expr.RdTmp):
                    to_be_replaced_with = stmt.data
                    while to_be_replaced_with in tmp_replace_dict:
                        # This is for the recursive replacements
                        to_be_replaced_with = tmp_replace_dict[stmt.data]
                    tmp_replace_dict[pyvex.expr.RdTmp(stmt.tmp)] = to_be_replaced_with
                    continue
                else:
                    if not isinstance(stmt, pyvex.stmt.IMark):
                        for tmp in tmp_replace_dict:
                            for expr in stmt.expressions:
                                if expr == tmp:
                                    stmt.replace_expression(expr, tmp_replace_dict[tmp])
                new_statements.append(stmt)

            node.irsb = pyvex.IRSB.empty_block(node.irsb.arch,
                                               node.irsb.addr,
                                               statements=new_statements,
                                               tyenv=node.irsb.tyenv,
                                               nxt=node.irsb.next,
                                               direct_next=node.irsb.direct_next,
                                               jumpkind=node.irsb.jumpkind,
                                               size=node.irsb.size)

        # Returning a new CFGVMDeobfuscation object with the updated graph
        if start_state:
            initial_input_state = start_state
        else:
            initial_input_state = proj.factory.blank_state(addr=self.start_addr,
                                                           mode='fastpath',
                                                           add_options=angr.sim_options.refs | {
                                                               angr.sim_options.REPLACEMENT_SOLVER,
                                                               angr.sim_options.DO_CCALLS})
        dsa_new_model._nodes_by_addr[self.start_addr][0].input_state = initial_input_state
        new_cfg = proj.analyses.CFGVMDeobfuscation(model=dsa_new_model, keep_state=True, iropt_level=1,
                                                   resolve_indirect_jumps=True, max_iterations=1,
                                                   vm_vpc_addr=self.vm_vpc_addr)
        return new_cfg

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


        dsa_new_model = self.new_model_graph(cfg.graph, proj, 'redun_store_load')
        for node in dsa_new_model.nodes():
            if node.addr == self.vm_start_addr:
                start_node = node
                break

        for node in dsa_new_model.nodes():
            if node.is_simprocedure:
                continue
            cur_block = angr.Block(node.irsb.addr, project=proj, vex=node.irsb)
            rd = self.project.analyses.ReachingDefinitions(cur_block,
                                                           track_tmps=True,
                                                           function_handler=CLibFunctionHandler(),
                                                           observation_points=[('node', node.addr, OP_AFTER)]
                                                           )

            # Find redundant loads
            replace_stle_dict = {}
            all_defs = rd.all_definitions
            for d in all_defs:
                if isinstance(d.codeloc, ExternalCodeLocation) or d.dummy:
                    continue
                uses = rd.all_uses.get_uses(d)

                if isinstance(d.atom, atoms.MemoryLocation) and isinstance(d.atom.addr, SpOffset):
                    for use in uses:
                        # if d.codeloc.ins_addr == 0x6f98b3:
                        #     import ipdb;ipdb.set_trace()
                        if not use.sim_procedure and isinstance(node.irsb.statements[use.stmt_idx].data, pyvex.expr.Load):
                            ## making sure the the Load is loading the entire stored value and not e.g. 1 byte of it, in which case we should not remove it THIS MIGHT BE AN ISSUE I NEED TO FIX IN THE FUTURE
                            if self.project.arch.bits == 64 and node.irsb.statements[use.stmt_idx].data.ty == 'Ity_I64' and d.atom.size == 8:
                                replace_stle_dict[use.stmt_idx] = node.irsb.statements[d.codeloc.stmt_idx].data
                            elif self.project.arch.bits == 32 and node.irsb.statements[use.stmt_idx].data.ty == 'Ity_I32' and d.atom.size == 4:
                                replace_stle_dict[use.stmt_idx] = node.irsb.statements[d.codeloc.stmt_idx].data


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

        # Returning a new CFGVMDeobfuscation object with the updated graph
        if start_state:
            initial_input_state = start_state
        else:
            initial_input_state = proj.factory.blank_state(addr=self.start_addr,
                                                           mode='fastpath',
                                                           add_options=angr.sim_options.refs | {
                                                               angr.sim_options.REPLACEMENT_SOLVER,
                                                               angr.sim_options.DO_CCALLS})
        dsa_new_model._nodes_by_addr[self.start_addr][0].input_state = initial_input_state
        new_cfg = proj.analyses.CFGVMDeobfuscation(model=dsa_new_model, keep_state=True, iropt_level=1,
                                                   resolve_indirect_jumps=True, max_iterations=1,
                                                   vm_vpc_addr=self.vm_vpc_addr)
        return new_cfg



# Eliminated dead stack-memdefs and regdefs in the whoel CFG
    def testing_whole_vm_RDA_deadassignment_elimination(self, cfg, proj, start_state=None):
        dsa_new_model = self.new_model_graph(cfg.graph, proj, 'test_rda_dae')
        #start_state = ReachingDefinitionsState()
        for node in dsa_new_model.nodes():
            if node.addr == self.vm_start_addr:
                start_node = node
                break

        rd = self.project.analyses.ReachingDefinitions(subject=Subject((dsa_new_model.graph, start_node)),
                                                       track_tmps=True,
                                                       function_handler=CLibFunctionHandler(),
                                                       max_iterations=3
                                                       )

        # Find dead assignments
        dead_defs_locs = set()
        all_defs = rd.all_definitions

        # There can be multiple memory definitions for the same location with different stack offset because of rd_state merging
        for d in all_defs:
            if isinstance(d.codeloc, ExternalCodeLocation) or d.dummy:
                continue

            #### Looking for def-use that look like => Stle(addr).... LDle(addr), removed defs that Look like STle(addr).....Put(rax)=addr because it was causing some incomplete elimination in (discount VM)0x400587
            if isinstance(d.atom, atoms.MemoryLocation):
                uses = rd.all_uses.get_uses(d)
                no_uses = 0
                for use in uses:
                    # making sure we only count the uses that are Loads, not just any variable having that memory adddress
                    if isinstance(cfg.model.get_node(use.block_id).irsb.statements[use.stmt_idx], pyvex.stmt.WrTmp):
                        if isinstance(cfg.model.get_node(use.block_id).irsb.statements[use.stmt_idx].data, pyvex.expr.Load):
                            no_uses = no_uses + 1
                if no_uses == 0 and d.atom.is_on_stack:
                    print(d)
                    print(cfg.model.get_node(d.codeloc.block_id).irsb.pp())
                    if d.codeloc.ins_addr in [0x6cbf81]:#0x6A5681, 0x6B4756]:
                        import ipdb;ipdb.set_trace()
                    dead_defs_locs.add(d.codeloc)
                elif d.codeloc.ins_addr in [0x6cbf81]:
                    import ipdb;ipdb.set_trace()


#        Remove dead assignments
        for node in dsa_new_model.nodes():
            new_statements = []
            if not node.is_simprocedure:
                print(node.irsb.pp())
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
                for idx, stmt in enumerate(new_statements):
                    print(f'{idx}, {stmt}')

                node.irsb = pyvex.IRSB.empty_block(node.irsb.arch,
                                                   node.irsb.addr,
                                                   statements=new_statements,
                                                   tyenv=node.irsb.tyenv,
                                                   nxt=node.irsb.next,
                                                   direct_next=node.irsb.direct_next,
                                                   jumpkind=node.irsb.jumpkind,
                                                   size=node.irsb.size)

            # Returning a new CFGVMDeobfuscation object with the updated graph
        if start_state:
            initial_input_state = start_state
        else:
            initial_input_state = proj.factory.blank_state(addr=self.start_addr,
                                                           mode='fastpath',
                                                           add_options=angr.sim_options.refs | {
                                                               angr.sim_options.REPLACEMENT_SOLVER,
                                                               angr.sim_options.DO_CCALLS})
        dsa_new_model._nodes_by_addr[self.start_addr][0].input_state = initial_input_state
        new_cfg = proj.analyses.CFGVMDeobfuscation(model=dsa_new_model, keep_state=True, iropt_level=1,
                                                   resolve_indirect_jumps=True, max_iterations=1,
                                                   vm_vpc_addr=self.vm_vpc_addr)
        return new_cfg

    def testing_new_improved_whole_vm_RDA_deadassignment_elimination(self, cfg, proj, start_state=None):
        dsa_new_model = self.new_model_graph(cfg.graph, proj, 'test_rda_dae')
        # start_state = ReachingDefinitionsState()
        for node in dsa_new_model.nodes():
            if node.addr == self.vm_start_addr:
                start_node = node
                break

        last_node = None
        for node in list(dsa_new_model.graph.nodes()):
            if not node.is_simprocedure and len(list(dsa_new_model.graph.successors(node))) == 0:
                last_node = node

        rd = self.project.analyses.ReachingDefinitions(subject=Subject((dsa_new_model.graph, start_node)),
                                                       track_tmps=True,
                                                       function_handler=CLibFunctionHandler(),
                                                       max_iterations=3,
                                                       observation_points=[('node', last_node.addr, OP_AFTER)]
                                                       )

        live_defs = rd.one_result

        # Find dead assignments
        dead_defs_locs = set()
        all_defs = rd.all_definitions

        # There can be multiple memory definitions for the same location with different stack offset because of rd_state merging
        for d in all_defs:
            if isinstance(d.codeloc, ExternalCodeLocation) or d.dummy:
                continue

            uses = rd.all_uses.get_uses(d)
            vs = None
            if isinstance(d.atom, atoms.MemoryLocation):
                no_uses = 0
                for use in uses:
                    # making sure we only count the uses that are Loads, not just any variable having that memory adddress
                    if isinstance(cfg.model.get_node(use.block_id).irsb.statements[use.stmt_idx], pyvex.stmt.WrTmp):
                        if isinstance(cfg.model.get_node(use.block_id).irsb.statements[use.stmt_idx].data,
                                      pyvex.expr.Load):
                            no_uses = no_uses + 1

                if no_uses == 0 and d.atom.is_on_stack:
                    stack_addr = live_defs.stack_offset_to_stack_addr(d.atom.addr.offset)
                    vs: 'MultiValues' = live_defs.stack_definitions.load(stack_addr, size=d.atom.size,
                                                                         endness=d.atom.endness)

            # is entirely possible that at the end of the block, a register definition is not used.
            # however, it might be used in future blocks.
            # so we only remove a definition if the definition is not alive anymore at the end of the block
            elif isinstance(d.atom, atoms.Register) and not uses:
                vs: 'MultiValues' = live_defs.register_definitions.load(d.atom.reg_offset, size=d.atom.size)
            else:
                continue
            if vs is None:
                continue
            defs_ = set()

            for values in vs.values.values():
                for value in values:
                    defs_.update(live_defs.extract_defs(value))

            if d not in defs_:
                dead_defs_locs.add(d.codeloc)


        #Remove dead assignments
        for node in dsa_new_model.nodes():
            new_statements = []
            if not node.is_simprocedure:
                print(node.irsb.pp())
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
                for idx, stmt in enumerate(new_statements):
                    print(f'{idx}, {stmt}')

                node.irsb = pyvex.IRSB.empty_block(node.irsb.arch,
                                                   node.irsb.addr,
                                                   statements=new_statements,
                                                   tyenv=node.irsb.tyenv,
                                                   nxt=node.irsb.next,
                                                   direct_next=node.irsb.direct_next,
                                                   jumpkind=node.irsb.jumpkind,
                                                   size=node.irsb.size)

            # Returning a new CFGVMDeobfuscation object with the updated graph
        if start_state:
            initial_input_state = start_state
        else:
            initial_input_state = proj.factory.blank_state(addr=self.start_addr,
                                                           mode='fastpath',
                                                           add_options=angr.sim_options.refs | {
                                                               angr.sim_options.REPLACEMENT_SOLVER,
                                                               angr.sim_options.DO_CCALLS})
        dsa_new_model._nodes_by_addr[self.start_addr][0].input_state = initial_input_state
        new_cfg = proj.analyses.CFGVMDeobfuscation(model=dsa_new_model, keep_state=True, iropt_level=1,
                                                   resolve_indirect_jumps=True, max_iterations=1,
                                                   vm_vpc_addr=self.vm_vpc_addr)
        return new_cfg

    # Eliminates dead memdefs, tmpdefs and regdefs in a single basic block
    def _eliminate_dead_assignments(self, cfg, proj, start_state=None):

        dsa_new_model = self.new_model_graph(cfg.graph, proj, 'dae')
        for node in dsa_new_model.nodes():
            if node.addr == self.vm_start_addr:
                start_node = node
                break

        for node in dsa_new_model.nodes():
            if node.is_simprocedure:
                continue
            cur_block = angr.Block(node.irsb.addr, project=proj, vex=node.irsb)
            rd = self.project.analyses.ReachingDefinitions(cur_block,
                                                           track_tmps=True,
                                                           function_handler=CLibFunctionHandler(),
                                                           observation_points=[('node', node.addr, OP_AFTER)]
                                                           )

            used_tmp_indices = set(rd.one_result.tmp_uses.keys())
            live_defs = rd.one_result

            # Find dead assignments
            dead_defs_stmt_idx = set()
            all_defs = rd.all_definitions
            for d in all_defs:
                if isinstance(d.codeloc, ExternalCodeLocation) or d.dummy:
                    continue

                if isinstance(d.atom, atoms.Tmp):
                    uses = live_defs.tmp_uses[d.atom.tmp_idx]
                    if not uses:
                        dead_defs_stmt_idx.add(d.codeloc.stmt_idx)
                else:
                    uses = rd.all_uses.get_uses(d)
                    if not uses:
                        # is entirely possible that at the end of the block, a register definition is not used.
                        # however, it might be used in future blocks.
                        # so we only remove a definition if the definition is not alive anymore at the end of the block
                        defs_ = set()
                        if isinstance(d.atom, atoms.Register):
                            vs: 'MultiValues' = live_defs.register_definitions.load(d.atom.reg_offset, size=d.atom.size)
                        elif isinstance(d.atom, atoms.MemoryLocation):
                            stack_addr = live_defs.stack_offset_to_stack_addr(d.atom.addr.offset)
                            vs: 'MultiValues' = live_defs.stack_definitions.load(stack_addr, size=d.atom.size,
                                                                                 endness=d.atom.endness)
                        else:
                            continue

                        for values in vs.values.values():
                            for value in values:
                                defs_.update(live_defs.extract_defs(value))

                        if d not in defs_:
                            dead_defs_stmt_idx.add(d.codeloc.stmt_idx)

            new_statements = []
            # Remove dead assignments
            for idx, stmt in enumerate(cur_block.vex.statements):
                if isinstance(stmt, pyvex.stmt.WrTmp):
                    if stmt.tmp not in used_tmp_indices:
                        continue

                # is it a dead virgin?
                if idx in dead_defs_stmt_idx:
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

        # Returning a new CFGVMDeobfuscation object with the updated graph
        if start_state:
            initial_input_state = start_state
        else:
            initial_input_state = proj.factory.blank_state(addr=self.start_addr,
                                                           mode='fastpath',
                                                           add_options=angr.sim_options.refs | {
                                                               angr.sim_options.REPLACEMENT_SOLVER,
                                                               angr.sim_options.DO_CCALLS})
        dsa_new_model._nodes_by_addr[self.start_addr][0].input_state = initial_input_state
        new_cfg = proj.analyses.CFGVMDeobfuscation(model=dsa_new_model, keep_state=True, iropt_level=1,
                                                   resolve_indirect_jumps=True, max_iterations=1,
                                                   vm_vpc_addr=self.vm_vpc_addr)
        return new_cfg
    def find_index_of_IMark(self, imark_addr, statements, stmt_idx):
        imark_ind = None
        min_gap = len(statements)+1
        for ind, cur_stmt in enumerate(statements):
            if isinstance(cur_stmt, pyvex.stmt.IMark) and cur_stmt.addr == imark_addr:
                if 0 < stmt_idx - ind < min_gap:
                    imark_ind = ind
        return imark_ind
    def block_arithmetic_simplifications(self, cfg, proj, start_state=None):
        # Naming this this CFGEmulated so that certain other analysis can uses the results from this
        new_model = self.new_model_graph(cfg.graph, proj, 'CFGEmulated')

        for node in list(new_model.nodes()):
            if not node.is_simprocedure:
                cur_block = angr.Block(node.irsb.addr, project=proj, vex=node.irsb)
                result = proj.analyses.ReachingDefinitions(cur_block, track_tmps=True, observe_all=True, dep_graph=DepGraph())

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
                        for use in result.all_uses_by_code_loc[code_loc]:
                            use_stmt = node.irsb.statements[use.codeloc.stmt_idx]
                            tmp_atom = self.convert_to_atom(use_stmt, node.irsb.tyenv, node.irsb.arch.byte_width)
                            if isinstance(use.codeloc, ExternalCodeLocation):
                                use_node = StatementNode(None, use.codeloc, def_atom=use.atom)
                            else:
                                imark_ins_ind = self.find_index_of_IMark(use.codeloc.ins_addr, node.irsb.statements,
                                                                         use.codeloc.stmt_idx)
                                new_ins_ind_sens_codeloc = IndSensitiveCodeLocation(use.codeloc.block_addr,
                                                                                    use.codeloc.stmt_idx,
                                                                                    ins_addr=use.codeloc.ins_addr,
                                                                                    ins_ind=imark_ins_ind)
                                use_node = StatementNode(use_stmt, new_ins_ind_sens_codeloc, def_atom=tmp_atom)
                            stmt_atom = self.convert_to_atom(stmt, node.irsb.tyenv, node.irsb.arch.byte_width)
                            stmt_node = StatementNode(stmt, ins_ind_sens_code_loc, def_atom=stmt_atom)
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
                conn_comps = nx.weakly_connected_components(stmt_graph.graph)
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
                new_address_map = {}
                for sub_graph in sub_graphs:
                    to_simplify_sub_graph = nx.DiGraph(copy.deepcopy(sub_graph.graph))
                    stmt_node_queue = []
                    for stmt_node in to_simplify_sub_graph.nodes():
                        if to_simplify_sub_graph.out_degree(stmt_node) == 0:
                            stmt_node_queue.append(stmt_node)
                            print(stmt_node)

                    visited_stmt_nodes = {}
                    simplified_statement_nodes = {}
                    simp_flag = 0
                    while len(stmt_node_queue) > 0:
                        cur_stmt_node = stmt_node_queue.pop(0)
                        succs = list(to_simplify_sub_graph.successors(cur_stmt_node))
                        skip = False

                        if cur_stmt_node in visited_stmt_nodes:
                            skip = True
                        for succ in succs:
                            if succ not in visited_stmt_nodes:
                                skip = True

                        visited_stmt_nodes[cur_stmt_node] = True
                        if skip:
                            continue

                        preds = list(to_simplify_sub_graph.predecessors(cur_stmt_node))
                        stmt_node_queue = preds + stmt_node_queue

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
                        successors = list(to_simplify_sub_graph.successors(cur_stmt_node))
                        if isinstance(cur_stmt.data, pyvex.expr.Binop) and cur_stmt.data.op in ["Iop_Add32", "Iop_Add64", "Iop_Sub32", "Iop_Sub64"] and len(successors) == 1:
                            if cur_stmt_node in simplified_statement_nodes:
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
                                if successor in simplified_statement_nodes:
                                    continue
                                succ_nodes_to_join = successors # Since only one successor is there
                                simplified_statement_nodes[successor] = True
                                simplified_statement_nodes[cur_stmt_node] = True
                                tmp_to_keep = successor.stmt.data.args[0].tmp
                                for arg in successor.stmt.data.args:
                                    if isinstance(arg, pyvex.expr.Const):
                                        const_1 = arg.con.value
                                if successor.stmt.data.op in ["Iop_Sub32", "Iop_Sub64"]:
                                    const_1 = -const_1

                                #simplified_statements[-1] = pyvex.stmt.WrTmp(cur_stmt.tmp, pyvex.expr.Binop("Iop_Add"+cur_stmt.data.op[-2:], [pyvex.expr.RdTmp(tmp_to_keep), pyvex.expr.Const(cur_stmt.data.args[1].__class__(pyvex.expr.U64(const_0+const_1 if const_0 + const_1 >= 0 else (1<<64)+const_1+const_0)))]))
                                new_simpl_stmt = pyvex.stmt.WrTmp(cur_stmt.tmp, pyvex.expr.Binop("Iop_Add" + cur_stmt.data.op[-2:],
                                                                                [pyvex.expr.RdTmp(tmp_to_keep),
                                                                                 pyvex.expr.Const(cur_stmt_const_class(((const_0+const_1)&(1<<64)-1)))]))
                                tmp_codeloc = IndSensitiveCodeLocation(successor.codeloc.block_addr,
                                                                       successor.codeloc.stmt_idx,
                                                                       ins_addr=cur_stmt_node.codeloc.ins_addr,
                                                                       ins_ind=cur_stmt_node.codeloc.ins_ind
                                                                       )

                                new_simpl_stmt_node = StatementNode(new_simpl_stmt, tmp_codeloc)
                                # This map is to ensure that if the two VEX insts are from two different x86 insts then after this simp we should treat them as one...... to make our life easier while mapping VEX back to x86
                                # new_address_map[new_simpl_stmt_node] = (cur_stmt_node.codeloc.ins_addr, cur_stmt_node.codeloc.ins_ind)
                                #successor.stmt = pyvex.stmt.WrTmp(cur_stmt.tmp, pyvex.expr.Binop("Iop_Add"+cur_stmt.data.op[-2:], [pyvex.expr.RdTmp(tmp_to_keep), pyvex.expr.Const(cur_stmt.data.args[1].__class__(pyvex.expr.U64(const_0+const_1 if const_0 + const_1 >= 0 else (1<<64)+const_1+const_0)))]))
                                for pred_node in pred_nodes_to_join:
                                    to_simplify_sub_graph.add_edge(pred_node, new_simpl_stmt_node)
                                for succ_node in succ_nodes_to_join:
                                    to_simplify_sub_graph.add_edge(new_simpl_stmt_node, succ_node)
                                to_simplify_sub_graph.remove_node(successor)
                                to_simplify_sub_graph.remove_node(cur_stmt_node)
                                #simplified_statements.pop(-2)
                                simp_flag = 1


                    ## reconstrcut the statements from the simplififed graph
                    stmt_node_queue = []
                    visited_stmt_nodes = {}

                    # insert the leaf nodes into the queue and update the addresses of the modified instructions
                    for stmt_node in to_simplify_sub_graph.nodes():
                        # Updating the new code locs for the stmts
                        # if not isinstance(stmt_node.codeloc, ExternalCodeLocation) and stmt_node in new_address_map:
                        #     ins_tuple = new_address_map[stmt_node]
                        #     new_stmt_node = StatementNode(stmt_node.stmt, )
                        #     stmt_node.codeloc.ins_addr = ins_tuple[0]
                        #     stmt_node.codeloc.ins_ind = ins_tuple[1]
                        if to_simplify_sub_graph.out_degree(stmt_node) == 0:
                            stmt_node_queue.append(stmt_node)
                            print(stmt_node)

                    while len(stmt_node_queue) > 0:
                        skip = False
                        cur_stmt_node = stmt_node_queue.pop(0)
                        if cur_stmt_node in visited_stmt_nodes:
                            continue
                        succs = list(to_simplify_sub_graph.successors(cur_stmt_node))

                        # make sure that all the successors are visited before visiting a node
                        for succ in succs:
                            if succ not in visited_stmt_nodes:
                                skip = True
                        if skip:
                            continue
                        preds = list(to_simplify_sub_graph.predecessors(cur_stmt_node))
                        stmt_node_queue = preds + stmt_node_queue
                        visited_stmt_nodes[cur_stmt_node] = True
                        if isinstance(cur_stmt_node.codeloc, ExternalCodeLocation):
                            continue
                        #simplified_statements.append(cur_stmt_node.stmt)
                        if (cur_stmt_node.codeloc.ins_addr, cur_stmt_node.codeloc.ins_ind) not in inst_grouped_simp_stmts:
                            inst_grouped_simp_stmts[(cur_stmt_node.codeloc.ins_addr, cur_stmt_node.codeloc.ins_ind)] = []
                        inst_grouped_simp_stmts[(cur_stmt_node.codeloc.ins_addr, cur_stmt_node.codeloc.ins_ind)].append(cur_stmt_node.stmt)

                # Making sure that the order of instructions is same as the original binary, though does not necessarily mean the best
                ordered_ins_addrs = []
                for ind, stmt in enumerate(node.irsb.statements):
                    if isinstance(stmt, pyvex.stmt.IMark) and (stmt.addr, ind) in inst_grouped_simp_stmts:
                        ordered_ins_addrs.append((stmt.addr, ind))

                for ins_tuple in ordered_ins_addrs:
                    ins_addr = ins_tuple[0]
                    ins_ind = ins_tuple[1]
                    simplified_statements.append(pyvex.stmt.IMark(ins_addr, length=0, delta=0))
                    for simp_stmt in inst_grouped_simp_stmts[(ins_addr, ins_ind)]:
                        simplified_statements.append(simp_stmt)

                node.irsb = pyvex.IRSB.empty_block(node.irsb.arch,
                                                   node.irsb.addr,
                                                   statements=simplified_statements,
                                                   tyenv=node.irsb.tyenv,
                                                   nxt=node.irsb.next,
                                                   direct_next=node.irsb.direct_next,
                                                   jumpkind=node.irsb.jumpkind,
                                                   size=node.irsb.size)
                print(node.irsb.pp())

                # if simp_flag == 1:
                #     import ipdb;ipdb.set_trace()
                #     pass

        # Returning a new CFGVMDeobfuscation object with the updated graph
        if start_state:
            initial_input_state = start_state
        else:
            initial_input_state = proj.factory.blank_state(addr=self.start_addr,
                                                           mode='fastpath',
                                                           add_options=angr.sim_options.refs | {
                                                               angr.sim_options.REPLACEMENT_SOLVER,
                                                               angr.sim_options.DO_CCALLS})
        new_model._nodes_by_addr[self.start_addr][0].input_state = initial_input_state
        new_cfg = proj.analyses.CFGVMDeobfuscation(model=new_model, keep_state=True, iropt_level=1,
                                                   resolve_indirect_jumps=True, max_iterations=1,
                                                   vm_vpc_addr=self.vm_vpc_addr)
        return new_cfg


    def new_model_without_terminator_graph(self, old_graph, proj, identifier):
        new_cfg_graph = old_graph.__class__()
        new_nodes = []
        node_map = {}
        node_map_by_addr = defaultdict(list)

        # not setting the attributes for the model since they will *most likely* be not used on the analysis
        new_model = proj.kb.cfgs.new_model(identifier)
        new_model.graph = new_cfg_graph

        for node in old_graph.nodes():
            if "PathTerminator" not in str(node.name):
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
            if "PathTerminator" not in str(src.name) and "PathTerminator" not in str(dst.name):
                new_edges.append((node_map[src.block_id], node_map[dst.block_id], {'jumpkind': data['jumpkind']}))

        new_cfg_graph.add_nodes_from(new_nodes)
        new_cfg_graph.add_edges_from(new_edges)

        new_model._nodes = node_map
        new_model._nodes_by_addr = node_map_by_addr

        return new_model
    ## creates a new model which contains a graph that is structurally similar to the old one but resets the states
    ## and keeps certain attributes
    def new_model_graph(self, old_graph, proj, identifier):
        new_cfg_graph = old_graph.__class__()
        new_nodes = []
        node_map = {}
        node_map_by_addr = defaultdict(list)

        # not setting the attributes for the model since they will *most likely* be not used on the analysis
        new_model = proj.kb.cfgs.new_model(identifier)
        new_model.graph = new_cfg_graph

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

        new_cfg_graph.add_nodes_from(new_nodes)
        new_cfg_graph.add_edges_from(new_edges)

        new_model._nodes = node_map
        new_model._nodes_by_addr = node_map_by_addr

        return new_model

    # def annotate_and_preconstrain_sp(self, start_state):
    #     actual_stack_end = start_state.solver.eval(start_state.regs.sp)
    #     start_state.regs.sp = start_state.solver.BVS("precon_sp", 64)
    #     start_state.regs.sp = start_state.regs.sp.annotate(StackPointerAnnotation(1))
    #     start_state.preconstrainer.preconstrain(actual_stack_end, start_state.regs.sp)
    ####### Run the data sensisitve, loop unrolling, CFGEmulated analysis
    def data_sensitive_graph(self, filename, vm_vpc_addr, start_addr, start_state, cfg_fast_graph, avoid_runs):
        #proj = angr.Project(filename)
        proj = self.project

        if start_state is None:
            if start_addr is None:
                main = proj.loader.main_object.get_symbol("main")
                start_addr = main.rebased_addr

            start_state = proj.factory.blank_state(addr=start_addr,
                                                   add_options={angr.sim_options.REPLACEMENT_SOLVER,
                                                                  angr.sim_options.DO_CCALLS})
        # self.annotate_and_preconstrain_sp(start_state)

        cfg = proj.analyses.CFGVMDeobfuscation(fail_fast=True,
                                        data_sensitive=True,
                                        vm_vpc_addr=vm_vpc_addr,
                                        starts=[start_addr],
                                        initial_state=start_state,
                                        max_iterations=1,
                                        resolve_indirect_jumps=False, ##### Need to resolve the issue that arises when this is set to True
                                        keep_state=True,
                                        state_add_options=angr.sim_options.refs| {angr.sim_options.DO_CCALLS},
                                        iropt_level=1,
                                        cfg_fast_graph=cfg_fast_graph,
                                        avoid_runs=avoid_runs,
                                        )
        return cfg, proj

    ####### Constant Propagation
    def constant_propagation(self, cfg, proj, start_addr, vm_vpc_addr, start_state=None):
        old_graph = cfg.graph
        new_model = self.new_model_graph(old_graph, proj, "temporary1")
        new_cfg_graph = new_model.graph

        ## Setting the input state for the first node(need to automate this)
        if start_addr == None:
            main = proj.loader.main_object.get_symbol("main")
            start_addr = main.rebased_addr
        if start_state:
            initial_input_state = start_state
        else:
            initial_input_state = proj.factory.blank_state(addr=start_addr,
                                                           mode='fastpath',
                                                           add_options=angr.sim_options.refs | {angr.sim_options.REPLACEMENT_SOLVER, angr.sim_options.DO_CCALLS})

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

        new_model._nodes_by_addr[start_addr][0].input_state = initial_input_state
        ## find the replacements

        prop = proj.analyses.PropagatorEmulated(graph=new_cfg_graph, iropt_level=1, start=start_addr, max_iterations=2)

        ## do the actual replacements
        for key, value in prop.replacements.items():
            node = new_model._nodes[key]
            if not node.is_simprocedure:
                new_stmts = node.irsb.statements
                for stmt, repl_pair in value.items():
                    for old, new in repl_pair.items():
                        ## This is for the next expression
                        if stmt.stmt_idx == -2:
                            node.irsb.next = new
                        else:
                            new_stmts[stmt.stmt_idx].replace_expression(old, new)

        ### Clearing the states for the newly created graph (or should I create a new copy again)
        new_model = self.new_model_graph(new_cfg_graph, proj, "temporary2")

        ## Setting the input state for the first node(need to automate this)
        if start_state:
            initial_input_state = start_state
        else:
            initial_input_state = proj.factory.blank_state(addr=start_addr,
                                                           mode='fastpath',
                                                           add_options=angr.sim_options.refs | {
                                                           angr.sim_options.REPLACEMENT_SOLVER, angr.sim_options.DO_CCALLS})
        new_model._nodes_by_addr[start_addr][0].input_state = initial_input_state

        #Run the emulation on the new graph to update the state attributes
        new_cfg = proj.analyses.CFGVMDeobfuscation(model=new_model, keep_state=True, iropt_level=1, resolve_indirect_jumps=False, max_iterations=1,
                                            vm_vpc_addr=vm_vpc_addr)

        ### Returning a new CFGVMDeobfuscation object with the updated graph
        return new_cfg

    #### This method removes stuff like empty blocks, empty instructions(Imark, AbiHints etc)
    def remove_junk(self, cfg, proj, start_addr, start_state=None):
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
                        print(stmt.__str__(arch=node.irsb.arch, tyenv=node.irsb.tyenv))
                        print(ddg._stmt_graph.out_edges([location]))
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
                print("DCE version")
                print(node.irsb.pp())
                print("\n")
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
        dce_new_model._nodes_by_addr[start_addr][0].input_state = initial_input_state
        new_cfg = proj.analyses.CFGVMDeobfuscation(model=dce_new_model, keep_state=True, iropt_level=1, resolve_indirect_jumps=True, max_iterations=1)
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

                cfg.graph.add_edge(node, fake_node, jumpkind='Ijk_Borking')
                import ipdb;ipdb.set_trace()

        return cfg


    ####### Dead Cod Elimination
    def dead_code_elimination(self, cfg, proj, start_addr, vm_vpc_addr, start_state):
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
                print(node.irsb.pp())
                print(node.block_id)
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
                        print("Dependencies of: "+stmt.__str__(arch=node.irsb.arch, tyenv=node.irsb.tyenv))
                        for out_edges in ddg._stmt_graph.out_edges([location]):
                            print(out_edges[1])
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

                    print("DCE version")
                    print(node.irsb.pp())
                    print("\n")
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
        dce_new_model._nodes_by_addr[start_addr][0].input_state = initial_input_state
        new_cfg = proj.analyses.CFGVMDeobfuscation(model=dce_new_model, keep_state=True, iropt_level=1, resolve_indirect_jumps=True, max_iterations=1, vm_vpc_addr=vm_vpc_addr)
        return new_cfg, changed

    ### Draw the graph with vex statements
    def draw_graph(self, cfg, filename):
        A = nx.nx_agraph.to_agraph(cfg.graph)
        for node in cfg.graph.nodes():
            stmt_str = str(node)
            if node.irsb != None:
                for ind, stmt in enumerate(node.irsb.statements):
                    stmt_str = stmt_str + "\l" + stmt.__str__(arch=node.irsb.arch, tyenv=node.irsb.tyenv)

            graphviz_node = A.get_node(str(node))
            graphviz_node.attr["label"] = stmt_str
            graphviz_node.attr["shape"] = "box"
        A.layout(prog="dot")
        A.draw(path=filename, format="svg")

    ### Drawing a graph comparing the removed x86 instructions vs the instructions that were kept(or a part of their statemnts was left beind after simplifications)
    def draw_original_graph(self, cfg, filename, proj):
        A = nx.nx_agraph.to_agraph(cfg.graph)
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

    ############### !!!! This only works under the assumption that no new statements are added to the final graph, i.e. statements are only removed from the final graph ################
    def compare_vex(self, initial_cfg, final_cfg, folder_name):

        A = nx.nx_agraph.to_agraph(initial_cfg.graph)
        B = nx.nx_agraph.to_agraph(final_cfg.graph)

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

    def pattern_match_to_x86_instructions(self, final_cfg, orig_cfg, proj, folder_name):
        A = nx.nx_agraph.to_agraph(final_cfg.graph)
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

from angr.analyses import AnalysesHub
AnalysesHub.register_default('VMDeobfuscation', VMDeobfuscation)
