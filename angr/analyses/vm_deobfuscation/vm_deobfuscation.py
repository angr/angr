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
from angr.engines import UberEngine
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
from ..cfg.cfg_vm_deobfuscation import StackPointerAnnotation, StackTouchedAnnotation, DataRegionAnnotation, annotate_with_new_replacements, VMStackVariableAnnotation
from ... import BP, BP_BEFORE, BP_AFTER
from ...knowledge_plugins import Function
from ...knowledge_plugins.key_definitions import atoms
from ...engines.light.data import SpOffset
from ...storage.memory_mixins import TopListPagesMemory, DefaultListPagesMemory
from ...storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from ...knowledge_plugins.key_definitions.undefined import Undefined, UNDEFINED
from multiprocessing import Process, Queue


to_break = False
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
    def __init__(self, block_addr: int, stmt_idx: int, ins_ind=None, sim_procedure=None, ins_addr=None,
                 context=None, block_idx=None, block_id=None, **kwargs):
        super(IndSensitiveCodeLocation, self).__init__(block_addr, stmt_idx, sim_procedure, ins_addr,
                 context, block_idx, block_id, **kwargs)
        self.ins_ind = ins_ind


class CLibFunctionHandler(FunctionHandler):
    def __init__(self, project):
        self.project = project

    def hook(self, analysis):
        return self

    def handle_local_function(self, state, function_address, call_stack,
                              maximum_local_call_depth, visited_blocks, dep_graph,
                              src_ins_addr=None,
                              codeloc=None):
       # We skip local functions that we have a CFG for, this is only for lib functions that we are hooking e.g.printf scanf in windows binaries that seem to be statically compiled
        if self.project.is_hooked(codeloc.block_addr):
            executed_rda = False
        else:
            executed_rda = True
        return executed_rda, state, visited_blocks, dep_graph


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

debug=False
class InputConcretizeEngine(UberEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _handle_vex_expr(self, expr):
        result = super()._handle_vex_expr(expr)
        new_result = result[0]

        if self.project.prev_symbolic_expr_locations_blockwise and not self.state.solver.symbolic(result[0]) and self.state.globals['cur_block_id'] in self.project.prev_symbolic_expr_locations_blockwise:
            for codeloc, expr_list in self.project.prev_symbolic_expr_locations_blockwise[self.state.globals['cur_block_id']].items():
                for to_repl_expr in expr_list:
                    if codeloc.stmt_idx == self.state.scratch.stmt_idx and to_repl_expr == expr:
                        sym_result = self.state.solver.BVS("symbolified_expr"+str(hex(codeloc.block_addr)), result[0].size())
                        self.state.globals['expr_loc_map'][sym_result.args[0]] = (codeloc, expr)
                        new_result = sym_result

        return [new_result, result[1]]

    def _handle_vex_expr_Load(self, expr: pyvex.expr.Load):
        return self._perform_vex_expr_Load(self._analyze_vex_expr_Load_addr(expr.addr), expr.ty, expr.end, expr)

    def _perform_vex_expr_Load(self, addr, ty, endness, expr, **kwargs):
        simplified_addr = addr[0]
        if self.state.solver.symbolic(addr[0]):
            try:
                simplified_addr = self.state.partial_symbolic_constraint_solver.eval_one(addr[0])
            except:
                pass

        result = super()._perform_vex_expr_Load((simplified_addr, addr[1]), ty, endness, **kwargs)

        if not self.state.solver.symbolic(simplified_addr):
            return result

        save = False
        var_ast_list = []

        if self.state.solver.symbolic(simplified_addr):
            conc_addrs = self.state.partial_symbolic_constraint_solver.eval_upto(simplified_addr, 5)
            ast_addrs = []
            for con_addr in conc_addrs:
                ast_addrs.append(claripy.BVV(con_addr, addr[0].size()))

            conc_addrs = ast_addrs

            if len(conc_addrs) < 5:
                save = True

        if len(var_ast_list) > 1:
            print("More than one variables? which one to save.... maybe both")
            #import ipdb;ipdb.set_trace()


        if save:
            loaded_values = []
            for conc_addr in conc_addrs:
                loaded_value = self.state.memory.load(conc_addr, self._ty_to_bytes(ty),
                                                      endness=self.state.arch.memory_endness)
                loaded_values.append(loaded_value)

            if len(conc_addrs) == 1 or len(conc_addrs) > 2:
                print("Hmmmm")
                import ipdb;
                ipdb.set_trace()
            else:
                state_split_cond = claripy.BoolS('mba_state_split_cond')
                ## IF OPTIMIZATION IS ZERO THEN WE HAVE TO STORE THIS IN THE REGISTER WHICH CREATED THIS TMP AS WELL,SINCE THE TEMP WILL NOT BE USED LATER WHEN THE REGISTER IS READ
                addr_mba=claripy.If(state_split_cond, conc_addrs[0], conc_addrs[1])
                self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr[0], addr_mba)
                self.state.scratch.temps[expr.addr.tmp] = addr_mba
                to_return=claripy.If(state_split_cond, loaded_values[0], loaded_values[1])
                self.state.partial_symbolic_constraint_solver._solver.add_replacement(result[0], to_return)

                ## This to add addrs which are of the following form mba+offset, mba+4
                if addr[0].op in ["__add__","__sub__"]:
                    if len(addr[0].args) == 2:
                        if addr[0].args[0].depth == 1:
                            if addr[0].op == "__add__":
                                self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr[0].args[1], claripy.If(state_split_cond, conc_addrs[0] - addr[0].args[0], conc_addrs[1] - addr[0].args[0]))
                            elif addr[0].op == "__sub__":
                                self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr[0].args[1], claripy.If(state_split_cond, addr[0].args[0] - conc_addrs[0], addr[0].args[0] - conc_addrs[1]))
                        elif addr[0].args[1].depth == 1:
                            if addr[0].op == "__add__":
                                self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr[0].args[0] ,claripy.If(state_split_cond, conc_addrs[0] - addr[0].args[1], conc_addrs[1] - addr[0].args[1]))
                            elif addr[0].op == "__sub__":
                                self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr[0].args[0] ,claripy.If(state_split_cond, conc_addrs[0] + addr[0].args[1], conc_addrs[1] + addr[0].args[1]))

                    elif len(addr[0].args) == 3:
                        if addr[0].args[0].depth == 1:
                            if addr[0].op == "__add__":
                                self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr[0].args[1] + addr[0].args[2], claripy.If(state_split_cond, conc_addrs[0] - addr[0].args[0], conc_addrs[1] - addr[0].args[0]))
                            elif addr[0].op == "__sub__":
                                print("Not implemented")
                                import ipdb;
                                ipdb.set_trace()
                                #self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr[0].args[1], claripy.If(state_split_cond, addr[0].args[0] - conc_addrs[0], addr[0].args[0] - conc_addrs[1]))
                        elif addr[0].args[1].depth == 1:
                            if addr[0].op == "__add__":
                                self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr[0].args[0] + addr[0].args[2],claripy.If(state_split_cond, conc_addrs[0] - addr[0].args[1], conc_addrs[1] - addr[0].args[1]))
                            elif addr[0].op == "__sub__":
                                print("Not implemented")
                                import ipdb;
                                ipdb.set_trace()
                                # self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr[0].args[0] ,claripy.If(state_split_cond, conc_addrs[0] + addr[0].args[1], conc_addrs[1] + addr[0].args[1]))
                        elif addr[0].args[2].depth == 1:
                            if addr[0].op == "__add__":
                                self.state.partial_symbolic_constraint_solver._solver.add_replacement(addr[0].args[0] + addr[0].args[1],claripy.If(state_split_cond, conc_addrs[0] - addr[0].args[2], conc_addrs[1] - addr[0].args[2]))
                            elif addr[0].op == "__sub__":
                                print("Not implemented")
                                import ipdb;
                                ipdb.set_trace()

                return [to_return ,result[1]]

        return result

def save_vm_vpc(state):
    # This is just a hack to make sure that when the VIP reg is being used for something else we don't track it ### NEED A BETTER AND GENERIC WAY
    expr_val = state.partial_symbolic_constraint_solver.eval_upto(state.inspect.reg_write_expr, 2)
    if len(expr_val) > 1:
        print("More than one VIP, gonna add both values and create a new one")
        #import ipdb;ipdb.set_trace()
        expr_val = expr_val[0]
    else:
        expr_val = expr_val[0]
    # expr_val = state.solver.eval_one(state.inspect.reg_write_expr)
    if state.project.loader.main_object.contains_addr(expr_val + state.globals['add_offset']):
        state.globals['cur_vm_vpc'] = expr_val + state.globals['add_offset']
        print("The value of PROGRAM COUNTER is: " + str(state.globals.get('cur_vm_vpc')) + " reg_offset: " + str(state.inspect.reg_write_offset))
    else:
        print("The value of the PROBLEMATIC PROGRAM COUNTER is and the PROBLEMATIC REGISTER IS: " + str(state.globals.get('cur_vm_vpc')) + " reg_offset: " + str(
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


class VMDeobfuscation(Analysis):

    def __init__(self, vsp_reg, prev_unroll_vm_addrs=None, start_addr=None, start_state=None, cfg_fast_graph=None, avoid_runs=None, vm_start_addr=None, verification_state=None, remove_insts=None, constant_prop_func_replacements=None,semantic_verf_hooks=None):

        # This is the address of the node where the virtual machine implementation starts
        self.vm_start_addr = vm_start_addr
        self.vsp_reg = vsp_reg
        self.start_addr = start_addr
        self.verification_state = verification_state
        self.constant_prop_func_replacements = constant_prop_func_replacements


        if self.project.arch.bits == 32:
            start_state.registers.store(start_state.arch.registers['ss'][0], 0)

        start_state_copy_without_bps = start_state.copy()


        # unroll the loops for the previous VM's
        start_state.globals['vm_vip_regs'] = {}
        start_state.globals['vm_end_addrs'] = {}
        start_state.globals['cur_rm_bps'] = []
        start_state.globals['call_stack_context_sensitivity_on'] = True

        # add breakpoints to activate and remove bps for each vm region
        for vm_tuple in prev_unroll_vm_addrs:
            vm_start_addr = vm_tuple[0]
            vm_end_addrs = vm_tuple[1]
            cur_vip_reg = vm_tuple[2]
            start_state.globals['vm_vip_regs'][vm_start_addr] = cur_vip_reg
            start_state.globals['vm_end_addrs'][vm_start_addr] = vm_end_addrs
            start_state.inspect.add_breakpoint('instruction',
                                               BP(BP_BEFORE, instruction=vm_start_addr, action=activate_save_vm_vpc))


        start_state_copy = start_state.copy()
        cfg, proj = self.data_sensitive_graph(self.project.filename, start_addr=self.start_addr, start_state=start_state_copy, cfg_fast_graph=cfg_fast_graph, avoid_runs=avoid_runs, remove_insts=remove_insts)
        self.project.kb.cfgs.cfgs = {}
        # clearing the saved states to save space
        for node in cfg.graph.nodes():
            node.input_state = None
            node.final_states = None

        folder_name = os.path.dirname(self.project.filename)
        #self.draw_graph(cfg, os.path.join(folder_name, "input.svg"))

        # removing path terminators, cause...............they causing problems
        cfg = self.new_model_without_terminator_graph(cfg.graph, proj, 'without_path_terminator')

        # removing fakeret nodes, cause...............they causing problems
     #   cfg = self.new_model_without_fakeret(cfg.graph, proj, 'without_path_fakeret')

        cfg = self.keep_only_one_graph(cfg, start_addr)
        #self.draw_graph(cfg, os.path.join(folder_name, "one_graph_input.svg"))

        start_state_copy = start_state.copy()
        cfg = self.convert_to_data_sensitive_irsb(cfg, proj, start_state_copy)

        # res = proj.analyses.Propagator(func=proj.kb.functions.get_by_addr(0x402350), func_graph=proj.kb.functions.get_by_addr(0x402350).graph)
        # import ipdb;
        # ipdb.set_trace()
        #
        # sub_nodes = []
        # done = False
        # for node in cfg.nodes():
        #     if node.addr == 0x43aab6 and node.block_id.vm_vpc == 4281418:
        #         sub_nodes.append(node)
        #         while True:
        #             succ = list(cfg.graph.successors(node))
        #             sub_nodes.append(succ[0])
        #             node = succ[0]
        #             if node.addr == 0x47bc28 and node.block_id.vm_vpc == 4358394:
        #                 sub_nodes.append(node)
        #                 done = True
        #                 break
        #         if done:
        #             break
        # sub_graph = cfg.graph.subgraph(sub_nodes).copy()
        #
        # sub_graph = self.new_model_graph(sub_graph, proj, 'sub_cfg')




    # This analysis needs more work
       #cfg = self.remove_non_local_variable_dep_branches(cfg, proj, start_state, start_addr, verification_input, cfg_fast_graph, avoid_runs)

        self.draw_graph(cfg, os.path.join(folder_name, "input.svg"))
        initial_cfg = self.new_model_graph(cfg.graph, proj, 'initial_cfg')

        # new_cfg, symbolic_expr_locations_blockwise = self.constant_propagation(sub_graph, proj, start_addr=0x43aab6,
        #                                                                        start_state=None,
        #                                                                        prev_symbolic_expr_locations_blockwise=None,
        #                                                                        vm_vpc=4281418)  # start_state=saved_start_state)

        # this constant prop is just used to get the symbolic_expr_locations_blockwise not to actually do constant prop

        # import tracemalloc
        # tracemalloc.start()

        # q = Queue()
        # p = Process(target=self.constant_propagation, args=(cfg, proj, start_addr, q), kwargs={'start_state':None, 'prev_symbolic_expr_locations_blockwise':None})
        # p.start()
        # # res = q.get()
        # res = []
        # while len(res) < 2:
        #     while not q.empty():
        #         print("here")
        #         res.append(q.get())
        #
        # new_cfg = res[0]
        # symbolic_expr_locations_blockwise = res[1]
        # p.join()
        # import ipdb;ipdb.set_trace()
        # import cProfile, pstats
        # profiler = cProfile.Profile()
        # profiler.enable()

        new_cfg, symbolic_expr_locations_blockwise = self.symbolizer(cfg, proj, start_addr, None, start_state=None, prev_symbolic_expr_locations_blockwise=None, prev_unroll_vm_addrs=prev_unroll_vm_addrs)#start_state=saved_start_state)
        # profiler.disable()
        # stats = pstats.Stats(profiler).sort_stats('tottime')
        # stats.print_stats()
        # import ipdb;ipdb.set_trace()
        self.draw_graph(new_cfg, os.path.join(folder_name, "cp_result.svg"))

        # snapshot = tracemalloc.take_snapshot()
        # top_stats = snapshot.statistics('lineno')
        #
        # print("[ Top 10 ]")
        # for stat in top_stats[:10]:
        #     print(stat)

        start_state_copy = start_state.copy()
        self.project.kb.cfgs.cfgs = {}

       #import ipdb;ipdb.set_trace()

        global debug
        debug = True
        cfg = None
        new_cfg, to_use_symbolic_exprs = self.symbolify_exprs(cfg, proj, symbolic_expr_locations_blockwise, start_addr=start_addr, start_state=start_state_copy, cfg_fast_graph=cfg_fast_graph, avoid_runs=avoid_runs, remove_insts=remove_insts)
        to_use_symbolic_exprs = None
        symbolic_expr_locations_blockwise=None

        import gc
        gc.collect()

        self.project.kb.cfgs.cfgs = {}
        # clearing the saved states to save space
        for node in new_cfg.graph.nodes():
            node.input_state = None
            node.final_states = None

        new_cfg = self.keep_only_one_graph(new_cfg, start_addr)

        self.draw_graph(new_cfg, os.path.join(folder_name, "symbolify_cfg.svg"))

        # filter the locations that we symbolize during constant propagation based on the previous analysis, to reduce the load on constant prop
        # new_symbolic_expr_locations_blockwise = defaultdict(lambda: defaultdict(list))
        # for codeloc, expr in to_use_symbolic_exprs:
        #     for expr_list in symbolic_expr_locations_blockwise[codeloc.block_id].values():
        #         for cur_expr in expr_list:
        #             if cur_expr == expr:
        #                 new_symbolic_expr_locations_blockwise[codeloc.block_id][codeloc].append(expr)
        #
        # import ipdb;ipdb.set_trace()
        # symbolic_expr_locations_blockwise = new_symbolic_expr_locations_blockwise

        start_state_copy = start_state.copy()
        new_cfg = self.convert_to_data_sensitive_irsb(new_cfg, proj, start_state_copy)

        start_state_copy = start_state.copy()

        # self.perform_semantic_verification(new_cfg, proj, start_state=verification_state, start_addr=start_addr,semantic_verf_hooks=semantic_verf_hooks)
        # import ipdb;ipdb.set_trace()
        # q = Queue()
        # p = Process(target=self.constant_propagation, args=(new_cfg, proj, start_addr, q), kwargs={'start_state':None, 'prev_symbolic_expr_locations_blockwise':symbolic_expr_locations_blockwise})
        # p.start()
        # # res = q.get()
        # res = []
        # while len(res) < 2:
        #     while not q.empty():
        #         print("here")
        #         res.append(q.get())
        #
        # new_cfg = res[0]
        # symbolic_expr_locations_blockwise = res[1]

        #p.join()
        import gc
        gc.collect()
        # new_cfg, symbolic_expr_locations_blockwise = self.constant_propagation(new_cfg, proj, start_addr, None,
        #                                                                        start_state=None,
        #                                                                        prev_symbolic_expr_locations_blockwise=None, prev_unroll_vm_addrs=prev_unroll_vm_addrs)
        new_cfg, symbolic_expr_locations_blockwise = self.symbolizer(new_cfg, proj, start_addr, None, start_state=None, prev_symbolic_expr_locations_blockwise=None, prev_unroll_vm_addrs=prev_unroll_vm_addrs,do_replacements=True)#start_state=saved_start_state)
        symbolic_expr_locations_blockwise = None
        self.project.kb.cfgs.cfgs = {}

        import gc
        gc.collect()

        # clearing the saved states to save space
        for node in new_cfg.graph.nodes():
            node.input_state = None
            node.final_states = None
        self.draw_graph(new_cfg, os.path.join(folder_name, "cp_result.svg"))

        # verification_state_copy = verification_state.copy()
        # self.perform_semantic_verification(new_cfg, proj, start_state=verification_state_copy,
        #                                    start_addr=start_addr, semantic_verf_hooks=semantic_verf_hooks)
        # import ipdb;ipdb.set_trace()
        start_state_copy = start_state.copy()
        #self.perform_semantic_verification(new_cfg, proj, start_state=verification_state, start_addr=start_addr,semantic_verf_hooks=semantic_verf_hooks)

        # if self.project.filename == "/media/sf_PhD/simple_vm_set/vmprotect_test/loop_exe_test/loop_test/x64/Debug/loop_test.vmp.exe":
        #     # VM_1_func = Function(proj.kb.functions, 0x1400B921B, 'VM_1', None, is_simprocedure=False)
        #     # VM_1_func.normalize()
        #     visited_nodes={}
        #     VM_1_func = Function(proj.kb.functions, 0x1400b921b, 'VM_1', None, is_simprocedure=False)
        #
        #     traversal_start_node = "<CFGENode 0x1400b921b (0x0 0x0 None0x140012030 0x14012404f 0x1400b921b )vm-vpc:None [58]>"
        #     node_stack=[]
        #     for cur_node in new_cfg.nodes():
        #         if str(cur_node) == traversal_start_node:
        #             node_stack.append(cur_node)
        #             VM_1_func.startpoint = cur_node
        #             break
        #     end_points = ["<CFGENode 0x14001143d (0x0 0x0 None0x140012030 0x14012404f 0x1400b921b )vm-vpc:5368834930 [5]>"]
        #
        #     while len(node_stack)>0:
        #         cur_node = node_stack.pop(0)
        #         if str(cur_node) in end_points or cur_node in visited_nodes:
        #             continue
        #         visited_nodes[cur_node] = True
        #         succs=new_cfg.get_successors(cur_node)
        #         node_stack = succs+node_stack
        #         for succ in succs:
        #             VM_1_func._transit_to(cur_node, succ)
        #
        #     VM_1_func.normalize()
        #     #self.project.kb.functions[5369467419].normalize()
        #     # self.project.kb.functions[5369467419].calling_convention = angr.calling_conventions.SimCCMicrosoftAMD64
        #     dec = proj.analyses.Decompiler(VM_1_func)
        #     print("Decompilation result:")
        #     print(dec.codegen.text)
        #     import ipdb;
        #     ipdb.set_trace()



        # # this is a simplification pass to remove all push x, ret to x type of jumps
        new_cfg = self.remove_push_ret(new_cfg, proj, start_addr=start_addr, start_state=None)
        self.draw_graph(new_cfg, os.path.join(folder_name, "remove_push_ret.svg"))


        # this is to remove those vex jump insts that will always to the same location. This is after the data sensitive analysis
        new_cfg = self.remove_useless_jump_instructions(new_cfg, proj, start_addr, None, initial_cfg)
        self.draw_graph(new_cfg, os.path.join(folder_name, "remove_useless_jump.svg"))

        for i in range(4):
            new_cfg = self._eliminate_dead_assignments(new_cfg, proj, start_state=start_state)
            self.draw_graph(new_cfg, os.path.join("dae_"+str(i)+"_result.svg"))

            new_cfg = self.block_arithmetic_simplifications(new_cfg, proj, start_state=start_state)
            self.draw_graph(new_cfg, os.path.join(folder_name, str(i)+"block_arithmetic_simplifications.svg"))
                # commented this for test_vmp to show the add eax,1 result

            new_cfg = self.join_basic_blocks(new_cfg, proj, start_addr=start_addr, start_state=None)

        #self.perform_semantic_verification(new_cfg, proj, start_state=verification_state, start_addr=start_addr,semantic_verf_hooks=semantic_verf_hooks)

        self.draw_graph(new_cfg, os.path.join(folder_name, "join_basic_blocks.svg"))

        #### These need to be after join basic blocks becasue of the way RDA considers a libc func call as internal instead of external
        for i in range(4):
            global to_break
            to_break = True
            new_cfg = self.testing_new_improved_whole_vm_RDA_deadassignment_elimination(new_cfg, proj, start_state=start_state)
            self.draw_graph(new_cfg, os.path.join(folder_name, str(i)+"whole_cfg_deadassignment_elimination.svg"))

        for i in range(4):
            new_cfg = self._eliminate_dead_assignments(new_cfg, proj, start_state=start_state)
            self.draw_graph(new_cfg, os.path.join("dae_"+str(i)+"_result.svg"))

        #self.perform_semantic_verification(new_cfg, proj, start_state=verification_state, start_addr=start_addr,semantic_verf_hooks=semantic_verf_hooks)

        new_cfg = self.remove_redundant_store_load(new_cfg, proj, start_state=start_state)
        self.draw_graph(new_cfg, os.path.join(folder_name, "debug_2_result.svg"))
        #self.perform_semantic_verification(new_cfg, proj, start_state=verification_state, start_addr=start_addr,semantic_verf_hooks=semantic_verf_hooks)

        verification_state_copy = verification_state.copy()
        self.perform_semantic_verification(new_cfg, proj, start_state=verification_state_copy,
                                           start_addr=start_addr, semantic_verf_hooks=semantic_verf_hooks)
        import ipdb;ipdb.set_trace()

        for i in range(2):
            new_cfg = self.testing_new_improved_whole_vm_RDA_deadassignment_elimination(new_cfg, proj, start_state=start_state)
            self.draw_graph(new_cfg, os.path.join(folder_name, str(i)+"whole_cfg_deadassignment_elimination.svg"))
        for i in range(2):
            new_cfg = self._eliminate_dead_assignments(new_cfg, proj, start_state=start_state)
            self.draw_graph(new_cfg, os.path.join("dae_"+str(i)+"_result.svg"))

        self.draw_graph(new_cfg, os.path.join(folder_name, "debug_1_result.svg"))
        new_cfg = self.remove_redundant_assignment(new_cfg, proj, start_state=start_state)
        self.draw_graph(new_cfg, os.path.join(folder_name, "redun_store_load.svg"))

        #self.perform_semantic_verification(new_cfg, proj, start_state=verification_state, start_addr=start_addr,semantic_verf_hooks=semantic_verf_hooks)

        for i in range(8):
            new_cfg = self.testing_new_improved_whole_vm_RDA_deadassignment_elimination(new_cfg, proj, start_state=start_state)
            self.draw_graph(new_cfg, os.path.join(folder_name, str(i)+"whole_cfg_deadassignment_elimination.svg"))

            new_cfg = self._eliminate_dead_assignments(new_cfg, proj, start_state=start_state)
            self.draw_graph(new_cfg, os.path.join("dae_cake_"+str(i)+"_result.svg"))

            new_cfg = self.block_arithmetic_simplifications(new_cfg, proj, start_state=start_state)
            self.draw_graph(new_cfg, os.path.join(folder_name, str(i)+"_block_arithmetic_simplifications.svg"))

            new_cfg = self.remove_redundant_Get_Put(new_cfg, proj, start_state=start_state)
            self.draw_graph(new_cfg, os.path.join(folder_name, str(i)+"remove_redun_get_put.svg"))

        #self.perform_semantic_verification(new_cfg, proj, start_state=verification_state, start_addr=start_addr,semantic_verf_hooks=semantic_verf_hooks)

        new_cfg = self.remove_redundant_assignment(new_cfg, proj, start_state=start_state)
        self.draw_graph(new_cfg, os.path.join(folder_name, "redun_store_load.svg"))

        for i in range(3):
            new_cfg = self.remove_redundant_Get_Put(new_cfg, proj, start_state=start_state)
            self.draw_graph(new_cfg, os.path.join(folder_name, str(i)+"remove_redun_get_put.svg"))

            new_cfg = self.testing_new_improved_whole_vm_RDA_deadassignment_elimination(new_cfg, proj, start_state=start_state)
            self.draw_graph(new_cfg, os.path.join(folder_name, str(i)+"whole_cfg_deadassignment_elimination.svg"))

            new_cfg = self._eliminate_dead_assignments(new_cfg, proj, start_state=start_state)
            self.draw_graph(new_cfg, os.path.join("dae_"+str(i)+"_result.svg"))

        verification_state_copy = verification_state.copy()
        self.perform_semantic_verification(new_cfg, proj, start_state=verification_state_copy, start_addr=start_addr,semantic_verf_hooks=semantic_verf_hooks)
        import ipdb;ipdb.set_trace()
        self.draw_graph(new_cfg, os.path.join(folder_name,  "final_result.svg"))
        self.draw_original_graph(new_cfg, os.path.join(folder_name, "comparision_graph.svg"), proj)
        self.compare_vex(initial_cfg, new_cfg, folder_name)
        self.pattern_match_to_x86_instructions(new_cfg, initial_cfg, proj, folder_name)

    def symbolizer(self, cfg, proj, start_addr, q, start_state=None, options=None,
                             prev_symbolic_expr_locations_blockwise=None, vm_vpc=None,
                             return_symbolic_expr_locations_blockwise=None, new_cfg=None, prev_unroll_vm_addrs=None, do_replacements=False):
        self.project.prev_symbolic_expr_locations_blockwise = prev_symbolic_expr_locations_blockwise
        print("Doing constant propagation")
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
            initial_input_state = start_state
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

            initial_input_state.register_plugin('partial_symbolic_constraint_solver',
                                                angr.state_plugins.solver.SimSolver(
                                                    claripy.solvers.SolverReplacement(claripy.Solver(),
                                                                                      unsafe_replacement=True,
                                                                                      auto_replace=False)))  # auto replace needs to be Fals otherwiseit will wrongly replace constraints that start with NOT to False

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
            initial_input_state.globals['mba_locs'] = {}
            initial_input_state.globals['same_sp_merged'] = False

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

        initial_input_state.inspect.add_breakpoint('mem_read',
                                                   BP(
                                                       BP_AFTER,
                                                       action=annotate_stack_read_value
                                                   ))

        def preconstrain_return_value(state):
            if state.inspect.simprocedure_name == "malloc" and state.inspect.simprocedure_result is not None and not state.solver.symbolic(
                    state.inspect.simprocedure_result):
                value = state.solver.eval(state.inspect.simprocedure_result)
                state.inspect.simprocedure_result = state.solver.BVS("return_val", 64)
                state.preconstrainer.preconstrain(value, state.inspect.simprocedure_result)
            return

        ### preconstraining return values of library calls like malloc
        initial_input_state.inspect.add_breakpoint('simprocedure', BP(BP_AFTER, action=preconstrain_return_value))

        ## annotating and preconstraining the stack pointer
        # self.annotate_and_preconstrain_sp(initial_input_state)

        for node in new_model._nodes_by_addr[start_addr]:
            if node.addr == start_addr and node.block_id.vm_vpc == vm_vpc:
                node.input_state = initial_input_state
        ## find the replacements

        # replacing the printf hook with unconstrained return just for constant prop, since it get's a symbolic fmt str poitner
        for func_addr, orig_sim_proc, repl_sim_proc in self.constant_prop_func_replacements:
            proj.unhook(func_addr)
            proj.hook(func_addr, repl_sim_proc)

        prop = proj.analyses.Symbolizer(graph=new_cfg_graph, iropt_level=1, start=start_addr, max_iterations=2)

        for func_addr, orig_sim_proc, repl_sim_proc in self.constant_prop_func_replacements:
            proj.unhook(func_addr)
            proj.hook(func_addr, orig_sim_proc)

        if do_replacements:
            for key, value in prop.replacements.items():
                node = new_model._nodes[key]
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
        return new_model, prop.symbolic_expr_locations_blockwise

    def symbolify_exprs(self, cfg, proj, symbolic_expr_locations_blockwise, start_addr=None, start_state=None, cfg_fast_graph=None, remove_insts=None, avoid_runs=None):
        start_state.globals['to_use_symbolic_exprs'] = []
        start_state.globals['expr_loc_map'] = {}
        self.project.prev_symbolic_expr_locations_blockwise = symbolic_expr_locations_blockwise
        cfg = proj.analyses.CFGVMDeobfuscation(fail_fast=True,
                                               data_sensitive=True,
                                               starts=(start_addr,),
                                               initial_state=start_state,
                                               max_iterations=1,
                                               resolve_indirect_jumps=False,
                                               keep_state=False,
                                               state_add_options=angr.sim_options.refs | {angr.sim_options.DO_CCALLS, angr.sim_options.REPLACEMENT_SOLVER},
                                               iropt_level=1,
                                               cfg_fast_graph=cfg_fast_graph,
                                               avoid_runs=avoid_runs,
                                               remove_insts=remove_insts
                                               # enable_advanced_backward_slicing=True
                                               )
        self.project.prev_symbolic_expr_locations_blockwise = None

        return cfg, cfg.to_use_symbolic_exprs

    def remove_push_ret(self, cfg, proj, start_addr, start_state=None,options=None):
        # this pass is to simplify push x, retn to x kind of jumps
        for node in cfg.graph.nodes():
            # this is to replace any indirect jumps to a simprocedure with a direct jump, should I do this for all jumps/calls?
            if not node.is_simprocedure and isinstance(node.irsb.next, pyvex.expr.RdTmp) and len(list(cfg.graph.successors(node))) == 1:
                if self.project.arch.bits == 32:
                    node.irsb.next = pyvex.expr.Const(DataSensitiveU32(list(cfg.graph.successors(node))[0].addr, list(cfg.graph.successors(node))[0].block_id))
                elif self.project.arch.bits == 64:
                    node.irsb.next = pyvex.expr.Const(DataSensitiveU64(list(cfg.graph.successors(node))[0].addr, list(cfg.graph.successors(node))[0].block_id))

            # # we are changin the jumpkinds that are IjK_Ret to Ijk_Call so that _process_block_end() in RDA treats the sim_procedures as a function
            if not node.is_simprocedure and len(list(cfg.graph.successors(node))) == 1 and \
                    list(cfg.graph.successors(node))[0].is_simprocedure:
                if node.irsb.jumpkind == 'Ijk_Ret':
                    node.irsb.jumpkind = 'Ijk_Boring'

            # this pass is to simplify push x, retn to x kind of jumps
            if not node.is_simprocedure:
                if len(list(cfg.graph.successors(node))) == 1 and node.irsb.jumpkind == "Ijk_Ret":
                    new_jumpkind = node.irsb.jumpkind
                    next_node_addr = list(cfg.graph.successors(node))[0].addr
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
                                                                               function_handler=CLibFunctionHandler(
                                                                                   self.project),
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


    def keep_only_one_graph(self, cfg, start_addr):
        conn_comps = nx.weakly_connected_components(cfg.graph)
        conn_comps = list(conn_comps)
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

    # this is to remove those vex jump insts that will always to the same location. This is after the data sensitive analysis
    def remove_useless_jump_instructions(self, cfg, proj, start_addr, start_state, orig_cfg):
        print("Remove useless jmp insts")
        #new_model = self.new_model_graph(cfg.graph, proj, 'remove_useless_jumps')
        new_model = cfg
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


    def join_basic_blocks(self, cfg, proj, start_addr, start_state):
        print("Join Basic blocks")
        #new_model = self.new_model_graph(cfg.graph, proj, 'join_basic_blocks')
        new_model = cfg

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

        # new_model._nodes_by_addr[self.start_addr][0].input_state = proj.factory.full_init_state(
        #     args=['./if_test.vmp.exe'],
        #     add_options=angr.options.unicorn,
        #     stdin=input,
        # )

        new_cfg = proj.analyses.CFGConcreteExecution(model=new_model, keep_state=True, iropt_level=1,
                                                   resolve_indirect_jumps=True)

        for node in new_cfg.graph.nodes():
            succs = new_cfg.get_successors(node)
            if len(succs) == 0 and node.input_state is not None:
                final_state = node.input_state
                print(node)
                print(final_state.posix.dumps(1))
        print("Done")
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

        import ipdb;ipdb.set_trace()

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

    def remove_redundant_Get_Put(self, cfg, proj, start_state=None):
        print("Remove redundant Get Put")
        #PUT(rsp) = t334        ===>      PUT(rsp) = t334
        #t116 = GET:I64(rsp)               t116 = t334
        # or
        #t83 = GET:I64(rsp)     ===>      t83 = GET:I64(rsp)
        #PUT(rsp) = t83

        #dsa_new_model = self.new_model_graph(cfg.graph, proj, 'redun_Get_Put')
        dsa_new_model = cfg
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
                                                           function_handler=CLibFunctionHandler(self.project),
                                                           observation_points=[('node', node.addr, OP_AFTER)]
                                                           )

            # Find redundant loads
            live_defs = rd.one_result
            to_remove = []
            replace_get_dict = {}
            all_defs = rd.all_definitions
            for d in all_defs:
                if isinstance(d.codeloc, ExternalCodeLocation) or d.dummy:
                    continue

                if isinstance(d.atom, atoms.Tmp):
                    uses = live_defs.tmp_uses[d.atom.tmp_idx]
                else:
                    uses = rd.all_uses.get_uses(d)

                if isinstance(d.atom, atoms.Register) and isinstance(node.irsb.statements[d.codeloc.stmt_idx], pyvex.stmt.Put):
                    for use in uses:
                        #make sure that other stmts don't define parts of a register e.g. put(cl) i.e. there's only one definition used at the location of the use
                        if len(rd.all_uses.get_uses_by_location(use)) == 1:
                            # This is an internal function or a sim procedure for which I have not written a rda handler
                            if isinstance(node.irsb.statements[use.stmt_idx], pyvex.stmt.WrTmp) and isinstance(node.irsb.statements[use.stmt_idx].data, pyvex.expr.Get) and (node.irsb.statements[d.codeloc.stmt_idx].data.result_size(node.irsb.tyenv) == node.irsb.statements[use.stmt_idx].data.result_size(node.irsb.tyenv)):
                                replace_get_dict[use.stmt_idx] = node.irsb.statements[d.codeloc.stmt_idx].data

                elif isinstance(d.atom, atoms.Tmp) and isinstance(node.irsb.statements[d.codeloc.stmt_idx].data, pyvex.expr.Get):
                    for use in uses:
                        # This is an internal function or a sim procedure for which I have not written a rda handler
                        if isinstance(node.irsb.statements[use.stmt_idx], pyvex.stmt.Put) and node.irsb.statements[use.stmt_idx].offset == node.irsb.statements[d.codeloc.stmt_idx].data.offset and (node.irsb.statements[use.stmt_idx].data.result_size(node.irsb.tyenv) == node.irsb.statements[d.codeloc.stmt_idx].data.result_size(node.irsb.tyenv)):
                            to_remove.append(use.stmt_idx)

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
            cur_block = angr.Block(node.irsb.addr, project=proj, vex=node.irsb)
            rd = self.project.analyses.ReachingDefinitions(cur_block,
                                                           track_tmps=True,
                                                           function_handler=CLibFunctionHandler(self.project),
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
                        # This is an enternal function or a sim procedure for which I have not written a rda handler
                        if use.block_id is None:
                            continue
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
    def testing_whole_vm_RDA_deadassignment_elimination(self, cfg, proj, start_state=None):
        dsa_new_model = self.new_model_graph(cfg.graph, proj, 'test_rda_dae')
        #start_state = ReachingDefinitionsState()
        for node in dsa_new_model.nodes():
            if node.addr == self.vm_start_addr:
                start_node = node
                break

        rd = self.project.analyses.ReachingDefinitions(subject=Subject((dsa_new_model.graph, start_node)),
                                                       track_tmps=True,
                                                       function_handler=CLibFunctionHandler(self.project),
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
                    if isinstance(cfg.get_node(use.block_id).irsb.statements[use.stmt_idx], pyvex.stmt.WrTmp):
                        if isinstance(cfg.get_node(use.block_id).irsb.statements[use.stmt_idx].data, pyvex.expr.Load):
                            no_uses = no_uses + 1
                if no_uses == 0 and d.atom.is_on_stack:
                    dead_defs_locs.add(d.codeloc)


#        Remove dead assignments
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
            if proj.arch.bits == 32:
                initial_input_state.registers.store(initial_input_state.arch.registers['ss'][0], 0)
        dsa_new_model._nodes_by_addr[self.start_addr][0].input_state = initial_input_state
        new_cfg = proj.analyses.CFGVMDeobfuscation(model=dsa_new_model, keep_state=True, iropt_level=1,
                                                   resolve_indirect_jumps=True, max_iterations=1)
        return new_cfg

    def testing_new_improved_whole_vm_RDA_deadassignment_elimination(self, cfg, proj, start_state=None):
        print("Whole CFG RDA based dead ass elimination")
        #dsa_new_model = self.new_model_graph(cfg.graph, proj, 'test_rda_dae')
        dsa_new_model =cfg
        # start_state = ReachingDefinitionsState()
        for node in dsa_new_model.nodes():
            if node.addr == self.vm_start_addr:
                start_node = node
                break

        leaf_nodes_list = []
        for node in list(dsa_new_model.graph.nodes()):
            if not node.is_simprocedure and len(list(dsa_new_model.graph.successors(node))) == 0:
                leaf_nodes_list.append(('node', node.addr, OP_AFTER))

        rd = self.project.analyses.ReachingDefinitions(subject=Subject((dsa_new_model.graph, start_node)),
                                                       track_tmps=True,
                                                       function_handler=CLibFunctionHandler(self.project),
                                                       max_iterations=3,
                                                       observation_points=leaf_nodes_list
                                                       )
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
            #         vs: 'MultiValues' = merged_live_defs.stack_definitions.load(stack_addr, size=d.atom.size,
            #                                                              endness=d.atom.endness)

            # is entirely possible that at the end of the block, a register definition is not used.
            # however, it might be used in future blocks.
            # so we only remove a definition if the definition is not alive anymore at the end of the block
            if isinstance(d.atom, atoms.Register) and not uses:
                vs: 'MultiValues' = merged_live_defs.register_definitions.load(d.atom.reg_offset, size=d.atom.size)
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
    # Eliminates dead memdefs, tmpdefs and regdefs in a single basic block
    def _eliminate_dead_assignments(self, cfg, proj, start_state=None):

        #dsa_new_model = self.new_model_graph(cfg.graph, proj, 'dae')
        dsa_new_model = cfg
        for node in dsa_new_model.nodes():
            if node.addr == self.vm_start_addr:
                start_node = node
                break

        for node in list(dsa_new_model.nodes()):
            if node.is_simprocedure:
                continue
            cur_block = angr.Block(node.irsb.addr, project=proj, vex=node.irsb)
            rd = self.project.analyses.ReachingDefinitions(cur_block,
                                                           track_tmps=True,
                                                           function_handler=CLibFunctionHandler(self.project),
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
                        if isinstance(node.irsb.next, DataSensitiveRdTmp):
                            if node.irsb.next.tmp != d.atom.tmp_idx:
                                dead_defs_stmt_idx.add(d.codeloc.stmt_idx)
                            else:
                                used_tmp_indices.add(d.atom.tmp_idx)
                        else:
                            dead_defs_stmt_idx.add(d.codeloc.stmt_idx)

                else:
                    uses = rd.all_uses.get_uses(d)
                    if not uses:
                        # is entirely possible that at the end of the block, a register definition is not used.
                        # however, it might be used in future blocks.
                        # so we only remove a definition if the definition is not alive anymore at the end of the block
                        defs_ = set()
                        if isinstance(d.atom, atoms.Register):
                            try:
                                vs: 'MultiValues' = live_defs.register_definitions.load(d.atom.reg_offset, size=d.atom.size)
                            except:
                                import ipdb;ipdb.set_trace()

                        elif isinstance(d.atom, atoms.MemoryLocation) and isinstance(d.atom.addr, SpOffset):
                            stack_addr = live_defs.stack_offset_to_stack_addr(d.atom.addr.offset)
                            try:
                                vs: 'MultiValues' = live_defs.stack_definitions.load(stack_addr, size=d.atom.size,
                                                                                 endness=d.atom.endness)
                            except:
                                import ipdb;ipdb.set_trace()
                        else:
                            continue

                        for values in vs.values():
                            for value in values:
                                defs_.update(live_defs.extract_defs(value))

                        if d not in defs_:
                            if d.codeloc.block_id and d.codeloc.block_id.vm_vpc == 5368833408 and d.codeloc.ins_addr == 0x14006a455:
                                import ipdb;ipdb.set_trace()
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
                        continue
                    elif stmt.guard.con.value == 1:
                        node.irsb.next = pyvex.expr.Const(stmt.dst)
                        continue
                new_statements.append(stmt)

            if new_statements != node.irsb.statements:
                changed = True
            # Dealing with empty blocks i.e. removing them
            if len(new_statements) == 0:
                if len(list(dsa_new_model.graph.successors(node))) >0:
                    succ = dsa_new_model.graph.successors(node)
                    succ = next(succ)
                    preds = dsa_new_model.graph.predecessors(node)
                    to_remove = False
                    for pred in preds:
                        pred_edge_data = dsa_new_model.graph.get_edge_data(pred, node)
                        # Reassigning the next expression of the previous
                        if not pred.is_simprocedure:
                            dsa_new_model.graph.add_edge(pred, succ, jumpkind=pred_edge_data['jumpkind'])
                            if len(pred.irsb.statements) > 0 and isinstance(pred.irsb.statements[-1], pyvex.stmt.Exit):
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
                        dsa_new_model.graph.remove_node(node)
                else:
                    dsa_new_model.graph.remove_node(node)
            else:
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
    def block_arithmetic_simplifications(self, cfg, proj, start_state=None):
        # Naming this this CFGEmulated so that certain other analysis can uses the results from this
        print("Block arithmetic simplification")
        #new_model = self.new_model_graph(cfg.graph, proj, 'CFGEmulated')
        new_model = cfg
        for node in list(new_model.nodes()):
            if not node.is_simprocedure:
                cur_block = angr.Block(node.irsb.addr, project=proj, vex=node.irsb)
                result = proj.analyses.ReachingDefinitions(cur_block, track_tmps=True,  observation_points=[('node', node.addr, OP_AFTER)], dep_graph=DepGraph())

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
                        if isinstance(cur_stmt.data, pyvex.expr.Binop) and cur_stmt.data.op in ["Iop_Add32", "Iop_Add64", "Iop_Sub32", "Iop_Sub64"] and len(successors) == 1:
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
        new_cfg_graph = old_graph.__class__()
        new_nodes = []
        node_map = {}
        node_map_by_addr = defaultdict(list)

        # not setting the attributes for the model since they will *most likely* be not used on the analysis
        new_model = proj.kb.cfgs.new_model(identifier)
        new_model.graph = new_cfg_graph

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

        new_cfg_graph.add_nodes_from(new_nodes)
        new_cfg_graph.add_edges_from(new_edges)

        new_model._nodes = node_map
        new_model._nodes_by_addr = node_map_by_addr

        return new_model


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
    def data_sensitive_graph(self, filename, start_addr, start_state, cfg_fast_graph, avoid_runs, remove_insts=None):
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

        cfg = proj.analyses.CFGVMDeobfuscation(fail_fast=True,
                                        data_sensitive=True,
                                        starts=(start_addr,),
                                        initial_state=start_state,
                                        max_iterations=1,
                                        resolve_indirect_jumps=False,
                                        keep_state=False,
                                        state_add_options=angr.sim_options.refs| {angr.sim_options.DO_CCALLS, angr.sim_options.REPLACEMENT_SOLVER},
                                        iropt_level=1,
                                        cfg_fast_graph=cfg_fast_graph,
                                        avoid_runs=avoid_runs,
                                        remove_insts=remove_insts
                                        # enable_advanced_backward_slicing=True
                                        )
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

        ## Setting the input state for the first node(need to automate this)
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
            node = new_model._nodes[key]
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
    def draw_graph(self, cfg, filename):
        print("saving graph "+str(filename))
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
        print("Drawing graph")
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
        print("Done")

    ############### !!!! This only works under the assumption that no new statements are added to the final graph, i.e. statements are only removed from the final graph ################
    def compare_vex(self, initial_cfg, final_cfg, folder_name):
        print("Comparing VEX")
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
        print("Done")

    def pattern_match_to_x86_instructions(self, final_cfg, orig_cfg, proj, folder_name):
        print("Pattern match to x86")
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
        print("Done")

from angr.analyses import AnalysesHub
AnalysesHub.register_default('VMDeobfuscation', VMDeobfuscation)
