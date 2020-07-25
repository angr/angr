import angr
import logging
import pyvex
import networkx as nx
import re
import copy
import os
from collections import defaultdict
from angr.code_location import CodeLocation
from angr.knowledge_plugins.cfg.cfg_node import CFGENode
from ailment.converter import IRSBConverter
from ailment.manager import Manager
from ..analysis import Analysis
from ..cfg.cfg_vm_deobfuscation import StackPointerAnnotation, StackTouchedAnnotation, DataRegionAnnotation
from ... import BP, BP_BEFORE, BP_AFTER

logger = logging.getLogger('angr.analyses.cfg.cfg_vm_deobfuscation').setLevel(logging.DEBUG)
#filename = "/media/sf_Security/sample_vm/sample_vm_with_input"
#filename = "/media/sf_Security/sample_vm/a.out"
filename = "/media/sf_Security/sample_vm/simple_vm_set/sample_vm_with_input/samplevm_with_input"
#filename = "/media/sf_Security/sample_vm/simple_vm_set/sample_vm_with_two_input/samplevm_with_two_input"
#filename = "/media/sf_Security/sample_vm/simple_vm_set/sample_vm_with_input_loop/samplevm_with_input_loop"
#filename = "/media/sf_Security/sample_vm/sample_vm_with_input_depend_branch"
#filename="/media/sf_Security/sample_vm/tigress-challenges/Linux-x86_64/0000/challenge-0"


class VMDeobfuscation(Analysis):

    def __init__(self, vm_vpc_addr, start_addr=None, start_state=None, cfg_fast_graph=None):

        # Delayed import
        import ailment.analyses  # pylint:disable=redefined-outer-name,unused-import

        # start_addr = 0x4006d1
        start_addr = start_addr
        cfg, proj = self.data_sensitive_graph(self.project.filename, vm_vpc_addr, start_addr=start_addr, start_state=start_state, cfg_fast_graph=cfg_fast_graph)
        self.vm_instruction_addrs = cfg.vm_instruction_addresses

        folder_name = os.path.dirname(self.project.filename)

        ### Might be a problem with Angr's decompiler
        # proj.analyses._init_plugin(VariableRecovery)
        # for cur_func in proj.kb.functions._function_map.values():
        #     proj.analyses.VariableRecovery(cur_func)
        #     dec = proj.analyses.Decompiler(cur_func, cfg=cfg)
        #     if dec.codegen is not None:
        #         print(dec.codegen.text)
        #     else:
        #         print("Failed to decompile")


        initial_cfg = cfg
        self.draw_graph(cfg, os.path.join(folder_name, "input.svg"))
        print("Doing constant propagation")
        new_cfg = self.constant_propagation(cfg, proj, start_addr=start_addr, vm_vpc_addr=vm_vpc_addr, start_state=start_state)

        self.draw_graph(new_cfg, os.path.join(folder_name, "cp_result.svg"))

        # DCE
        for i in range(11):
            new_cfg = self.dead_code_elimination(new_cfg, proj, start_addr=start_addr, vm_vpc_addr=vm_vpc_addr)
            self.draw_graph(new_cfg, os.path.join(folder_name, str(i)+"_dce_result.svg"))

        self.simplifications(new_cfg, proj, start_addr=start_addr, vm_vpc_addr=vm_vpc_addr)
        self.draw_graph(new_cfg, os.path.join(folder_name,  "final_result.svg"))
        self.draw_original_graph(new_cfg, os.path.join(folder_name, "comparision_graph.svg"), proj)
        self.compare_vex(initial_cfg, new_cfg, folder_name)
        self.pattern_match_to_x86_instructions(new_cfg, proj, folder_name)

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
                                branch_trace = copy.deepcopy(node.branch_trace),
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

    def annotate_and_preconstrain_sp(self, start_state):
        actual_stack_end = start_state.solver.eval(start_state.regs.sp)
        start_state.regs.sp = start_state.solver.BVS("precon_sp", 64)
        start_state.regs.sp = start_state.regs.sp.annotate(StackPointerAnnotation(1))
        start_state.preconstrainer.preconstrain(actual_stack_end, start_state.regs.sp)
    ####### Run the data sensisitve, loop unrolling, CFGEmulated analysis
    def data_sensitive_graph(self, filename, vm_vpc_addr, start_addr, start_state, cfg_fast_graph):
        #proj = angr.Project(filename)
        proj = self.project

        if start_state is None:
            if start_addr is None:
                main = proj.loader.main_object.get_symbol("main")
                start_addr = main.rebased_addr

            start_state = proj.factory.blank_state(addr=start_addr,
                                                   add_options={angr.sim_options.REPLACEMENT_SOLVER,
                                                                  angr.sim_options.DO_CCALLS})
        self.annotate_and_preconstrain_sp(start_state)

        cfg = proj.analyses.CFGVMDeobfuscation(fail_fast=True,
                                        data_sensitive=True ,
                                        vm_vpc_addr=vm_vpc_addr,
                                        starts=[start_addr],
                                        initial_state=start_state,
                                        max_iterations=1,
                                        resolve_indirect_jumps=False, ##### Need to resolve the issue that arises when this is set to True
                                        keep_state=True,
                                        state_add_options=angr.sim_options.refs| {angr.sim_options.DO_CCALLS},
                                        iropt_level=1,
                                        cfg_fast_graph=cfg_fast_graph)
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
            if len(state.inspect.mem_read_address.annotations) != 0 and isinstance(
                    (state.inspect.mem_read_address.annotations[0]), StackPointerAnnotation):
                state.inspect.mem_read_expr = state.inspect.mem_read_expr.annotate(StackTouchedAnnotation(1))

        initial_input_state.inspect.add_breakpoint('mem_read',
                                     BP(
                                         BP_AFTER,
                                         action=annotate_stack_read_value
                                     ))

        ### annotating the data region in RCTF 2018
        def annotate_data_region(state):
            state.mem[state.mem[0x601098].uint64_t.resolved + 0x100].byte = state.mem[
                state.mem[0x601098].uint64_t.resolved + 0x100].byte.resolved.annotate(DataRegionAnnotation(1))
            state.mem[state.mem[0x601098].uint64_t.resolved + 0x110].byte = state.mem[
                state.mem[0x601098].uint64_t.resolved + 0x110].byte.resolved.annotate(DataRegionAnnotation(1))
            state.mem[state.mem[0x601098].uint64_t.resolved + 0x145].byte = state.mem[
                state.mem[0x601098].uint64_t.resolved + 0x145].byte.resolved.annotate(DataRegionAnnotation(1))
            state.mem[state.mem[0x601098].uint64_t.resolved + 0x146].byte = state.mem[
                state.mem[0x601098].uint64_t.resolved + 0x146].byte.resolved.annotate(DataRegionAnnotation(1))
            for i in range(32):
                state.mem[state.mem[0x601098].uint64_t.resolved + 0x111 + i].byte = state.mem[
                    state.mem[0x601098].uint64_t.resolved + 0x111 + i].byte.resolved.annotate(DataRegionAnnotation(1))
                state.mem[state.mem[0x601098].uint64_t.resolved + 0x5 + i].byte = state.mem[
                    state.mem[0x601098].uint64_t.resolved + 0x5 + i].byte.resolved.annotate(DataRegionAnnotation(1))

        initial_input_state.inspect.add_breakpoint('instruction', BP(BP_BEFORE, instruction=0x400896, action=annotate_data_region))

        ## annotating and preconstraining the stack pointer
        self.annotate_and_preconstrain_sp(initial_input_state)

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
                        if stmt.stmt_idx == None:
                            node.irsb.next = new
                        else:
                            new_stmts[stmt.stmt_idx].replace_expression(old, new)

        ### Clearing the states for the newly created graph (or should I create a new copy again)
        new_model = self.new_model_graph(new_cfg_graph, proj, "temporary2")

        ## Setting the input state for the first node(need to automate this)
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
    def remove_junk(self, cfg, proj, start_addr):
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

                    location = CodeLocation(node.irsb.addr , ind, node.block_id)
                    if len(ddg._stmt_graph.out_edges([location])) != 0:
                        print(stmt.__str__(arch=node.irsb.arch, tyenv=node.irsb.tyenv))
                        print(ddg._stmt_graph.out_edges([location]))
                        new_stmts.append(stmt)
                    ## check if there's a Store from a symbolic memory address
                    elif (isinstance(stmt, pyvex.stmt.Store) and not type(stmt.addr) == pyvex.expr.Const):
                        new_stmts.append(stmt)

                node.irsb = pyvex.IRSB.empty_block(node.irsb.arch,
                                                   node.irsb.addr,
                                                   statements=new_stmts,
                                                   tyenv=node.irsb.tyenv,
                                                   nxt=node.irsb.next,
                                                   direct_next=node.irsb.direct_next,
                                                   jumpkind=node.irsb.jumpkind)
                print("DCE version")
                print(node.irsb.pp())
                print("\n")
            else:
                print("This is a SimProcedure")
                print(node)
                print("\n")


        ### Returning a new CFGVMDeobfuscation object with the updated graph
        dce_new_model = self.new_model_graph(cfg.graph, proj, 'dce')
        initial_input_state = proj.factory.blank_state(addr=start_addr,
                                                       mode='fastpath',
                                                       add_options=angr.sim_options.refs | {
                                                       angr.sim_options.REPLACEMENT_SOLVER, angr.sim_options.DO_CCALLS})
        dce_new_model._nodes_by_addr[start_addr][0].input_state = initial_input_state
        new_cfg = proj.analyses.CFGVMDeobfuscation(model=dce_new_model, keep_state=True, iropt_level=1, resolve_indirect_jumps=True, max_iterations=1)
        return new_cfg

    def simplifications(self, cfg, proj, start_addr, vm_vpc_addr):
        if start_addr == None:
            main = proj.loader.main_object.get_symbol("main")
            start_addr = main.rebased_addr

        for node in list(cfg.graph.nodes()):
            if not node.is_simprocedure:
                manager = Manager("manager",node.irsb.arch)
                ail_block = IRSBConverter.convert(node.irsb, manager)
                print("Original:")
                print(ail_block)
                print("\nSimplified:")
                simplified_ail_block = proj.analyses.AILBlockSimplifier(ail_block)
                print(simplified_ail_block.result_block)
                print("\n\n")

        ### Returning a new CFGVMDeobfuscation object with the updated graph
        simplified_new_model = self.new_model_graph(cfg.graph, proj, 'simplify1')
        initial_input_state = proj.factory.blank_state(addr=start_addr,
                                                       mode='fastpath',
                                                       add_options=angr.sim_options.refs | {
                                                           angr.sim_options.REPLACEMENT_SOLVER,
                                                       angr.sim_options.DO_CCALLS})

        simplified_new_model._nodes_by_addr[start_addr][0].input_state = initial_input_state
        new_cfg = proj.analyses.CFGVMDeobfuscation(model=simplified_new_model, keep_state=True, iropt_level=1,
                                            resolve_indirect_jumps=True, max_iterations=1, vm_vpc_addr=vm_vpc_addr)
        return new_cfg

    ####### Dead Cod Elimination
    def dead_code_elimination(self, cfg, proj, start_addr, vm_vpc_addr):
        print("Performing dead code elimination")
        if start_addr == None:
            main = proj.loader.main_object.get_symbol("main")
            start_addr = main.rebased_addr
        ddg = proj.analyses.DDG(cfg, start_addr)

        for node in list(cfg.graph.nodes()):
            if not node.is_simprocedure:
                print(node.simprocedure_name)
                old_stmts = node.irsb.statements
                new_stmts = []
                print(node.irsb.pp())
                print(node.block_id)
                for ind, stmt in enumerate(old_stmts):
                    if isinstance(stmt, pyvex.stmt.IMark) and ind == len(old_stmts)-1:
                        continue
                    elif isinstance(stmt, pyvex.stmt.AbiHint) and ind == len(old_stmts)-1:
                        continue
                    elif isinstance(stmt, pyvex.stmt.IMark) and isinstance(old_stmts[ind+1], pyvex.stmt.IMark):
                        continue
                    elif isinstance(stmt, pyvex.stmt.IMark) and isinstance(old_stmts[ind+1], pyvex.stmt.AbiHint):
                        continue
                    elif isinstance(stmt, pyvex.stmt.Exit) and type(stmt.guard) == pyvex.expr.Const:
                        ### Removing conditional statements that depend on a constant
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
                    #### Check for stmts with no outgoing edges for deadcode
                    if len(ddg._stmt_graph.out_edges([location])) != 0:
                        print(stmt.__str__(arch=node.irsb.arch, tyenv=node.irsb.tyenv))
                        print(ddg._stmt_graph.out_edges([location]))
                        new_stmts.append(stmt)
                    ### check if there's a Store from a symbolic memory address
                    elif (isinstance(stmt, pyvex.stmt.Store) and not type(stmt.addr) == pyvex.expr.Const):
                        new_stmts.append(stmt)

                ### Dealing with empty blocks i.e. removing them
                if len(new_stmts) == 0:
                    succ = cfg.graph.successors(node)
                    succ = next(succ)
                    preds = cfg.graph.predecessors(node)
                    to_remove = False
                    for pred in preds:
                        pred_edge_data = cfg.graph.get_edge_data(pred, node)
                        ### Reassigning the next expression of the previous
                        if not pred.is_simprocedure:
                            cfg.graph.add_edge(pred, succ, jumpkind=pred_edge_data['jumpkind'])
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
                                                       jumpkind=node.irsb.jumpkind)

                    print("DCE version")
                    print(node.irsb.pp())
                    print("\n")
            else:
                print("This is a SimProcedure")
                print(node)
                print("\n")

        ### Returning a new CFGVMDeobfuscation object with the updated graph
        dce_new_model = self.new_model_graph(cfg.graph, proj, 'dce')
        initial_input_state = proj.factory.blank_state(addr=start_addr,
                                                       mode='fastpath',
                                                       add_options=angr.sim_options.refs | {
                                                       angr.sim_options.REPLACEMENT_SOLVER, angr.sim_options.DO_CCALLS})
        dce_new_model._nodes_by_addr[start_addr][0].input_state = initial_input_state
        new_cfg = proj.analyses.CFGVMDeobfuscation(model=dce_new_model, keep_state=True, iropt_level=1, resolve_indirect_jumps=True, max_iterations=1, vm_vpc_addr=vm_vpc_addr)
        return new_cfg

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

    def pattern_match_to_x86_instructions(self, final_cfg, proj, folder_name):
        A = nx.nx_agraph.to_agraph(final_cfg.graph)

        #### Iterating over nodes of the initial graph
        for final_cfg_node in final_cfg.graph.nodes():
            original_addresses = proj.factory.block(final_cfg_node.addr).instruction_addrs
            original_instructions = proj.factory.block(final_cfg_node.addr).capstone.insns
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
                        match_result = re.match("\nt\d+\s=\sGET:I64\((\w+)\)\nt\d+\s=\sAdd64\(t\d+,(0xff+\w+)\)\nt\d+\s=\st\d+\nSTle\(t\d+\)\s=\s(\w+)",cur_ins_str)
                        if match_result:
                            x86_stmt_str = x86_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='orange'>" + str(hex(curr_ins_addr))+": mov dword ptr [" + match_result.group(1) + " - "+str((int(match_result.group(2), 16)^0xffffffffffffffff)+1) +"], "+match_result.group(3) +"</FONT>"
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

                        match_result = re.match("\nt\d+\s=\sGET:I64\((\w+)\)\nt\d+\s=\s64to32\(t\d+\)\nSTle\((0x\w+)\)\s=\s(t\d+)", cur_ins_str)
                        if match_result:
                            x86_stmt_str = x86_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='orange'>" + str(hex(curr_ins_addr)) + ": mov " + "dword ptr " + "[" + match_result.group(2) + "], " + match_result.group(1)  + "</FONT>"
                            continue

                        x86_stmt_str = x86_stmt_str + "<BR ALIGN='LEFT'/> <FONT COLOR='blue'>" + str(original_instructions[original_addresses.index(curr_ins_addr)]).replace("\t", " ") + "</FONT>"

            graphviz_node = A.get_node(str(final_cfg_node))
            graphviz_node.attr["label"] = x86_stmt_str+">"
            graphviz_node.attr["shape"] = "box"

        A.layout(prog="dot")
        A.draw(path=os.path.join(folder_name, "x86_regexd_cfg.svg"), format="svg")

from angr.analyses import AnalysesHub
AnalysesHub.register_default('VMDeobfuscation', VMDeobfuscation)
