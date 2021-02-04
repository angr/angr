import angr
import logging
import pyvex
import claripy
import networkx as nx
import re
import copy
import os
from collections import defaultdict
from angr.code_location import CodeLocation
from angr.analyses.reaching_definitions.subject import Subject
from angr.knowledge_plugins.cfg.cfg_node import CFGENode
from angr.knowledge_plugins.key_definitions.atoms import Tmp, Register, MemoryLocation
from ailment.converter import IRSBConverter
from ailment.manager import Manager
from ..reaching_definitions.dep_graph import DepGraph
from ..reaching_definitions.external_codeloc import ExternalCodeLocation
from ..analysis import Analysis
from ..cfg.cfg_vm_deobfuscation import StackPointerAnnotation, StackTouchedAnnotation, DataRegionAnnotation, annotate_with_new_replacements
from ... import BP, BP_BEFORE, BP_AFTER
from ...knowledge_plugins.key_definitions import atoms
from ...engines.light.data import SpOffset


logger = logging.getLogger('angr.analyses.cfg.cfg_vm_deobfuscation').setLevel(logging.DEBUG)
#filename = "/media/sf_Security/sample_vm/sample_vm_with_input"
#filename = "/media/sf_Security/sample_vm/a.out"
filename = "/media/sf_Security/sample_vm/simple_vm_set/sample_vm_with_input/samplevm_with_input"
#filename = "/media/sf_Security/sample_vm/simple_vm_set/sample_vm_with_two_input/samplevm_with_two_input"
#filename = "/media/sf_Security/sample_vm/simple_vm_set/sample_vm_with_input_loop/samplevm_with_input_loop"
#filename = "/media/sf_Security/sample_vm/sample_vm_with_input_depend_branch"
#filename="/media/sf_Security/sample_vm/tigress-challenges/Linux-x86_64/0000/challenge-0"


class StatementNode:
    def __init__(self, stmt, codeloc, def_atom=None):
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

    def __init__(self, vm_vpc_addr, start_addr=None, start_state=None, cfg_fast_graph=None, avoid_runs=None):

        start_addr = start_addr
        cfg, proj = self.data_sensitive_graph(self.project.filename, vm_vpc_addr, start_addr=start_addr, start_state=start_state, cfg_fast_graph=cfg_fast_graph, avoid_runs=avoid_runs)

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

        original_functions = list(cfg.kb.functions.items())

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

        # DCE commented out temporarily to make testing faster for block simplifications
        for i in range(11):
            new_cfg = self.dead_code_elimination(new_cfg, proj, start_addr=start_addr, vm_vpc_addr=vm_vpc_addr, start_state=start_state)
            self.draw_graph(new_cfg, os.path.join(folder_name, str(i)+"_dce_result.svg"))

        #elf.simplifications(new_cfg, proj, start_addr=start_addr, vm_vpc_addr=vm_vpc_addr)
        # Need to copy the arith simplifications back to the node.irsb, for below
        #new_cfg = self.block_arithmetic_simplifications(new_cfg, proj)
        new_cfg = self._eliminate_dead_assignments(new_cfg, proj)
        self.draw_graph(new_cfg, os.path.join(folder_name,  "final_result.svg"))
        self.draw_original_graph(new_cfg, os.path.join(folder_name, "comparision_graph.svg"), proj)
        self.compare_vex(initial_cfg, new_cfg, folder_name)
        self.pattern_match_to_x86_instructions(new_cfg, proj, folder_name)

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

    def _eliminate_dead_assignments(self, cfg, proj, start_addr=None):

        dsa_new_model = self.new_model_graph(cfg.graph, proj, 'dsa')
        for node in dsa_new_model.nodes():
            if node.addr == 0x400cf7:
                start_node = node
                break

        new_statements = [ ]
        #start_state = ReachingDefinitionsState()
        rd = self.project.analyses.ReachingDefinitions(subject=Subject((dsa_new_model.graph, start_node)),
                                                       track_tmps=True,
                                                       )

        # used_tmp_indices = set(rd.one_result.tmp_uses.keys())
        # live_defs = rd.one_result

        # Find dead assignments
        dead_defs_locs = set()
        all_defs = rd.all_definitions
        for d in all_defs:
            if isinstance(d.codeloc, ExternalCodeLocation) or d.dummy:
                continue

            if not isinstance(d.atom, atoms.Tmp):
                uses = rd.all_uses.get_uses(d)
                if not uses:
                    if isinstance(d.atom, atoms.MemoryLocation):
                        print(d)
                        print(cfg.model.get_node(d.codeloc.block_id).irsb.pp())
                        # import ipdb;
                        # ipdb.set_trace()
                    # is entirely possible that at the end of the block, a register definition is not used.
                    # however, it might be used in future blocks.
                    # so we only remove a definition if the definition is not alive anymore at the end of the block
                    # if isinstance(d.atom, atoms.Register):
                    #     if d not in live_defs.register_definitions.get_variables_by_offset(d.atom.reg_offset):
                    dead_defs_locs.add(d.codeloc)
                    # if isinstance(d.atom, atoms.MemoryLocation) and isinstance(d.atom.addr, SpOffset):
                    #     if d not in live_defs.stack_definitions.get_variables_by_offset(d.atom.addr.offset):
                            #dead_defs_locs.add(d.codeloc)


        # Remove dead assignments
        for node in dsa_new_model.nodes():
            for idx, stmt in enumerate(node.irsb.statements):
                if isinstance(stmt, pyvex.stmt.IMark):
                    cur_ins_addr = stmt.addr

                stmt_loc = CodeLocation(node.irsb.addr,
                            idx,
                            cur_ins_addr,
                            context=tuple(),
                            block_id=node.block_id)

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
                                               jumpkind=node.irsb.jumpkind)

        # Returning a new CFGVMDeobfuscation object with the updated graph
        if start_state:
            initial_input_state = start_state
        else:
            initial_input_state = proj.factory.blank_state(addr=start_addr,
                                                           mode='fastpath',
                                                           add_options=angr.sim_options.refs | {
                                                               angr.sim_options.REPLACEMENT_SOLVER,
                                                               angr.sim_options.DO_CCALLS})
        dsa_new_model._nodes_by_addr[start_addr][0].input_state = initial_input_state
        new_cfg = proj.analyses.CFGVMDeobfuscation(model=dsa_new_model, keep_state=True, iropt_level=1,
                                                   resolve_indirect_jumps=True, max_iterations=1,
                                                   vm_vpc_addr=vm_vpc_addr)
        return new_cfg

    # def function_dead_assignment_elimination(self, cfg, proj, original_functions):
    #     for node in cfg.model.nodes():
    #         if node.addr == 0x40087f:
    #             import ipdb;
    #             ipdb.set_trace()
    #             result = proj.analyses.ReachingDefinitions(Subject((cfg.model.graph, node)), track_tmps=True,
    #                                                        dep_graph=DepGraph())

    def block_arithmetic_simplifications(self, cfg, proj):
        for node in list(cfg.graph.nodes()):
            if not node.is_simprocedure:
                cur_block = angr.Block(node.irsb.addr, project=proj, vex=node.irsb)
                result = proj.analyses.ReachingDefinitions(cur_block, track_tmps=True, observe_all=True, dep_graph=DepGraph())

                ## create stmt dependency graph
                stmt_graph = StatementGraph()
                for ind, stmt in enumerate(node.irsb.statements):
                    if isinstance(stmt, pyvex.stmt.IMark):
                        cur_ins_addr = stmt.addr
                        continue
                    code_loc = CodeLocation(node.addr, ind, ins_addr=cur_ins_addr)
                    if code_loc in result.all_uses_by_code_loc:
                        for use in result.all_uses_by_code_loc[code_loc]:
                            use_stmt = node.irsb.statements[use.codeloc.stmt_idx]
                            tmp_atom = self.convert_to_atom(use_stmt, node.irsb.tyenv, node.irsb.arch.byte_width)
                            if isinstance(use.codeloc, ExternalCodeLocation):
                                use_node = StatementNode(None, use.codeloc, def_atom=use.atom)
                            else:
                                use_node = StatementNode(use_stmt, use.codeloc, def_atom=tmp_atom)
                            stmt_atom = self.convert_to_atom(stmt, node.irsb.tyenv, node.irsb.arch.byte_width)
                            stmt_node = StatementNode(stmt, code_loc, def_atom=stmt_atom)
                            stmt_graph.add_edge(stmt_node, use_node)
                    else:
                        ## These are independent statements so we do not have atoms associated with them
                        stmt_node = StatementNode(stmt, code_loc)
                        stmt_graph.add_node(stmt_node)

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
                for sub_graph in sub_graphs:
                    stmt_node_queue = []
                    for stmt_node in sub_graph.nodes():
                        if sub_graph.graph.out_degree(stmt_node) == 0:
                            stmt_node_queue.append(stmt_node)
                            print(stmt_node)

                    simplified_statements = []
                    while len(stmt_node_queue) > 0:
                        cur_stmt_node = stmt_node_queue.pop(0)
                        preds = list(sub_graph.graph.predecessors(cur_stmt_node))
                        stmt_node_queue = stmt_node_queue + preds

                        if isinstance(cur_stmt_node.codeloc, ExternalCodeLocation):
                            continue
                        cur_stmt = cur_stmt_node.stmt
                        simplified_statements.append(cur_stmt)
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

                        successors = list(sub_graph.graph.successors(cur_stmt_node))
                        if isinstance(cur_stmt.data, pyvex.expr.Binop) and cur_stmt.data.op in ["Iop_Add32", "Iop_Sub32"] and len(successors) == 1:
                            for arg in cur_stmt.data.args:
                                if isinstance(arg, pyvex.expr.Const):
                                    const_0 = arg.con.value
                            if cur_stmt.data.op in ["Iop_Add32", "Iop_Sub32"]:
                                const_0 = -const_0
                            successor = successors[0]
                            successors = list(sub_graph.graph.successors(successor))
                            if isinstance(successor.stmt, pyvex.stmt.WrTmp) and isinstance(successor.stmt.data, pyvex.expr.Unop) and successor.stmt.data.op == "Iop_64to32":
                                successor = successors[0]
                                successors = list(sub_graph.graph.successors(successor))
                                if isinstance(successor.stmt, pyvex.stmt.WrTmp) and isinstance(successor.stmt.data, pyvex.expr.Unop) and successor.stmt.data.op == "Iop_32Uto64":
                                    successor = successors[0]
                                    successors = list(sub_graph.graph.successors(successor))
                                    if isinstance(successor.stmt.data, pyvex.expr.Binop) and successor.stmt.data.op in ["Iop_Add32", "Iop_Sub32"] and len(successors) == 1:
                                        for arg in successor.stmt.data.args:
                                            if isinstance(arg, pyvex.expr.Const):
                                                const_1 = arg
                                        if successor.stmt.data.op in ["Iop_Add32", "Iop_Sub32"]:
                                            const_1 = -const_1
                                        successor = successors[0]
                                        successors = list(sub_graph.graph.successors(successor))
                                        if isinstance(successor.stmt, pyvex.stmt.WrTmp) and isinstance(successor.stmt.data, pyvex.expr.Unop) and successor.stmt.data.op == "Iop_64to32":
                                            successor = successors[0]
                                            successors = list(sub_graph.graph.successors(successor))
                                            if isinstance(successor.stmt, pyvex.stmt.WrTmp) and isinstance(successor.stmt.data, pyvex.expr.Get):
                                                simplified_statements[-5] = pyvex.stmt.WrTmp(simplified_statements[-2].tmp, simplified_statements[-5].data)
                                                simplified_statements[-1] = pyvex.stmt.WrTmp(cur_stmt.tmp, pyvex.expr.Binop(cur_stmt.data.op, [cur_stmt.data.args[0], pyvex.expr.Const(cur_stmt.data.args[1].__class__(const_0.con.value+const_1.con.value))]))
                                                simplified_statements.pop(-4)
                                                simplified_statements.pop(-3)
                                                simplified_statements.pop(-2)

                        # using the full size register for the respective binary i.e. rax or eax
                        # x86
                        # add eax,const1         ==> add eax, const1+const2
                        # add eax, const2
                        # VEX
                        # t2 = GET:I32(eax)                     t2 = GET:I32(eax)
                        # t0 = Add32(t2, 0x00000001)    ==>     t3 = Add32(t2, 0x00000003)
                        # t3 = Add32(t0, 0x00000002)
                        successors = list(sub_graph.graph.successors(cur_stmt_node))
                        if isinstance(cur_stmt.data, pyvex.expr.Binop) and cur_stmt.data.op in ["Iop_Add32", "Iop_Add64", "Iop_Sub32", "Iop_Sub64"] and len(successors) == 1:
                            for arg in cur_stmt.data.args:
                                if isinstance(arg, pyvex.expr.Const):
                                    const_0 = arg.con.value
                            if cur_stmt.data.op in ["Iop_Sub32", "Iop_Sub64"]:
                                const_0 = -const_0
                            successor = successors[0]
                            if isinstance(successor.codeloc, ExternalCodeLocation):
                                continue

                            successors = list(sub_graph.graph.successors(successor))
                            predecessors = list(sub_graph.graph.predecessors(successor))
                            if isinstance(successor.stmt.data, pyvex.expr.Binop) and successor.stmt.data.op in ["Iop_Add32", "Iop_Add64", "Iop_Sub32", "Iop_Sub64"] and len(successors) == 1 and len(predecessors) == 1:
                                for arg in successor.stmt.data.args:
                                    if isinstance(arg, pyvex.expr.Const):
                                        const_1 = arg.con.value
                                if successor.stmt.data.op in ["Iop_Sub32", "Iop_Sub64"]:
                                    const_1 = -const_1
                                simplified_statements[-1] = pyvex.stmt.WrTmp(cur_stmt.tmp, pyvex.expr.Binop(cur_stmt.data.op, [pyvex.expr.RdTmp(simplified_statements[-3].tmp), pyvex.expr.Const(cur_stmt.data.args[1].__class__(const_0+const_1))]))
                                simplified_statements.pop(-2)
                                import ipdb;
                                ipdb.set_trace()
                                for stmt in simplified_statements:
                                    print(stmt)

                ## reconstrcut the statements from the simplififed graph
        return

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
                                        data_sensitive=True ,
                                        vm_vpc_addr=vm_vpc_addr,
                                        starts=[start_addr],
                                        initial_state=start_state,
                                        max_iterations=1,
                                        resolve_indirect_jumps=False, ##### Need to resolve the issue that arises when this is set to True
                                        keep_state=True,
                                        state_add_options=angr.sim_options.refs| {angr.sim_options.DO_CCALLS},
                                        iropt_level=1,
                                        cfg_fast_graph=cfg_fast_graph,
                                        avoid_runs=avoid_runs)
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

    def simplifications(self, cfg, proj, start_addr, vm_vpc_addr, start_state=None):
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
        if start_state:
            initial_input_state = start_state
        else:
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
    def dead_code_elimination(self, cfg, proj, start_addr, vm_vpc_addr, start_state):
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
                    # Check for stmts with no outgoing edges for deadcode
                    if len(ddg._stmt_graph.out_edges([location])) != 0:
                        print("Dependencies of: "+stmt.__str__(arch=node.irsb.arch, tyenv=node.irsb.tyenv))
                        for out_edges in ddg._stmt_graph.out_edges([location]):
                            print(out_edges[1])
                        new_stmts.append(stmt)
                    # check if there's a Store from a symbolic memory address
                    elif (isinstance(stmt, pyvex.stmt.Store) and not type(stmt.addr) == pyvex.expr.Const):
                        new_stmts.append(stmt)

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
                                if pred.irsb.statements[-1].dst.value == node.irsb.addr:
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
                                                       jumpkind=node.irsb.jumpkind)

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
