import angr
import logging
import pyvex
from angr.analyses.code_location import CodeLocation
import copy
from collections import defaultdict
from angr.knowledge_plugins.cfg.cfg_node import CFGENode

filename = "/media/sf_Security/sample_vm/sample_vm_with_input"

## creates a new model which contains a graph that is structurally similar to the old one but resets the states
## and keeps certain attributes
def new_model_graph(old_graph, proj, identifier):
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
                            data_offset=copy.deepcopy(node.data_offset),
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

####### Run the data sensisitve, loop unrolling, CFGEmulated analysis
def data_sensitive_graph(filename):
    logger = logging.getLogger('angr.analyses.cfg.cfg_emulated').setLevel(logging.DEBUG)
    proj = angr.Project(filename)
    main = proj.loader.main_object.get_symbol("main")
    start_state = proj.factory.blank_state(addr=main.rebased_addr,
                                           add_options={angr.sim_options.REPLACEMENT_SOLVER,
                                                          angr.sim_options.DO_CCALLS})
    cfg = proj.analyses.CFGEmulated(fail_fast=True,
                                    data_sensitive=True ,
                                    starts=[main.rebased_addr],
                                    initial_state=start_state,
                                    max_iterations=5,
                                    resolve_indirect_jumps=True,
                                    keep_state=True,
                                    state_add_options=angr.sim_options.refs| {angr.sim_options.DO_CCALLS},
                                    iropt_level=0)
    return cfg, proj


####### Constant Propagation
def constant_propagation(cfg, proj):
    old_graph = cfg.graph
    new_model = new_model_graph(old_graph, proj, "temporary1")
    new_cfg_graph = new_model.graph

    ## Setting the input state for the first node(need to automate this)
    main = proj.loader.main_object.get_symbol("main")
    initial_input_state = proj.factory.blank_state(addr=main.rebased_addr,
                                                   mode='fastpath',
                                                   add_options=angr.sim_options.refs | {angr.sim_options.REPLACEMENT_SOLVER, angr.sim_options.DO_CCALLS})


    new_model._nodes_by_addr[main.rebased_addr][0].input_state = initial_input_state
    ## find the replacements
    prop = proj.analyses.PropagatorEmulated(graph=new_cfg_graph, iropt_level=0, start=main.rebased_addr)

    ## do the actual replacements
    for key, value in prop.replacements.items():
        node = new_model._nodes[key]
        if not node.is_simprocedure:
            new_stmts = node.irsb.statements
            for stmt, repl_pair in value.items():
                for old, new in repl_pair.items():
                    new_stmts[stmt.stmt_idx].replace_expression(old, new)

    ### Clearing the states for the newly created graph (or should I create a new copy again)
    new_model = new_model_graph(new_cfg_graph, proj, "temporary2")
    new_cfg_graph = new_model.graph

    ## Setting the input state for the first node(need to automate this)
    new_model._nodes_by_addr[main.rebased_addr][0].input_state = initial_input_state

    #Run the emulation on the new graph to update the state attributes
    proj.analyses.CFGEmulated(graph=new_cfg_graph)

    return new_model

####### Dead Cod Elimination
def dead_code_elimination(cfg, proj):
    main = proj.loader.main_object.get_symbol("main")
    ddg = proj.analyses.DDG(cfg, main.rebased_addr)
    for node in list(cfg.graph.nodes()):
        if not node.is_simprocedure:
            print(node.simprocedure_name)
            old_stmts = node.irsb.statements
            new_stmts = []
            print(node.irsb.pp())
            print(node.block_id)
            for ind, stmt in enumerate(old_stmts):
                if isinstance(stmt, pyvex.stmt.IMark) or isinstance(stmt, pyvex.stmt.AbiHint)\
                         or isinstance(stmt, pyvex.stmt.Exit):
                    new_stmts.append(stmt)
                    continue

                location = CodeLocation(node.irsb.addr , ind, node.block_id)
                if len(ddg._stmt_graph.out_edges([location])) != 0:
                    print(stmt)
                    print(ddg._stmt_graph.out_edges([location]))
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

cfg, proj = data_sensitive_graph(filename)
const_prop_model = constant_propagation(cfg, proj)

### Just to create a new CFGEmulated instance
main = proj.loader.main_object.get_symbol("main")
start_state = proj.factory.blank_state(addr=main.rebased_addr,
                                       add_options={angr.sim_options.REPLACEMENT_SOLVER,
                                                    angr.sim_options.DO_CCALLS})
new_cfg = proj.analyses.CFGEmulated(fail_fast=True,
                                    data_sensitive=True ,
                                    starts=[main.rebased_addr],
                                    initial_state=start_state,
                                    max_iterations=5,
                                    resolve_indirect_jumps=True,
                                    keep_state=True,
                                    state_add_options=angr.sim_options.refs | {angr.sim_options.DO_CCALLS},
                                    iropt_level=0)
new_cfg._graph = const_prop_model.graph
new_cfg._model = const_prop_model
dead_code_elimination(new_cfg, proj)

## Doing DCE second time
# dce2_new_model = new_model_graph(new_cfg.graph, proj, 'dce2')
#
# new_cfg._graph = dce2_new_model.graph
# new_cfg._model = dce2_new_model
# dead_code_elimination(new_cfg, proj)