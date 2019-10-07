import angr
import logging
import pyvex
from angr.analyses.code_location import CodeLocation
import copy
from collections import defaultdict
from angr.knowledge_plugins.cfg.cfg_node import CFGENode

filename = "/media/sf_Security/sample_vm/a.out"

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
    new_cfg_graph = cfg.graph.__class__()
    new_nodes = []
    node_map = {}
    node_map_by_addr = defaultdict(list)
    for node in cfg.graph.nodes():
        new_node = CFGENode(irsb=copy.deepcopy(node.irsb),
                            block_id=copy.deepcopy(node.block_id),
                            size=copy.deepcopy(node.size),
                            data_offset=copy.deepcopy(node.data_offset),
                            looping_times=copy.deepcopy(node.looping_times),
                            callstack_key=copy.deepcopy(node.callstack_key),
                            simprocedure_name=copy.deepcopy(node.simprocedure_name),
                            addr=copy.deepcopy(node.addr),
                            input_state=None,
                            final_states=None,
                            cfg=cfg.model)

        new_nodes.append(new_node)
        node_map[new_node.block_id] = new_node
        node_map_by_addr[new_node.addr].append(new_node)

    new_edges = []
    for src, dst, data in cfg.graph.edges(data=True):
        new_edges.append((node_map[src.block_id], node_map[dst.block_id], {'jumpkind': data['jumpkind']}))

    new_cfg_graph.add_nodes_from(new_nodes)
    new_cfg_graph.add_edges_from(new_edges)

    initial_input_state = proj.factory.blank_state(addr=0x4005e8, add_options={angr.sim_options.REPLACEMENT_SOLVER,
                                          angr.sim_options.DO_CCALLS})
    import pdb
    pdb.set_trace()
    node_map_by_addr[0x4005e8][0].input_state = initial_input_state

    #Should I create a new copy of cfg?? to do the replacements in ?? ## yes yes i should
    prop = proj.analyses.PropagatorEmulated(graph=new_cfg_graph, iropt_level=0)

    for key, value in prop.replacements.items():
        node = node_map[key]
        new_stmts = node.irsb.statements

        for stmt, repl_pair in value.items():
            for old, new in repl_pair.items():
                new_stmts[stmt.stmt_idx].replace_expression(old, new)

    #Run the emulation on the new graph to update the state attributes
    proj.analyses.CFGEmulated(graph=new_cfg_graph)
    return new_cfg_graph, node_map, node_map_by_addr

####### Dead Cod Elimination
def dead_code_elimination(cfg, proj):
    ddg = proj.analyses.DDG(cfg, 0x4005e8)
    for node in list(cfg.graph.nodes()):
        old_stmts = node.irsb.statements
        new_stmts = []
        print(node.irsb.pp())
        print(node.block_id)
        for ind, stmt in enumerate(old_stmts):
            if isinstance(stmt, pyvex.stmt.IMark) or isinstance(stmt, pyvex.stmt.AbiHint)\
                    or isinstance(stmt, pyvex.stmt.Store) or isinstance(stmt, pyvex.stmt.Exit):
                new_stmts.append(stmt)
                continue

            if not (isinstance(stmt.data, pyvex.expr.Const)):
                new_stmts.append(stmt)
                continue

            # Check for Put(rip) or Put(rsp)
            if isinstance(stmt, pyvex.stmt.Put) and (stmt.offset == 0x30):
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

cfg, proj = data_sensitive_graph(filename)
new_cfg_graph, new_node_map, new_node_map_by_addr = constant_propagation(cfg, proj)
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
new_cfg._graph = new_cfg_graph
new_cfg._model = new_cfg.kb.cfgs.new_model("new_model")
new_cfg._model._iropt_level = 0
new_cfg._model._nodes = new_node_map
new_cfg._model._nodes_by_addr = new_node_map_by_addr
new_cfg._model.graph = new_cfg_graph
dead_code_elimination(new_cfg, proj)