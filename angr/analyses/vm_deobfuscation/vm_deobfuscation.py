import angr
import logging
import pyvex
from angr.analyses.code_location import CodeLocation

filename = "/media/sf_Security/sample_vm/a.out"

####### Run the data sensisitve, loop unrolling, CFGEmulated analysis
def data_sensitive_graph(filename):
    logger = logging.getLogger('angr.analyses.cfg.cfg_emulated').setLevel(logging.DEBUG)
    proj = angr.Project(filename)
    main = proj.loader.main_object.get_symbol("main")
    start_state = proj.factory.blank_state(addr=main.rebased_addr,
                                           add_options = {angr.sim_options.REPLACEMENT_SOLVER,
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
    prop = proj.analyses.PropagatorEmulated(graph=cfg.graph, iropt_level=0)
    for key, value in prop.replacements.items():
        node = cfg._graph_get_node(key)
        new_stmts = node.irsb.statements

        for stmt, repl_pair in value.items():
            for old, new in repl_pair.items():
                new_stmts[stmt.stmt_idx].replace_expression(old, new)

####### Dead Cod Elimination
def dead_code_elimination(cfg, proj):
    ddg = proj.analyses.DDG(cfg, start=cfg.functions['main'].addr)
    for node in list(cfg.graph.nodes()):
        old_stmts = node.irsb.statements
        new_stmts = []
        print(node.irsb.pp())
        print(node.block_id)
        for ind, stmt in enumerate(old_stmts):
            if isinstance(stmt, pyvex.stmt.IMark) or isinstance(stmt, pyvex.stmt.AbiHint) or isinstance(stmt, pyvex.stmt.Store):
                new_stmts.append(stmt)
                continue
            if isinstance(stmt, pyvex.stmt.Put) and stmt.offset == 0x30:
                new_stmts.append(stmt)
                continue
            location = CodeLocation(node.irsb.addr , ind, node.block_id)
            if len(ddg._stmt_graph.out_edges([location])) != 0:
                #if node.irsb.addr == 0x40050f:
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
constant_propagation(cfg, proj)
dead_code_elimination(cfg, proj)