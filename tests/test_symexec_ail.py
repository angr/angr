import angr
import angr.analyses.decompiler
import claripy
import logging
import nose
import nose.tools
import os

from angr import SimState
from angr.engines import SimEngineAIL

l = logging.getLogger('angr.tests.test_symexec_ail')


test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests'))

def test_simple():

    p = angr.Project(os.path.join(test_location, 'x86_64', 'fauxware'), auto_load_libs=False)
    cfg = p.analyses.CFG(collect_data_references=True, normalize=True)

    main_func = cfg.kb.functions['main']

    # convert function blocks to AIL blocks
    clinic = p.analyses.Clinic(main_func)

    # recover regions
    ri = p.analyses.RegionIdentifier(main_func, graph=clinic.graph)

    # structure it
    rs = p.analyses.RecursiveStructurer(ri.region)

    # simplify it
    s = p.analyses.RegionSimplifier(rs.result)

    codegen = p.analyses.StructuredCodeGenerator(main_func, s.result, cfg=cfg)
    print(codegen.text)

def test_loadg_no_constraint_creation():
    #state = SimState(arch='armel', mode='symbolic')
    engine = SimEngineAIL()

    # from angr.engines.vex.statements.loadg import SimIRStmt_LoadG

    # stmt = pyvex.IRStmt.LoadG('Iend_LE', 'ILGop_16Uto32',
    #                           0, # dst
    #                           pyvex.IRExpr.Const(pyvex.const.U32(0x2000)), # addr (src)
    #                           pyvex.IRExpr.Const(pyvex.const.U32(0x1337)), # alt
    #                           pyvex.IRExpr.RdTmp(1)  # guard
    #                           )
    # tyenv = pyvex.IRTypeEnv(state.arch)
    # tyenv.types = [ 'Ity_I32', 'Ity_I32' ]
    # state.scratch.set_tyenv(tyenv)
    # state.scratch.temps[1] = state.solver.BVS('tmp_1', 32)
    # SimIRStmt_LoadG(engine, state, stmt)

    # # LOADG should not create new constraints - it is a simple conditional memory read. The conditions should only be
    # # used inside the value AST to guard the memory read.
    # assert not state.solver.constraints
    # assert state.scratch.temps[0] is not None
    # assert state.scratch.temps[0].variables.issuperset(state.scratch.temps[1].variables)
    # assert state.scratch.temps[0].op == 'If'


if __name__ == '__main__':
    g = globals().copy()
    for func_name, func in g.items():
        if func_name.startswith("test_") and hasattr(func, "__call__"):
            func()
