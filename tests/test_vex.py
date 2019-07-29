import nose
import logging

import pyvex
import claripy

from angr import SimState, SimEngineVEX
import angr.engines.vex.ccall as s_ccall

l = logging.getLogger('angr.tests.test_vex')

#@nose.tools.timed(10)
def test_ccall():
    s = SimState(arch="AMD64")

    l.debug("Testing amd64_actions_ADD")
    l.debug("(8-bit) 1 + 1...")
    arg_l = s.solver.BVV(1, 8)
    arg_r = s.solver.BVV(1, 8)
    cf, pf, af, zf, sf, of = s_ccall.pc_actions_ADD(s, 8, arg_l, arg_r, 0, platform='AMD64')
    nose.tools.assert_true(s.solver.is_true(cf == 0))
    nose.tools.assert_true(s.solver.is_true(pf == 0))
    nose.tools.assert_true(s.solver.is_true(af == 0))
    nose.tools.assert_true(s.solver.is_true(zf == 0))
    nose.tools.assert_true(s.solver.is_true(sf == 0))
    nose.tools.assert_true(s.solver.is_true(of == 0))

    l.debug("(32-bit) (-1) + (-2)...")
    arg_l = s.solver.BVV(-1, 32)
    arg_r = s.solver.BVV(-1, 32)
    cf, pf, af, zf, sf, of = s_ccall.pc_actions_ADD(s, 32, arg_l, arg_r, 0, platform='AMD64')
    nose.tools.assert_true(s.solver.is_true(cf == 1))
    nose.tools.assert_true(s.solver.is_true(pf == 0))
    nose.tools.assert_true(s.solver.is_true(af == 1))
    nose.tools.assert_true(s.solver.is_true(zf == 0))
    nose.tools.assert_true(s.solver.is_true(sf == 1))
    nose.tools.assert_true(s.solver.is_true(of == 0))

    l.debug("Testing pc_actions_SUB")
    l.debug("(8-bit) 1 - 1...",)
    arg_l = s.solver.BVV(1, 8)
    arg_r = s.solver.BVV(1, 8)
    cf, pf, af, zf, sf, of = s_ccall.pc_actions_SUB(s, 8, arg_l, arg_r, 0, platform='AMD64')
    nose.tools.assert_true(s.solver.is_true(cf == 0))
    nose.tools.assert_true(s.solver.is_true(pf == 1))
    nose.tools.assert_true(s.solver.is_true(af == 0))
    nose.tools.assert_true(s.solver.is_true(zf == 1))
    nose.tools.assert_true(s.solver.is_true(sf == 0))
    nose.tools.assert_true(s.solver.is_true(of == 0))

    l.debug("(32-bit) (-1) - (-2)...")
    arg_l = s.solver.BVV(-1, 32)
    arg_r = s.solver.BVV(-2, 32)
    cf, pf, af, zf, sf, of = s_ccall.pc_actions_SUB(s, 32, arg_l, arg_r, 0, platform='AMD64')
    nose.tools.assert_true(s.solver.is_true(cf == 0))
    nose.tools.assert_true(s.solver.is_true(pf == 0))
    nose.tools.assert_true(s.solver.is_true(af == 0))
    nose.tools.assert_true(s.solver.is_true(zf == 0))
    nose.tools.assert_true(s.solver.is_true(sf == 0))
    nose.tools.assert_true(s.solver.is_true(of == 0))

    l.debug("Testing pc_actions_ROL")
    l.debug("(8-bit) ROL 1 1...")
    result = s.solver.BVV(2, 8) # the result of rol(1, 1)
    oldflags = s.solver.BVV(0, 8)
    cf, pf, af, zf, sf, of = s_ccall.pc_actions_ROL(s, 8, result, None, oldflags, platform='AMD64')
    nose.tools.assert_true(s.solver.is_true(cf == 0))
    nose.tools.assert_true(s.solver.is_true(pf == 0))
    nose.tools.assert_true(s.solver.is_true(af == 0))
    nose.tools.assert_true(s.solver.is_true(zf == 0))
    nose.tools.assert_true(s.solver.is_true(sf == 0))
    nose.tools.assert_true(s.solver.is_true(of == 0))

    l.debug("(32-bit) ROL (-1) (-2)... (shift out of range)")
    result = s.solver.BVV(-1, 32) # the result of rol(-1, 0xfe)
    oldflags = s.solver.BVV(0, 32)
    cf, pf, af, zf, sf, of = s_ccall.pc_actions_ROL(s, 32, result, None, oldflags, platform='AMD64')
    nose.tools.assert_true(s.solver.is_true(cf == 1))
    nose.tools.assert_true(s.solver.is_true(pf == 0))
    nose.tools.assert_true(s.solver.is_true(af == 0))
    nose.tools.assert_true(s.solver.is_true(zf == 0))
    nose.tools.assert_true(s.solver.is_true(sf == 0))
    nose.tools.assert_true(s.solver.is_true(of == 0))

    l.debug("Testing pc_actions_ROR")
    l.debug("(32-bit) ROR 2 1...")
    result = s.solver.BVV(1, 32) # the result of ror(2, 1)
    oldflags = s.solver.BVV(0, 8)
    cf, pf, af, zf, sf, of = s_ccall.pc_actions_ROR(s, 32, result, None, oldflags, platform='AMD64')
    nose.tools.assert_true(s.solver.is_true(cf == 0))
    nose.tools.assert_true(s.solver.is_true(pf == 0))
    nose.tools.assert_true(s.solver.is_true(af == 0))
    nose.tools.assert_true(s.solver.is_true(zf == 0))
    nose.tools.assert_true(s.solver.is_true(sf == 0))
    nose.tools.assert_true(s.solver.is_true(of == 0))

    l.debug("Testing pc_actions_ROR")
    l.debug("(32-bit) ROR 1 1...")
    result = s.solver.BVV(0x80000000, 32) # the result of ror(1, 1)
    oldflags = s.solver.BVV(0, 8)
    cf, pf, af, zf, sf, of = s_ccall.pc_actions_ROR(s, 32, result, None, oldflags, platform='AMD64')
    nose.tools.assert_true(s.solver.is_true(cf == 1))
    nose.tools.assert_true(s.solver.is_true(pf == 0))
    nose.tools.assert_true(s.solver.is_true(af == 0))
    nose.tools.assert_true(s.solver.is_true(zf == 0))
    nose.tools.assert_true(s.solver.is_true(sf == 0))
    nose.tools.assert_true(s.solver.is_true(of == 1))

    l.debug("Testing pc_actions_ROR")
    l.debug("(32-bit) ROR -1 1...")
    result = s.solver.BVV(-1, 32) # the result of ror(0xffffffff, 1)
    oldflags = s.solver.BVV(0, 32)
    cf, pf, af, zf, sf, of = s_ccall.pc_actions_ROR(s, 32, result, None, oldflags, platform='AMD64')
    nose.tools.assert_true(s.solver.is_true(cf == 1))
    nose.tools.assert_true(s.solver.is_true(pf == 0))
    nose.tools.assert_true(s.solver.is_true(af == 0))
    nose.tools.assert_true(s.solver.is_true(zf == 0))
    nose.tools.assert_true(s.solver.is_true(sf == 0))
    nose.tools.assert_true(s.solver.is_true(of == 0))

    l.debug("(32-bit) ROR (-1) (-2)... (shift out of range)")
    result = s.solver.BVV(-1, 32) # the result of ror(0xffffffff, 0xfe)
    oldflags = s.solver.BVV(0, 32)
    cf, pf, af, zf, sf, of = s_ccall.pc_actions_ROR(s, 32, result, None, oldflags, platform='AMD64')
    nose.tools.assert_true(s.solver.is_true(cf == 1))
    nose.tools.assert_true(s.solver.is_true(pf == 0))
    nose.tools.assert_true(s.solver.is_true(af == 0))
    nose.tools.assert_true(s.solver.is_true(zf == 0))
    nose.tools.assert_true(s.solver.is_true(sf == 0))
    nose.tools.assert_true(s.solver.is_true(of == 0))

def test_aarch64_32bit_ccalls():

    # GitHub issue #1238
    s = SimState(arch="AArch64")

    x = s.solver.BVS("x", 32)
    # A normal operation
    flag_z, _ = s_ccall.arm64g_calculate_flag_z(s, s_ccall.ARM64G_CC_OP_ADD32, x, s.solver.BVV(1, 32), 0)
    nose.tools.assert_true(s.satisfiable(extra_constraints=(flag_z == 0,)))
    nose.tools.assert_true(s.satisfiable(extra_constraints=(flag_z == 1,)))
    # What VEX does
    flag_z, _ = s_ccall.arm64g_calculate_flag_z(s, s_ccall.ARM64G_CC_OP_ADD32, x.zero_extend(32), s.solver.BVV(1, 64), 0)
    nose.tools.assert_true(s.satisfiable(extra_constraints=(flag_z == 0,)))
    nose.tools.assert_true(s.satisfiable(extra_constraints=(flag_z == 1,)))


def test_some_vector_ops():
    from angr.engines.vex.irop import translate

    s = SimState(arch='AMD64')

    a =              s.solver.BVV(0xffff0000000100020003000400050006, 128)
    b =              s.solver.BVV(0x00020002000200020002000200020002, 128)

    calc_result = translate(s, 'Iop_Sub16x8', (a, b))
    correct_result = s.solver.BVV(0xfffdfffeffff00000001000200030004, 128)
    nose.tools.assert_true(s.solver.is_true(calc_result == correct_result))

    calc_result = translate(s, 'Iop_CmpEQ16x8', (a, b))
    correct_result = s.solver.BVV(0x000000000000ffff0000000000000000, 128)
    nose.tools.assert_true(s.solver.is_true(calc_result == correct_result))

    calc_result = translate(s, 'Iop_CmpEQ8x16', (a, b))
    correct_result = s.solver.BVV(0x0000ff00ff00ffffff00ff00ff00ff00, 128)
    nose.tools.assert_true(s.solver.is_true(calc_result == correct_result))

    calc_result = translate(s, 'Iop_CmpGT16Sx8', (a, b))
    correct_result = s.solver.BVV(0x0000000000000000ffffffffffffffff, 128)
    nose.tools.assert_true(s.solver.is_true(calc_result == correct_result))

    calc_result = translate(s, 'Iop_CmpGT16Ux8', (a, b))
    correct_result = s.solver.BVV(0xffff000000000000ffffffffffffffff, 128)
    nose.tools.assert_true(s.solver.is_true(calc_result == correct_result))

    calc_result = translate(s, 'Iop_InterleaveLO16x8', (a, b))
    correct_result = s.solver.BVV(0x00030002000400020005000200060002, 128)
    nose.tools.assert_true(s.solver.is_true(calc_result == correct_result))

    calc_result = translate(s, 'Iop_InterleaveLO8x16', (a, b))
    correct_result = s.solver.BVV(0x00000302000004020000050200000602, 128)
    nose.tools.assert_true(s.solver.is_true(calc_result == correct_result))

    calc_result = translate(s, 'Iop_Min8Ux16', (a, b))
    correct_result = s.solver.BVV(0x00020000000100020002000200020002, 128)
    nose.tools.assert_true(s.solver.is_true(calc_result == correct_result))

    calc_result = translate(s, 'Iop_Min8Sx16', (a, b))
    correct_result = s.solver.BVV(0xffff0000000100020002000200020002, 128)
    nose.tools.assert_true(s.solver.is_true(calc_result == correct_result))

    calc_result = translate(s, 'Iop_QNarrowBin16Sto8Ux16', (a, b))
    correct_result = s.solver.BVV(0x00000102030405060202020202020202, 128)
    nose.tools.assert_true(s.solver.is_true(calc_result == correct_result))

    c =              s.solver.BVV(0xff008877, 32)
    d =              s.solver.BVV(0x11111111, 32)

    calc_result = translate(s, 'Iop_HAdd8Sx4', (c, d))
    correct_result = s.solver.BVV(0x0808cc44, 32)
    nose.tools.assert_true(s.solver.is_true(calc_result == correct_result))

    calc_result = translate(s, 'Iop_QAdd8Sx4', (c, d))
    correct_result = s.solver.BVV(0x1011997f, 32)
    nose.tools.assert_true(s.solver.is_true(calc_result == correct_result))

    calc_result = translate(s, 'Iop_QAdd8Ux4', (c, d))
    correct_result = s.solver.BVV(0xff119988, 32)
    nose.tools.assert_true(s.solver.is_true(calc_result == correct_result))

    calc_result = translate(s, 'Iop_QSub8Sx4', (c, d))
    correct_result = s.solver.BVV(0xeeef8066, 32)
    nose.tools.assert_true(s.solver.is_true(calc_result == correct_result))

    calc_result = translate(s, 'Iop_QSub8Ux4', (c, d))
    correct_result = s.solver.BVV(0xee007766, 32)
    nose.tools.assert_true(s.solver.is_true(calc_result == correct_result))

    e =              s.solver.BVV(0xff00887766554433, 64)
    f =              s.solver.BVV(0x0202000200020002, 64)

    calc_result = translate(s, 'Iop_QNarrowBin16Sto8Ux8', (e, f))
    correct_result = s.solver.BVV(0x0000ffffff020202, 64)
    nose.tools.assert_true(s.solver.is_true(calc_result == correct_result))

def test_store_simplification():
    state = SimState(arch='X86')
    state.regs.esp = state.solver.BVS('stack_pointer', 32)
    state.regs.ebp = state.solver.BVS('base_pointer', 32)
    state.regs.eax = state.solver.BVS('base_eax', 32)

    irsb = pyvex.IRSB(b'PT]\xc2\x10\x00', 0x4000, state.arch)
    sim_successors = SimEngineVEX().process(state.copy(), irsb)
    exit_state = sim_successors.all_successors[0]

    nose.tools.assert_true(claripy.backends.z3.is_true(exit_state.regs.ebp == state.regs.esp - 4))


def test_loadg_no_constraint_creation():

    state = SimState(arch='armel', mode='symbolic')
    engine = SimEngineVEX()

    from angr.engines.vex.statements.loadg import SimIRStmt_LoadG

    stmt = pyvex.IRStmt.LoadG('Iend_LE', 'ILGop_16Uto32',
                              0, # dst
                              pyvex.IRExpr.Const(pyvex.const.U32(0x2000)), # addr (src)
                              pyvex.IRExpr.Const(pyvex.const.U32(0x1337)), # alt
                              pyvex.IRExpr.RdTmp(1)  # guard
                              )
    tyenv = pyvex.IRTypeEnv(state.arch)
    tyenv.types = [ 'Ity_I32', 'Ity_I32' ]
    state.scratch.set_tyenv(tyenv)
    state.scratch.temps[1] = state.solver.BVS('tmp_1', 32)
    SimIRStmt_LoadG(engine, state, stmt)

    # LOADG should not create new constraints - it is a simple conditional memory read. The conditions should only be
    # used inside the value AST to guard the memory read.
    assert not state.solver.constraints
    assert state.scratch.temps[0] is not None
    assert state.scratch.temps[0].variables.issuperset(state.scratch.temps[1].variables)
    assert state.scratch.temps[0].op == 'If'


if __name__ == '__main__':
    g = globals().copy()
    for func_name, func in g.items():
        if func_name.startswith("test_") and hasattr(func, "__call__"):
            func()
