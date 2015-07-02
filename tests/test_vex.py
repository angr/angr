import nose
from simuvex import SimState
import simuvex.vex.ccall as s_ccall
import logging
l = logging.getLogger('simuvex.test.vex')

#@nose.tools.timed(10)
def broken_ccall():
    s = SimState(arch="AMD64")

    l.debug("Testing amd64_actions_ADD")
    l.debug("(8-bit) 1 + 1...")
    arg_l = s.se.BitVecVal(1, 8)
    arg_r = s.se.BitVecVal(1, 8)
    ret = s_ccall.pc_actions_ADD(s, 8, arg_l, arg_r, 0, platform='AMD64')
    nose.tools.assert_equal(ret, 0)

    l.debug("(32-bit) (-1) + (-2)...")
    arg_l = s.se.BitVecVal(-1, 32)
    arg_r = s.se.BitVecVal(-1, 32)
    ret = s_ccall.pc_actions_ADD(s, 32, arg_l, arg_r, 0, platform='AMD64')
    nose.tools.assert_equal(ret, 0b101010)

    l.debug("Testing pc_actions_SUB")
    l.debug("(8-bit) 1 - 1...",)
    arg_l = s.se.BitVecVal(1, 8)
    arg_r = s.se.BitVecVal(1, 8)
    ret = s_ccall.pc_actions_SUB(s, 8, arg_l, arg_r, 0, platform='AMD64')
    nose.tools.assert_equal(ret, 0b010100)

    l.debug("(32-bit) (-1) - (-2)...")
    arg_l = s.se.BitVecVal(-1, 32)
    arg_r = s.se.BitVecVal(-1, 32)
    ret = s_ccall.pc_actions_SUB(s, 32, arg_l, arg_r, 0, platform='AMD64')
    nose.tools.assert_equal(ret, 0)

def test_some_vector_ops():
    from simuvex.vex.irop import translate

    s = SimState()

    a =              s.BVV(0xffff0000000100020003000400050006, 128)
    b =              s.BVV(0x00020002000200020002000200020002, 128)

    calc_result = translate(s, 'Iop_Sub16x8', (a, b))
    correct_result = s.BVV(0xfffdfffeffff00000001000200030004, 128)
    nose.tools.assert_true(s.se.is_true(calc_result == correct_result))

    calc_result = translate(s, 'Iop_CmpEQ16x8', (a, b))
    correct_result = s.BVV(0x000000000000ffff0000000000000000, 128)
    nose.tools.assert_true(s.se.is_true(calc_result == correct_result))

    calc_result = translate(s, 'Iop_CmpGT16Sx8', (a, b))
    correct_result = s.BVV(0x0000000000000000ffffffffffffffff, 128)
    nose.tools.assert_true(s.se.is_true(calc_result == correct_result))

    calc_result = translate(s, 'Iop_CmpGT16Ux8', (a, b))
    correct_result = s.BVV(0xffff000000000000ffffffffffffffff, 128)
    nose.tools.assert_true(s.se.is_true(calc_result == correct_result))

if __name__ == '__main__':
    test_some_vector_ops()
