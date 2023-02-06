import logging

import pyvex
import claripy

from angr import SimState, load_shellcode
from angr.engines import HeavyVEXMixin
import angr.engines.vex.claripy.ccall as s_ccall

l = logging.getLogger("angr.tests.test_vex")


def test_ccall():
    s = SimState(arch="AMD64")

    l.debug("Testing amd64_actions_ADD")
    l.debug("(8-bit) 1 + 1...")
    arg_l = s.solver.BVV(1, 8)
    arg_r = s.solver.BVV(1, 8)
    cf, pf, af, zf, sf, of = s_ccall.pc_actions_ADD(s, 8, arg_l, arg_r, 0, platform="AMD64")
    assert s.solver.is_true(cf == 0)
    assert s.solver.is_true(pf == 0)
    assert s.solver.is_true(af == 0)
    assert s.solver.is_true(zf == 0)
    assert s.solver.is_true(sf == 0)
    assert s.solver.is_true(of == 0)

    l.debug("(32-bit) (-1) + (-2)...")
    arg_l = s.solver.BVV(-1, 32)
    arg_r = s.solver.BVV(-1, 32)
    cf, pf, af, zf, sf, of = s_ccall.pc_actions_ADD(s, 32, arg_l, arg_r, 0, platform="AMD64")
    assert s.solver.is_true(cf == 1)
    assert s.solver.is_true(pf == 0)
    assert s.solver.is_true(af == 1)
    assert s.solver.is_true(zf == 0)
    assert s.solver.is_true(sf == 1)
    assert s.solver.is_true(of == 0)

    l.debug("Testing pc_actions_SUB")
    l.debug(
        "(8-bit) 1 - 1...",
    )
    arg_l = s.solver.BVV(1, 8)
    arg_r = s.solver.BVV(1, 8)
    cf, pf, af, zf, sf, of = s_ccall.pc_actions_SUB(s, 8, arg_l, arg_r, 0, platform="AMD64")
    assert s.solver.is_true(cf == 0)
    assert s.solver.is_true(pf == 1)
    assert s.solver.is_true(af == 0)
    assert s.solver.is_true(zf == 1)
    assert s.solver.is_true(sf == 0)
    assert s.solver.is_true(of == 0)

    l.debug("(32-bit) (-1) - (-2)...")
    arg_l = s.solver.BVV(-1, 32)
    arg_r = s.solver.BVV(-2, 32)
    cf, pf, af, zf, sf, of = s_ccall.pc_actions_SUB(s, 32, arg_l, arg_r, 0, platform="AMD64")
    assert s.solver.is_true(cf == 0)
    assert s.solver.is_true(pf == 0)
    assert s.solver.is_true(af == 0)
    assert s.solver.is_true(zf == 0)
    assert s.solver.is_true(sf == 0)
    assert s.solver.is_true(of == 0)

    l.debug("Testing pc_actions_ROL")
    l.debug("(8-bit) ROL 1 1...")
    result = s.solver.BVV(2, 8)  # the result of rol(1, 1)
    oldflags = s.solver.BVV(0, 8)
    cf, pf, af, zf, sf, of = s_ccall.pc_actions_ROL(s, 8, result, None, oldflags, platform="AMD64")
    assert s.solver.is_true(cf == 0)
    assert s.solver.is_true(pf == 0)
    assert s.solver.is_true(af == 0)
    assert s.solver.is_true(zf == 0)
    assert s.solver.is_true(sf == 0)
    assert s.solver.is_true(of == 0)

    l.debug("(32-bit) ROL (-1) (-2)... (shift out of range)")
    result = s.solver.BVV(-1, 32)  # the result of rol(-1, 0xfe)
    oldflags = s.solver.BVV(0, 32)
    cf, pf, af, zf, sf, of = s_ccall.pc_actions_ROL(s, 32, result, None, oldflags, platform="AMD64")
    assert s.solver.is_true(cf == 1)
    assert s.solver.is_true(pf == 0)
    assert s.solver.is_true(af == 0)
    assert s.solver.is_true(zf == 0)
    assert s.solver.is_true(sf == 0)
    assert s.solver.is_true(of == 0)

    l.debug("Testing pc_actions_ROR")
    l.debug("(32-bit) ROR 2 1...")
    result = s.solver.BVV(1, 32)  # the result of ror(2, 1)
    oldflags = s.solver.BVV(0, 8)
    cf, pf, af, zf, sf, of = s_ccall.pc_actions_ROR(s, 32, result, None, oldflags, platform="AMD64")
    assert s.solver.is_true(cf == 0)
    assert s.solver.is_true(pf == 0)
    assert s.solver.is_true(af == 0)
    assert s.solver.is_true(zf == 0)
    assert s.solver.is_true(sf == 0)
    assert s.solver.is_true(of == 0)

    l.debug("Testing pc_actions_ROR")
    l.debug("(32-bit) ROR 1 1...")
    result = s.solver.BVV(0x80000000, 32)  # the result of ror(1, 1)
    oldflags = s.solver.BVV(0, 8)
    cf, pf, af, zf, sf, of = s_ccall.pc_actions_ROR(s, 32, result, None, oldflags, platform="AMD64")
    assert s.solver.is_true(cf == 1)
    assert s.solver.is_true(pf == 0)
    assert s.solver.is_true(af == 0)
    assert s.solver.is_true(zf == 0)
    assert s.solver.is_true(sf == 0)
    assert s.solver.is_true(of == 1)

    l.debug("Testing pc_actions_ROR")
    l.debug("(32-bit) ROR -1 1...")
    result = s.solver.BVV(-1, 32)  # the result of ror(0xffffffff, 1)
    oldflags = s.solver.BVV(0, 32)
    cf, pf, af, zf, sf, of = s_ccall.pc_actions_ROR(s, 32, result, None, oldflags, platform="AMD64")
    assert s.solver.is_true(cf == 1)
    assert s.solver.is_true(pf == 0)
    assert s.solver.is_true(af == 0)
    assert s.solver.is_true(zf == 0)
    assert s.solver.is_true(sf == 0)
    assert s.solver.is_true(of == 0)

    l.debug("(32-bit) ROR (-1) (-2)... (shift out of range)")
    result = s.solver.BVV(-1, 32)  # the result of ror(0xffffffff, 0xfe)
    oldflags = s.solver.BVV(0, 32)
    cf, pf, af, zf, sf, of = s_ccall.pc_actions_ROR(s, 32, result, None, oldflags, platform="AMD64")
    assert s.solver.is_true(cf == 1)
    assert s.solver.is_true(pf == 0)
    assert s.solver.is_true(af == 0)
    assert s.solver.is_true(zf == 0)
    assert s.solver.is_true(sf == 0)
    assert s.solver.is_true(of == 0)

    l.debug("Testing amd64_actions_ADCX")

    l.debug("(ADCX, 32-bit) 0xffffffff + 1...")
    arg_l = s.solver.BVV(0xFFFFFFFF, 32)
    arg_r = s.solver.BVV(1, 32)
    cf, pf, af, zf, sf, of = s_ccall.pc_actions_ADCX(s, 32, arg_l, arg_r, s.solver.BVV(0, 32), True, platform="AMD64")
    assert s.solver.is_true(cf == 1)
    assert s.solver.is_true(of == 0)

    l.debug("(ADOX, 32-bit) 0xffffffff + 1...")
    arg_l = s.solver.BVV(0xFFFFFFFF, 32)
    arg_r = s.solver.BVV(1, 32)
    cf, pf, af, zf, sf, of = s_ccall.pc_actions_ADCX(s, 32, arg_l, arg_r, s.solver.BVV(0, 32), False, platform="AMD64")
    assert s.solver.is_true(cf == 0)
    assert s.solver.is_true(of == 1)

    l.debug("(ADCX, 64-bit) 0xffffffffffffffff + 1...")
    arg_l = s.solver.BVV(0xFFFFFFFFFFFFFFFF, 64)
    arg_r = s.solver.BVV(1, 64)
    cf, pf, af, zf, sf, of = s_ccall.pc_actions_ADCX(s, 64, arg_l, arg_r, s.solver.BVV(0, 64), True, platform="AMD64")
    assert s.solver.is_true(cf == 1)
    assert s.solver.is_true(of == 0)

    l.debug("(ADOX, 64-bit) 0xffffffffffffffff + 1...")
    arg_l = s.solver.BVV(0xFFFFFFFFFFFFFFFF, 64)
    arg_r = s.solver.BVV(1, 64)
    cf, pf, af, zf, sf, of = s_ccall.pc_actions_ADCX(s, 64, arg_l, arg_r, s.solver.BVV(0, 64), False, platform="AMD64")
    assert s.solver.is_true(cf == 0)
    assert s.solver.is_true(of == 1)


def test_aarch64_32bit_ccalls():
    # GitHub issue #1238
    s = SimState(arch="AArch64")

    x = s.solver.BVS("x", 32)
    # A normal operation
    flag_z = s_ccall.arm64g_calculate_flag_z(s, s_ccall.ARM64G_CC_OP_ADD32, x, s.solver.BVV(1, 32), 0)
    assert s.satisfiable(extra_constraints=(flag_z == 0,))
    assert s.satisfiable(extra_constraints=(flag_z == 1,))
    # What VEX does
    flag_z = s_ccall.arm64g_calculate_flag_z(s, s_ccall.ARM64G_CC_OP_ADD32, x.zero_extend(32), s.solver.BVV(1, 64), 0)
    assert s.satisfiable(extra_constraints=(flag_z == 0,))
    assert s.satisfiable(extra_constraints=(flag_z == 1,))


def test_some_vector_ops():
    engine = HeavyVEXMixin(None)
    s = SimState(arch="AMD64")

    def translate(state, op, args):
        return engine._perform_vex_expr_Op(op, args)

    a = s.solver.BVV(0xFFFF0000000100020003000400050006, 128)
    b = s.solver.BVV(0x00020002000200020002000200020002, 128)

    calc_result = translate(s, "Iop_Sub16x8", (a, b))
    correct_result = s.solver.BVV(0xFFFDFFFEFFFF00000001000200030004, 128)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_CmpEQ16x8", (a, b))
    correct_result = s.solver.BVV(0x000000000000FFFF0000000000000000, 128)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_CmpEQ8x16", (a, b))
    correct_result = s.solver.BVV(0x0000FF00FF00FFFFFF00FF00FF00FF00, 128)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_CmpGT16Sx8", (a, b))
    correct_result = s.solver.BVV(0x0000000000000000FFFFFFFFFFFFFFFF, 128)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_CmpGT16Ux8", (a, b))
    correct_result = s.solver.BVV(0xFFFF000000000000FFFFFFFFFFFFFFFF, 128)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_InterleaveLO16x8", (a, b))
    correct_result = s.solver.BVV(0x00030002000400020005000200060002, 128)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_InterleaveLO8x16", (a, b))
    correct_result = s.solver.BVV(0x00000302000004020000050200000602, 128)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_Min8Ux16", (a, b))
    correct_result = s.solver.BVV(0x00020000000100020002000200020002, 128)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_Min8Sx16", (a, b))
    correct_result = s.solver.BVV(0xFFFF0000000100020002000200020002, 128)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_QNarrowBin16Sto8Ux16", (a, b))
    correct_result = s.solver.BVV(0x00000102030405060202020202020202, 128)
    assert s.solver.is_true(calc_result == correct_result)

    c = s.solver.BVV(0xFF008877, 32)
    d = s.solver.BVV(0x11111111, 32)

    calc_result = translate(s, "Iop_HAdd8Sx4", (c, d))
    correct_result = s.solver.BVV(0x0808CC44, 32)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_QAdd8Sx4", (c, d))
    correct_result = s.solver.BVV(0x1011997F, 32)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_QAdd8Ux4", (c, d))
    correct_result = s.solver.BVV(0xFF119988, 32)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_QSub8Sx4", (c, d))
    correct_result = s.solver.BVV(0xEEEF8066, 32)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_QSub8Ux4", (c, d))
    correct_result = s.solver.BVV(0xEE007766, 32)
    assert s.solver.is_true(calc_result == correct_result)

    e = s.solver.BVV(0xFF00887766554433, 64)
    f = s.solver.BVV(0x0202000200020002, 64)

    calc_result = translate(s, "Iop_QNarrowBin16Sto8Ux8", (e, f))
    correct_result = s.solver.BVV(0x0000FFFFFF020202, 64)
    assert s.solver.is_true(calc_result == correct_result)

    gg = claripy.BVV(0x111111112222222233333333FFFFFFFF, 128)
    h = claripy.BVV(0x1111111100000000FFFFFFFFFFFFFFFF, 128)

    calc_result = translate(s, "Iop_CmpEQ32Fx4", (gg, h))
    correct_result = claripy.BVV(0xFFFFFFFF000000000000000000000000, 128)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_Clz32x4", (gg,))
    correct_result = claripy.BVV(0x00000003000000020000000200000000, 128)
    assert s.solver.is_true(calc_result == correct_result)

    i = claripy.BVV(0x1001000000001000, 64)
    j = claripy.BVV(0x100000000000F000, 64)

    calc_result = translate(s, "Iop_Mull16Sx4", (i, j))
    correct_result = claripy.BVV(0x10010000000000000000000FF000000, 128)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_Mull16Ux4", (i, j))
    correct_result = claripy.BVV(0x100100000000000000000000F000000, 128)
    assert s.solver.is_true(calc_result == correct_result)

    k = claripy.BVV(0xE7, 8)
    ll = claripy.BVV(0x1234, 16)
    m = claripy.BVV(0x12345678, 32)

    calc_result = translate(s, "Iop_Dup8x8", (k,))
    correct_result = claripy.BVV(0xE7E7E7E7E7E7E7E7, 64)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_Dup8x16", (k,))
    correct_result = claripy.BVV(0xE7E7E7E7E7E7E7E7E7E7E7E7E7E7E7E7, 128)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_Dup16x4", (ll,))
    correct_result = claripy.BVV(0x1234123412341234, 64)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_Dup16x8", (ll,))
    correct_result = claripy.BVV(0x12341234123412341234123412341234, 128)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_Dup32x2", (m,))
    correct_result = claripy.BVV(0x1234567812345678, 64)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_Dup32x4", (m,))
    correct_result = claripy.BVV(0x12345678123456781234567812345678, 128)
    assert s.solver.is_true(calc_result == correct_result)

    n = claripy.BVV(0x0123456789ABCDEF, 64)
    o = claripy.BVV(0xAF, 8)
    p = claripy.BVV(0xDFEC, 16)
    q = claripy.BVV(0xBFCFDFEF, 32)
    r = claripy.BVV(0x0102030405060708, 64)
    ss = claripy.BVS("index", 8)

    # According to the source code of LibVex, the index is a U8 constant
    calc_result = translate(s, "Iop_GetElem8x8", (n, claripy.BVV(0, 8)))
    correct_result = claripy.BVV(0xEF, 8)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_GetElem8x8", (n, claripy.BVV(1, 8)))
    correct_result = claripy.BVV(0xCD, 8)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_GetElem8x8", (n, claripy.BVV(6, 8)))
    correct_result = claripy.BVV(0x23, 8)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_GetElem8x8", (n, claripy.BVV(7, 8)))
    correct_result = claripy.BVV(0x01, 8)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_GetElem16x4", (n, claripy.BVV(0, 8)))
    correct_result = claripy.BVV(0xCDEF, 16)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_GetElem16x4", (n, claripy.BVV(3, 8)))
    correct_result = claripy.BVV(0x0123, 16)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_GetElem32x2", (n, claripy.BVV(0, 8)))
    correct_result = claripy.BVV(0x89ABCDEF, 32)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_GetElem32x2", (n, claripy.BVV(1, 8)))
    correct_result = claripy.BVV(0x01234567, 32)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_SetElem8x8", (n, claripy.BVV(0, 8), o))
    correct_result = claripy.BVV(0x0123456789ABCDAF, 64)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_SetElem8x8", (n, claripy.BVV(1, 8), o))
    correct_result = claripy.BVV(0x0123456789ABAFEF, 64)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_SetElem8x8", (n, claripy.BVV(6, 8), o))
    correct_result = claripy.BVV(0x01AF456789ABCDEF, 64)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_SetElem8x8", (n, claripy.BVV(7, 8), o))
    correct_result = claripy.BVV(0xAF23456789ABCDEF, 64)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_SetElem16x4", (n, claripy.BVV(0, 8), p))
    correct_result = claripy.BVV(0x0123456789ABDFEC, 64)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_SetElem16x4", (n, claripy.BVV(3, 8), p))
    correct_result = claripy.BVV(0xDFEC456789ABCDEF, 64)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_SetElem32x2", (n, claripy.BVV(0, 8), q))
    correct_result = claripy.BVV(0x01234567BFCFDFEF, 64)
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_SetElem32x2", (n, claripy.BVV(1, 8), q))
    correct_result = claripy.BVV(0xBFCFDFEF89ABCDEF, 64)
    assert s.solver.is_true(calc_result == correct_result)

    # Symbolic indexes
    calc_result = translate(ss, "Iop_GetElem8x8", (r, ss))
    correct_result = claripy.If(
        ss == 7,
        claripy.BVV(0x01, 8),
        claripy.If(
            ss == 6,
            claripy.BVV(0x02, 8),
            claripy.If(
                ss == 5,
                claripy.BVV(0x03, 8),
                claripy.If(
                    ss == 4,
                    claripy.BVV(0x04, 8),
                    claripy.If(
                        ss == 3,
                        claripy.BVV(0x05, 8),
                        claripy.If(
                            ss == 2,
                            claripy.BVV(0x06, 8),
                            claripy.If(ss == 1, claripy.BVV(0x07, 8), claripy.BVV(0x08, 8)),
                        ),
                    ),
                ),
            ),
        ),
    )
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_GetElem16x4", (r, ss))
    correct_result = claripy.If(
        ss == 3,
        claripy.BVV(0x0102, 16),
        claripy.If(
            ss == 2,
            claripy.BVV(0x0304, 16),
            claripy.If(ss == 1, claripy.BVV(0x0506, 16), claripy.BVV(0x0708, 16)),
        ),
    )
    assert s.solver.is_true(calc_result == correct_result)

    calc_result = translate(s, "Iop_GetElem32x2", (r, ss))
    correct_result = claripy.If(ss == 1, claripy.BVV(0x01020304, 32), claripy.BVV(0x05060708, 32))
    assert s.solver.is_true(calc_result == correct_result)

    r_slices = r.chop(8)
    calc_result = translate(s, "Iop_SetElem8x8", (r, ss, o))
    correct_result = claripy.Concat(
        claripy.If(ss == 7, o, r_slices[0]),
        claripy.If(ss == 6, o, r_slices[1]),
        claripy.If(ss == 5, o, r_slices[2]),
        claripy.If(ss == 4, o, r_slices[3]),
        claripy.If(ss == 3, o, r_slices[4]),
        claripy.If(ss == 2, o, r_slices[5]),
        claripy.If(ss == 1, o, r_slices[6]),
        claripy.If(ss == 0, o, r_slices[7]),
    )
    assert s.solver.is_true(calc_result == correct_result)

    r_slices = r.chop(16)
    calc_result = translate(s, "Iop_SetElem16x4", (r, ss, p))
    correct_result = claripy.Concat(
        claripy.If(ss == 3, p, r_slices[0]),
        claripy.If(ss == 2, p, r_slices[1]),
        claripy.If(ss == 1, p, r_slices[2]),
        claripy.If(ss == 0, p, r_slices[3]),
    )
    assert s.solver.is_true(calc_result == correct_result)

    r_slices = r.chop(32)
    calc_result = translate(s, "Iop_SetElem32x2", (r, ss, q))
    correct_result = claripy.Concat(
        claripy.If(ss == 1, q, r_slices[0]),
        claripy.If(ss == 0, q, r_slices[1]),
    )
    assert s.solver.is_true(calc_result == correct_result)


def test_store_simplification():
    state = SimState(arch="X86")
    state.regs.esp = state.solver.BVS("stack_pointer", 32)
    state.regs.ebp = state.solver.BVS("base_pointer", 32)
    state.regs.eax = state.solver.BVS("base_eax", 32)

    irsb = pyvex.IRSB(b"PT]\xc2\x10\x00", 0x4000, state.arch)
    sim_successors = HeavyVEXMixin(None).process(state.copy(), irsb=irsb)
    exit_state = sim_successors.all_successors[0]

    assert claripy.backends.z3.is_true(exit_state.regs.ebp == state.regs.esp - 4)


def test_loadg_no_constraint_creation():
    state = SimState(arch="armel", mode="symbolic")
    engine = HeavyVEXMixin(None)

    stmt = pyvex.IRStmt.LoadG(
        "Iend_LE",
        "ILGop_16Uto32",
        0,  # dst
        pyvex.IRExpr.Const(pyvex.const.U32(0x2000)),  # addr (src)
        pyvex.IRExpr.Const(pyvex.const.U32(0x1337)),  # alt
        pyvex.IRExpr.RdTmp(1),  # guard
    )
    tyenv = pyvex.IRTypeEnv(state.arch)
    tyenv.types = ["Ity_I32", "Ity_I32"]
    state.scratch.set_tyenv(tyenv)
    state.scratch.temps[1] = state.solver.BVS("tmp_1", 32)
    engine.state = state
    engine._handle_vex_stmt(stmt)

    # LOADG should not create new constraints - it is a simple conditional memory read. The conditions should only be
    # used inside the value AST to guard the memory read.
    assert not state.solver.constraints
    assert state.scratch.temps[0] is not None
    assert state.scratch.temps[0].variables.issuperset(state.scratch.temps[1].variables)
    assert state.scratch.temps[0].op == "If"


def test_amd64_ud012_behaviors():
    # Test if VEX's lifter behaves as what CFGFast expects
    #
    # Note: if such behaviors change in the future, you also need to fix the ud{0,1,2} handling logic in
    # CFGFast._generate_cfgnode().

    # according to VEX, ud0 is not part of the block
    a = load_shellcode(b"\x90\x90\x0f\xff", "amd64")
    block_0 = a.factory.block(0)
    assert block_0.size == 2

    # according to VEX, ud1 is not part of the block
    a = load_shellcode(b"\x90\x90\x0f\xb9", "amd64")
    block_1 = a.factory.block(0)
    assert block_1.size == 2

    # according to VEX, ud2 under AMD64 *is* part of the block
    a = load_shellcode(b"\x90\x90\x0f\x0b", "amd64")
    block_2 = a.factory.block(0)
    assert block_2.size == 4


def test_x86_ud2_behaviors():
    # Test if VEX's lifter behaves as what CFGFast expects
    #
    # Note: if such behaviors change in the future, you also need to fix the ud2 handling logic in
    # CFGFast._generate_cfgnode().

    # according to VEX, ud2 on x86 is not part of the block
    a = load_shellcode(b"\x90\x90\x0f\x0b", "x86")
    block_0 = a.factory.block(0)
    assert block_0.size == 2


def test_blsr():
    p = load_shellcode(bytes.fromhex("c4e2f8f3cf0f95c00fb6c0c3"), arch="amd64")
    # compiled form of !!(x & (x - 1))
    # 2c0:   c4 e2 f8 f3 cf          blsr   %rdi,%rax

    # 2c5:   0f 95 c0                setne  %al
    # 2c8:   0f b6 c0                movzbl %al,%eax
    # 2cb:   c3                      retq
    x = claripy.BVS("x", 64)
    s = p.factory.call_state(0, x)
    sm = p.factory.simulation_manager(s)
    sm.run()

    target_func = claripy.If((x & (x - 1)) == 0, claripy.BVV(0, 64), 1)
    solver = claripy.Solver()
    solver.add(sm.one_deadended.regs.rax != target_func)
    assert not solver.satisfiable()


if __name__ == "__main__":
    g = globals().copy()
    for func_name, func in g.items():
        if func_name.startswith("test_") and hasattr(func, "__call__"):
            func()
