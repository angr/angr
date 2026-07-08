"""Round-trip tests for the postcard-based AIL serialization, exercised
through pickle -- the production path (``__reduce__`` -> ``to_bytes`` /
``from_bytes``)."""

from __future__ import annotations

import pickle
import unittest

from angr.ailment.block import Block
from angr.ailment.expression import (
    ITE,
    Array,
    BasePointerOffset,
    BinaryOp,
    Call,
    ComboRegister,
    Const,
    Convert,
    DirtyExpression,
    Expression,
    Extract,
    FunctionLikeMacro,
    Insert,
    Load,
    Macro,
    MultiStatementExpression,
    Phi,
    Register,
    Reinterpret,
    RustEnum,
    StackBaseOffset,
    StringLiteral,
    Struct,
    Tmp,
    UnaryOp,
    VEXCCallExpression,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import (
    CAS,
    Assignment,
    ConditionalJump,
    DirtyStatement,
    Jump,
    Label,
    Return,
    SideEffectStatement,
    Statement,
    Store,
    WeakAssignment,
)
from angr.rustylib.ailment import RoundingMode  # pylint:disable=import-error,no-name-in-module


def roundtrip(obj):
    return pickle.loads(pickle.dumps(obj))


class TestSerialize(unittest.TestCase):
    # --- atoms ---------------------------------------------------------------

    def test_const_int(self):
        c = Const(1, 42, 32)
        c2 = roundtrip(c)
        assert isinstance(c2, Const)
        assert c2.idx == c.idx and c2.value == c.value and c2.bits == c.bits
        assert c.likes(c2)

    def test_const_float(self):
        cf = Const(12, 3.14, 64)
        cf2 = roundtrip(cf)
        assert cf2.value == 3.14

    def test_const_bigint_outside_i128(self):
        huge = Const(13, 2**200 + 1, 256)
        huge2 = roundtrip(huge)
        assert huge2.value == 2**200 + 1

    def test_const_negative_int(self):
        neg = Const(14, -42, 32)
        neg2 = roundtrip(neg)
        assert neg2.value == -42

    def test_tmp(self):
        t = Tmp(2, 5, 64)
        t2 = roundtrip(t)
        assert isinstance(t2, Tmp)
        assert t2.tmp_idx == 5 and t2.bits == 64
        assert t.likes(t2)

    def test_register(self):
        r = Register(3, 16, 32)
        r2 = roundtrip(r)
        assert isinstance(r2, Register)
        assert r2.reg_offset == 16
        assert r.likes(r2)

    def test_combo_register_recurses(self):
        cr = ComboRegister(4, [Register(0, 0, 32), Register(0, 4, 32)])
        cr2 = roundtrip(cr)
        assert isinstance(cr2, ComboRegister)
        assert len(cr2.registers) == 2
        assert cr2.registers[0].reg_offset == 0
        assert cr2.registers[1].reg_offset == 4
        assert cr.likes(cr2)

    def test_virtual_variable_int_oident(self):
        vv = VirtualVariable(5, 100, 64, VirtualVariableCategory.REGISTER, oident=16)
        vv2 = roundtrip(vv)
        assert isinstance(vv2, VirtualVariable)
        assert vv2.varid == 100
        assert vv2.category == VirtualVariableCategory.REGISTER
        assert vv2.oident == 16

    def test_virtual_variable_tuple_oident(self):
        # PARAMETER vvars carry a nested (inner_category, inner_payload) oident.
        vv = VirtualVariable(6, 200, 64, VirtualVariableCategory.PARAMETER, oident=(VirtualVariableCategory.STACK, -32))
        vv2 = roundtrip(vv)
        assert vv2.oident == (VirtualVariableCategory.STACK, -32)

    def test_phi(self):
        vv = VirtualVariable(5, 100, 64, VirtualVariableCategory.REGISTER, oident=16)
        ph = Phi(7, 64, [((0x400, None), vv), ((0x500, 0), None)])
        ph2 = roundtrip(ph)
        assert isinstance(ph2, Phi)
        assert len(ph2.src_and_vvars) == 2
        (src1, v1) = ph2.src_and_vvars[0]
        assert src1 == (0x400, None)
        assert v1.varid == 100
        (src2, v2) = ph2.src_and_vvars[1]
        assert src2 == (0x500, 0)
        assert v2 is None

    # --- ops ----------------------------------------------------------------

    def test_unary_op(self):
        u = UnaryOp(1, "Not", Const(0, 5, 32))
        u2 = roundtrip(u)
        assert isinstance(u2, UnaryOp)
        assert u2.op == "Not"
        assert u2.operand.value == 5
        assert u.likes(u2)

    def test_binary_op(self):
        b = BinaryOp(2, "Add", [Const(0, 5, 32), Const(0, 3, 32)], False)
        b2 = roundtrip(b)
        assert isinstance(b2, BinaryOp)
        assert b2.op == "Add"
        assert b2.operands[0].value == 5 and b2.operands[1].value == 3
        assert b.likes(b2)

    def test_binary_op_floating_point_rounding_mode(self):
        b = BinaryOp(
            3,
            "FAdd",
            [Const(0, 1.0, 64), Const(0, 2.0, 64)],
            False,
            floating_point=True,
            rounding_mode=RoundingMode.RM_NearestTiesEven,
        )
        b2 = roundtrip(b)
        assert b2.floating_point
        assert b2.rounding_mode == RoundingMode.RM_NearestTiesEven

    def test_binary_op_non_default_rounding_mode(self):
        b = BinaryOp(
            4,
            "FAdd",
            [Const(0, 1.0, 64), Const(0, 2.0, 64)],
            False,
            floating_point=True,
            rounding_mode=RoundingMode.RM_TowardsZero,
        )
        b2 = roundtrip(b)
        assert b2.rounding_mode == RoundingMode.RM_TowardsZero

    def test_convert(self):
        c = Convert(5, 32, 64, True, Const(0, 0xFF, 32))
        c2 = roundtrip(c)
        assert isinstance(c2, Convert)
        assert c2.from_bits == 32 and c2.to_bits == 64 and c2.is_signed
        assert c2.operand.value == 0xFF

    def test_reinterpret(self):
        ri = Reinterpret(6, 32, "I", 32, "F", Const(0, 0x40490FDB, 32))
        ri2 = roundtrip(ri)
        assert isinstance(ri2, Reinterpret)
        assert ri2.from_type == "I" and ri2.to_type == "F"

    def test_nested_binary_unary(self):
        nested = BinaryOp(
            10,
            "Add",
            [UnaryOp(0, "Not", Const(0, 5, 32)), Const(0, 1, 32)],
            False,
        )
        nested2 = roundtrip(nested)
        assert isinstance(nested2.operands[0], UnaryOp)
        assert nested2.operands[0].operand.value == 5
        assert nested.likes(nested2)

    # --- exprs --------------------------------------------------------------

    def test_load(self):
        ld = Load(1, Register(0, 16, 64), 4, "Iend_LE")
        ld2 = roundtrip(ld)
        assert isinstance(ld2, Load)
        assert ld2.size == 4 and ld2.endness == "Iend_LE"
        assert isinstance(ld2.addr, Register) and ld2.addr.reg_offset == 16

    def test_load_with_guard_and_alt(self):
        ld = Load(
            2,
            Register(0, 16, 64),
            4,
            "Iend_LE",
            guard=Const(0, 1, 1),
            alt=Const(0, 0, 32),
        )
        ld2 = roundtrip(ld)
        assert isinstance(ld2.guard, Const) and ld2.guard.value == 1
        assert isinstance(ld2.alt, Const) and ld2.alt.value == 0

    def test_ite(self):
        ite = ITE(3, Const(0, 1, 1), Const(0, 5, 32), Const(0, 7, 32))
        ite2 = roundtrip(ite)
        assert isinstance(ite2, ITE)
        assert ite2.iftrue.value == 7 and ite2.iffalse.value == 5

    def test_dirty_expression(self):
        de = DirtyExpression(4, "rdtsc", [Const(0, 0, 32)], bits=64, mfx="read")
        de2 = roundtrip(de)
        assert isinstance(de2, DirtyExpression)
        assert de2.callee == "rdtsc" and de2.mfx == "read"

    def test_vex_ccall(self):
        vc = VEXCCallExpression(
            5,
            "amd64g_calculate_condition",
            (Const(0, 0, 32), Const(0, 1, 32)),
            1,
        )
        vc2 = roundtrip(vc)
        assert isinstance(vc2, VEXCCallExpression)
        assert vc2.callee == "amd64g_calculate_condition"
        assert len(vc2.operands) == 2

    def test_extract(self):
        ex = Extract(6, 8, Register(0, 0, 32), Const(0, 0, 32), "Iend_LE")
        ex2 = roundtrip(ex)
        assert isinstance(ex2, Extract)
        assert ex2.endness == "Iend_LE" and ex2.bits == 8

    def test_insert(self):
        ins = Insert(
            7,
            Register(0, 0, 32),
            Const(0, 0, 32),
            Const(0, 0xFF, 8),
            "Iend_LE",
        )
        ins2 = roundtrip(ins)
        assert isinstance(ins2, Insert)
        assert ins2.endness == "Iend_LE"

    def test_call_with_const_target(self):
        call = Call(8, Const(0, 0x400, 64), args=[Const(0, 1, 32)], bits=32)
        call2 = roundtrip(call)
        assert isinstance(call2, Call)
        assert isinstance(call2.target, Const) and call2.target.value == 0x400
        assert len(call2.args) == 1

    def test_string_literal_text(self):
        sl = StringLiteral(9, "hello", 40)
        sl2 = roundtrip(sl)
        assert sl2.data == "hello"

    def test_struct(self):
        st = Struct(
            10,
            "mystruct",
            {0: Const(0, 1, 32), 4: Const(0, 2, 32)},
            {"a": 0, "b": 4},
            64,
        )
        st2 = roundtrip(st)
        assert isinstance(st2, Struct)
        assert st2.name == "mystruct"
        assert dict(st2.field_offsets) == {"a": 0, "b": 4}

    def test_rust_enum_list(self):
        re_ = RustEnum(11, "Option", [Const(0, 1, 32)], 32)
        re2 = roundtrip(re_)
        assert isinstance(re2.fields, list)

    def test_rust_enum_tuple(self):
        # Tuple inputs are accepted but normalized to a list (the Rust enum
        # stores fields as a typed Vec).
        re_ = RustEnum(12, "Result", (Const(0, 1, 32), Const(0, 0, 32)), 32)
        re2 = roundtrip(re_)
        assert isinstance(re2.fields, list)
        assert len(re2.fields) == 2

    def test_array(self):
        arr = Array(13, [Const(0, 1, 32), Const(0, 2, 32)], 64)
        arr2 = roundtrip(arr)
        assert isinstance(arr2.elements, list)
        assert len(arr2.elements) == 2

    def test_base_pointer_offset(self):
        bpo = BasePointerOffset(14, 64, "stack_base", -32)
        bpo2 = roundtrip(bpo)
        assert isinstance(bpo2, BasePointerOffset)
        assert bpo2.base == "stack_base" and bpo2.offset == -32

    def test_stack_base_offset(self):
        sbo = StackBaseOffset(15, 64, -16)
        sbo2 = roundtrip(sbo)
        assert isinstance(sbo2, StackBaseOffset)
        assert sbo2.base == "stack_base" and sbo2.offset == -16

    def test_macro(self):
        m = Macro(16, "mymacro", delimiter="[]")
        m2 = roundtrip(m)
        assert isinstance(m2, Macro)
        assert m2.name == "mymacro" and m2.delimiter == "[]"

    def test_function_like_macro(self):
        flm = FunctionLikeMacro(17, "format!", args=[Const(0, 1, 32)], bits=32)
        flm2 = roundtrip(flm)
        assert isinstance(flm2, FunctionLikeMacro)
        assert flm2.name == "format!"
        assert len(flm2.args) == 1 and flm2.args[0].value == 1

    # --- statements ----------------------------------------------------------

    def test_assignment(self):
        a_ = Assignment(1, Tmp(0, 0, 32), Const(0, 42, 32))
        a2 = roundtrip(a_)
        assert isinstance(a2, Assignment)
        assert isinstance(a2.dst, Tmp) and isinstance(a2.src, Const)
        assert a_.likes(a2)

    def test_weak_assignment(self):
        wa = WeakAssignment(2, Tmp(0, 1, 32), Const(0, 7, 32))
        wa2 = roundtrip(wa)
        assert isinstance(wa2, WeakAssignment)

    def test_store(self):
        st = Store(
            3,
            Register(0, 16, 64),
            Const(0, 0xFF, 32),
            4,
            "Iend_LE",
            guard=Const(0, 1, 1),
            offset=0x20,
        )
        st2 = roundtrip(st)
        assert isinstance(st2, Store)
        assert st2.size == 4 and st2.endness == "Iend_LE"
        assert isinstance(st2.guard, Const) and st2.guard.value == 1
        assert st2.tags["offset"] == 0x20

    def test_jump(self):
        j = Jump(4, Const(0, 0x500, 64), target_idx=2)
        j2 = roundtrip(j)
        assert isinstance(j2, Jump)
        assert j2.target_idx == 2 and j2.target.value == 0x500

    def test_conditional_jump(self):
        cj = ConditionalJump(
            5,
            Const(0, 1, 1),
            true_target=Const(0, 0x400, 64),
            false_target=Const(0, 0x500, 64),
            true_target_idx=1,
            false_target_idx=None,
        )
        cj2 = roundtrip(cj)
        assert isinstance(cj2, ConditionalJump)
        assert cj2.true_target.value == 0x400
        assert cj2.true_target_idx == 1
        assert cj2.false_target_idx is None

    def test_side_effect_statement(self):
        ses = SideEffectStatement(
            6,
            DirtyExpression(0, "rdtsc", [], bits=64),
            ret_expr=Tmp(0, 3, 64),
        )
        ses2 = roundtrip(ses)
        assert isinstance(ses2, SideEffectStatement)
        assert isinstance(ses2.expr, DirtyExpression)
        assert isinstance(ses2.ret_expr, Tmp)

    def test_return(self):
        r = Return(7, [Const(0, 0, 32), Tmp(0, 4, 32)])
        r2 = roundtrip(r)
        assert isinstance(r2, Return)
        assert len(r2.ret_exprs) == 2

    def test_cas(self):
        cas = CAS(
            8,
            Register(0, 16, 64),
            Tmp(0, 1, 32),
            None,
            Tmp(0, 2, 32),
            None,
            Tmp(0, 3, 32),
            None,
            "Iend_LE",
        )
        cas2 = roundtrip(cas)
        assert isinstance(cas2, CAS)
        assert cas2.endness == "Iend_LE" and cas2.data_hi is None

    def test_dirty_statement(self):
        ds = DirtyStatement(9, DirtyExpression(0, "flush", [], bits=0))
        ds2 = roundtrip(ds)
        assert isinstance(ds2, DirtyStatement)

    def test_label(self):
        lbl = Label(10, "L1")
        lbl2 = roundtrip(lbl)
        assert isinstance(lbl2, Label) and lbl2.name == "L1"

    # --- MultiStatementExpression -------------------------------------------

    def test_multi_statement_expression(self):
        mse = MultiStatementExpression(
            0,
            [Assignment(0, Tmp(0, 1, 32), Const(0, 5, 32))],
            Tmp(0, 1, 32),
        )
        mse2 = roundtrip(mse)
        assert isinstance(mse2, MultiStatementExpression)
        assert isinstance(mse2.stmts[0], Assignment)
        assert isinstance(mse2.expr, Tmp)

    # --- Block --------------------------------------------------------------

    def test_block_with_mixed_statements(self):
        block = Block(
            0x400,
            statements=[
                Label(0, "L1"),
                Assignment(1, Tmp(0, 1, 32), Const(0, 42, 32)),
                Jump(2, Const(0, 0x410, 64)),
            ],
            original_size=12,
        )
        b2 = roundtrip(block)
        assert isinstance(b2, Block)
        assert b2.addr == 0x400 and b2.original_size == 12
        assert len(b2.statements) == 3
        assert isinstance(b2.statements[0], Label)
        assert isinstance(b2.statements[1], Assignment)
        assert isinstance(b2.statements[2], Jump)

    def test_block_with_idx(self):
        block = Block(0x500, statements=[Return(0, [])], idx=3)
        b2 = roundtrip(block)
        assert b2.idx == 3

    def test_empty_block(self):
        block = Block(0x600)
        b2 = roundtrip(block)
        assert b2.addr == 0x600 and len(b2.statements) == 0

    # --- per-class to_bytes / from_bytes ------------------------------------

    def test_expression_to_from_bytes(self):
        data = Tmp(1, 5, 64).to_bytes()
        t = Expression.from_bytes(data)
        assert isinstance(t, Tmp) and t.tmp_idx == 5

    def test_statement_to_from_bytes(self):
        s = Assignment(1, Tmp(0, 1, 32), Const(0, 42, 32)).to_bytes()
        a2 = Statement.from_bytes(s)
        assert isinstance(a2, Assignment)


if __name__ == "__main__":
    unittest.main()
