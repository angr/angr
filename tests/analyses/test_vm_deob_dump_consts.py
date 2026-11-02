from __future__ import annotations

import json
import math
import struct
from unittest import TestCase, main

import pyvex
from pyvex import const as C

from angr.analyses.vm_deobfuscation.deobf_reader import _Reader
from angr.analyses.vm_deobfuscation.deobf_schema import DeobfFormatError, UnsupportedIRError
from angr.analyses.vm_deobfuscation.deobf_writer import _Writer


def _reader():
    r = object.__new__(_Reader)
    r._addr_map = None
    return r


def _nan_with_payload():
    return struct.unpack(">d", bytes.fromhex("7ff8000000001234"))[0]


class TestDeobfDumpConsts(TestCase):
    def _roundtrip(self, con):
        enc = json.loads(json.dumps(_Writer(None)._expr(pyvex.expr.Const(con))))
        return _reader()._expr(enc).con

    def assert_same(self, a, b):
        assert type(a) is type(b), (type(a), type(b))
        assert a.tag == b.tag and a.type == b.type
        if isinstance(a.value, float):
            assert struct.pack(">d", a.value) == struct.pack(">d", b.value)
        else:
            assert type(a.value) is type(b.value) and a.value == b.value

    def test_roundtrip_every_const_class(self):
        cases = [
            C.U1(1),
            C.U8(0xAB),
            C.U16(0xBEEF),
            C.U32(0xDEADBEEF),
            C.U64(0xFFFF_FFFF_FFFF_FFFF),
            C.vex_int_class(128)((1 << 128) - 3),
            # Encoded BlockIDs are far wider than the nominal type.
            C.U64((1 << 150) + 7),
            C.F32(1.5),
            C.F32i(-0.0),
            C.F64(math.pi),
            C.F64i(float("inf")),
            C.F64(_nan_with_payload()),
            # pushan also builds float consts with int values via ty_to_const_class
            C.F32i(0x3FC00000),
            C.F64i(0),
            # full 128-bit value (a CPUID result), not VEX's 16-bit byte mask
            C.V128(0x49656E696C65746E756E654700000010),
            C.V128(0),
            C.V256((1 << 256) - 1),
            C.V512(0x1234 << 400),
        ]
        for con in cases:
            with self.subTest(con=repr(con)):
                self.assert_same(con, self._roundtrip(con))

    def test_lifted_v128_mask_semantics(self):
        # VEX stores a byte mask; pyvex expands it on lift.  The expanded value must survive.
        con = C.V128._from_c(type("c", (), {"Ico": type("u", (), {"V128": 0b101})()})())
        assert con.value == 0xFF00FF
        self.assert_same(con, self._roundtrip(con))

    def test_int_encoding_unchanged(self):
        assert _Writer(None)._const(C.U32(5)) == {"ty": "Ity_I32", "value": "5"}

    def test_old_tagless_dump(self):
        r = _reader()
        con = r._const({"ty": "Ity_V128", "value": str(0x178BFBFF000000000001080000000003)})
        self.assert_same(C.V128(0x178BFBFF000000000001080000000003), con)
        # Old writers could not tell F64 from F64i; resolve it the way pyvex does.
        self.assert_same(C.F64i(4), r._const({"ty": "Ity_F64", "value": "4"}))
        with self.assertRaises(DeobfFormatError):
            r._const({"ty": "Ity_Bogus", "value": "0"})

    def test_bad_tags(self):
        r = _reader()
        with self.assertRaises(DeobfFormatError):
            r._const({"ty": "Ity_F32", "tag": "Ico_F64", "value": "0"})
        with self.assertRaises(DeobfFormatError):
            r._const({"ty": "Ity_F32", "tag": "Ico_Bogus", "value": "0"})

        class Weird(C.IRConst):
            type = "Ity_I32"
            tag = "Ico_Weird"

            def __init__(self, value):
                self._value = value

        with self.assertRaises(UnsupportedIRError):
            _Writer(None)._const(Weird(0))


if __name__ == "__main__":
    main()
