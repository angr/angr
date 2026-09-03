#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import archinfo

from angr.analyses.typehoon import typeconsts
from angr.go.signature import GoFuncSignature, GoNamedType, GoSignatureSet, GoStructField
from angr.go.sim_type import (
    GoSimStruct,
    GoSimTypeArray,
    GoSimTypeFunc,
    GoSimTypeInt,
    GoSimTypeInterface,
    GoSimTypeMap,
    GoSimTypePointer,
    GoSimTypeSlice,
    GoSimTypeString,
    GoSimTypeTuple,
)
from angr.go.type_parser import GoTypeParser
from angr.go.typehoon.translator import GoTypeTranslator
from angr.sim_type import SimType, SimTypeLongLong, SimTypePointer

ARCH = archinfo.ArchAMD64()

TYPES = {
    "main.point": GoNamedType(
        "main.point", "struct", 16, 8, [GoStructField("x", "int", 0), GoStructField("y", "int", 8)]
    ),
    "main.node": GoNamedType(
        "main.node", "struct", 24, 8, [GoStructField("next", "*main.node", 0), GoStructField("s", "string", 8)]
    ),
    "main.padded": GoNamedType(
        "main.padded", "struct", 16, 8, [GoStructField("a", "uint8", 0), GoStructField("b", "int", 8)]
    ),
    "time.Duration": GoNamedType("time.Duration", "named", 8, 8, underlying="int64"),
    "io.Writer": GoNamedType("io.Writer", "interface", 16, 8, methods=[("Write", "func([]uint8) (int, error)")]),
}


def parser():
    return GoTypeParser(ARCH, TYPES.get)


class TestGoTypeParser(unittest.TestCase):
    def test_predeclared(self):
        p = parser()
        cases = {
            "int": ("int", 64),
            "uint8": ("uint8", 8),
            "byte": ("byte", 8),
            "uintptr": ("uintptr", 64),
            "bool": ("bool", 8),
            "float64": ("float64", 64),
            "float32": ("float32", 32),
            "string": ("string", 128),
            "any": ("any", 128),
            "error": ("error", 128),
            "unsafe.Pointer": ("unsafe.Pointer", 64),
        }
        for s, (spelling, size) in cases.items():
            with self.subTest(type=s):
                t = p.parse(s)
                assert t.go_repr() == spelling
                assert t.size == size

    def test_composites(self):
        p = parser()
        assert isinstance(p.parse("[]int"), GoSimTypeSlice)
        assert p.parse("[]int").size == 192
        assert isinstance(p.parse("[4]int"), GoSimTypeArray)
        assert p.parse("[4]int").size == 256
        assert isinstance(p.parse("*main.point"), GoSimTypePointer)
        assert isinstance(p.parse("map[string][]int"), GoSimTypeMap)
        assert p.parse("map[string][]int").go_repr() == "map[string][]int"
        assert p.parse("chan<- int").go_repr() == "chan<- int"
        assert p.parse("<-chan main.point").go_repr() == "<-chan main.point"
        assert p.parse("[]*os.File").go_repr() == "[]*os.File"
        assert p.parse("struct { x int; y int }").go_repr() == "struct { x int; y int }"
        assert p.parse("struct { x int; y int }").size == 128
        assert p.parse("interface { Error() string }").go_repr() == "interface { Error() string }"

    def test_functions(self):
        p = parser()
        f = p.parse("func(int, string) (int, error)")
        assert isinstance(f, GoSimTypeFunc)
        assert f.go_repr() == "func(int, string) (int, error)"
        assert isinstance(f.signature.returnty, GoSimTypeTuple)
        assert f.signature.returnty.size == 192
        assert p.parse("func(string, ...any) (int, error)").go_repr() == "func(string, ...any) (int, error)"
        assert p.parse("func()").go_repr() == "func()"
        sig = p.parse_signature(["string"], ["int", "error"], ["s"])
        assert sig.repr("main.parse") == "func main.parse(s string) (int, error)"
        assert [r.go_repr() for r in sig.results] == ["int", "error"]

    def test_named_types(self):
        p = parser()
        pt = p.parse("main.point")
        assert isinstance(pt, GoSimStruct)
        assert pt.go_repr() == "main.point"
        assert pt.offsets == {"x": 0, "y": 8}
        assert pt.size == 128
        # pinned layout wins over angr's own alignment rules
        padded = p.parse("main.padded")
        assert padded.offsets == {"a": 0, "b": 8}
        assert padded.size == 128
        # self-referential types terminate and point back at themselves
        node = p.parse("main.node")
        assert node.fields["next"].pts_to is node
        # named non-struct types keep their name but the underlying representation
        d = p.parse("time.Duration")
        assert isinstance(d, GoSimTypeInt)
        assert d.go_repr() == "time.Duration"
        assert d.size == 64
        w = p.parse("io.Writer")
        assert isinstance(w, GoSimTypeInterface)
        assert w.go_repr() == "io.Writer"
        assert [n for n, _ in w.methods] == ["Write"]
        # unknown names are opaque
        assert p.parse("net/http.Server").go_repr() == "net/http.Server"
        assert p.parse("slices.Index[[]int,int]").go_repr() == "slices.Index[[]int,int]"

    def test_json_round_trip(self):
        p = parser()
        for s in [
            "string",
            "[]int",
            "map[string]int",
            "func(int) error",
            "*main.point",
            "error",
            "chan int",
            "unsafe.Pointer",
            "[3]float64",
            "main.point",
            "struct { a int; b string }",
            "time.Duration",
        ]:
            with self.subTest(type=s):
                t = p.parse(s)
                t2 = SimType.from_json(t.to_json()).with_arch(ARCH)
                assert t2 == t, s
                assert t2.go_repr() == t.go_repr()
                assert t2.size == t.size

    def test_signature_records(self):
        d = {
            "go_version": "go1.22.5",
            "goarch": "amd64",
            "functions": {
                "strconv.Atoi": {"params": [["s", "string"]], "results": [["~r0", "int"], ["~r1", "error"]]},
                "os.(*File).Write": {
                    "recv": ["f", "*os.File"],
                    "params": [["b", "[]uint8"]],
                    "results": [["n", "int"], ["err", "error"]],
                },
            },
            "types": {"os.File": {"kind": "struct", "size": 8, "align": 8, "fields": [["file", "*os.file", 0]]}},
        }
        ss = GoSignatureSet.from_json(d)
        assert ss.to_json() == d
        sig = ss.functions["os.(*File).Write"]
        assert isinstance(sig, GoFuncSignature)
        assert [pp.type_str for pp in sig.all_params] == ["*os.File", "[]uint8"]


class TestGoTypeTranslator(unittest.TestCase):
    def test_typeconst_to_go(self):
        tr = GoTypeTranslator(ARCH)
        assert tr.tc2simtype(typeconsts.Int64())[0].go_repr() == "int"
        assert tr.tc2simtype(typeconsts.Int32())[0].go_repr() == "int32"
        assert tr.tc2simtype(typeconsts.Int8())[0].go_repr() == "uint8"
        assert tr.tc2simtype(typeconsts.Pointer64(typeconsts.BottomType()))[0].go_repr() == "unsafe.Pointer"
        assert tr.tc2simtype(typeconsts.Pointer64(typeconsts.Int32()))[0].go_repr() == "*int32"
        st = tr.tc2simtype(typeconsts.Struct({0: typeconsts.Int64(), 16: typeconsts.Int32()}, name="main.t"))[0]
        assert isinstance(st, GoSimStruct)
        assert list(st.fields) == ["field_0", "padding_8", "field_10"]

    def test_go_to_typeconst(self):
        tr = GoTypeTranslator(ARCH)
        p = parser()
        assert isinstance(tr.simtype2tc(p.parse("int")), typeconsts.Int64)
        assert isinstance(tr.simtype2tc(p.parse("*main.point")), typeconsts.Pointer64)
        s = tr.simtype2tc(p.parse("string"))
        assert isinstance(s, typeconsts.Struct)
        assert set(s.fields) == {0, 8}
        sl = tr.simtype2tc(p.parse("[]int"))
        assert set(sl.fields) == {0, 8, 16}
        # C types re-expressed in Go
        assert tr.ctype2go(SimTypePointer(SimTypeLongLong(signed=True)).with_arch(ARCH)).go_repr() == "*int"

    def test_string_is_not_declared_like_a_struct(self):
        assert isinstance(GoSimTypeString().with_arch(ARCH), GoSimStruct)
        assert GoSimTypeString().with_arch(ARCH).go_repr() == "string"


if __name__ == "__main__":
    unittest.main()
