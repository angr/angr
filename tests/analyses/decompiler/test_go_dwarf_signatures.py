#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.go.analyses.dwarf_signatures import read_go_dwarf_signatures
from angr.go.signature import GoSignatureSet
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")
GO_CORPUS = os.path.join(test_location, "x86_64", "go")


def read_signatures(path: str) -> GoSignatureSet:
    proj = angr.Project(path, auto_load_libs=False)
    return read_go_dwarf_signatures(proj)


def pairs(params) -> list[tuple[str, str]]:
    return [(p.name, p.type_str) for p in params]


class GoDwarfSignatureTarget(unittest.TestCase):
    """Per-toolchain base: reads the `basics` binary once per class."""

    VERSION: str = ""
    sigs: GoSignatureSet

    @classmethod
    def setUpClass(cls):
        if not cls.VERSION:
            raise unittest.SkipTest("abstract target")
        cls.sigs = read_signatures(os.path.join(GO_CORPUS, cls.VERSION, "basics"))

    def test_metadata(self):
        assert self.sigs.go_version == self.VERSION
        assert self.sigs.goarch == "amd64"
        assert len(self.sigs.functions) > 1000

    def test_parse(self):
        sig = self.sigs.functions["main.parse"]
        assert sig.recv is None
        assert pairs(sig.params) == [("s", "string")]
        assert pairs(sig.results) == [("~r0", "int"), ("~r1", "error")]

    def test_divmod(self):
        sig = self.sigs.functions["main.divmod"]
        assert pairs(sig.params) == [("a", "int"), ("b", "int")]
        assert [p.type_str for p in sig.results] == ["int", "int"]

    def test_scale(self):
        sig = self.sigs.functions["main.scale"]
        assert pairs(sig.params) == [("p", "*main.point"), ("k", "int")]
        assert sig.results == []

    def test_sum_and_count(self):
        assert pairs(self.sigs.functions["main.sum"].params) == [("xs", "[]int")]
        assert pairs(self.sigs.functions["main.count"].params) == [("s", "string"), ("c", "uint8")]

    def test_manhattan_by_value(self):
        sig = self.sigs.functions["main.manhattan"]
        assert pairs(sig.params) == [("p", "main.point")]
        assert [p.type_str for p in sig.results] == ["int"]

    def test_main(self):
        sig = self.sigs.functions["main.main"]
        assert sig.params == [] and sig.results == [] and sig.recv is None

    def test_methods(self):
        sig = self.sigs.functions["errors.(*errorString).Error"]
        assert sig.recv is not None and sig.recv.type_str == "*errors.errorString"
        assert sig.params == []
        assert [p.type_str for p in sig.results] == ["string"]
        assert sig.all_params[0] is sig.recv

        sig = self.sigs.functions["runtime.errorString.Error"]
        assert sig.recv is not None and sig.recv.type_str == "runtime.errorString"

    def test_point_struct(self):
        ty = self.sigs.types["main.point"]
        assert ty.kind == "struct"
        assert ty.size == 16 and ty.align == 8
        assert [(f.name, f.type_str, f.offset) for f in ty.fields] == [("x", "int", 0), ("y", "int", 8)]

    def test_error_interface(self):
        ty = self.sigs.types["error"]
        assert ty.kind == "interface"
        assert ty.size == 16
        assert ty.methods == [("Error", "func() string")]

    def test_named_types(self):
        ty = self.sigs.types["errors.errorString"]
        assert ty.kind == "struct" and [(f.name, f.type_str) for f in ty.fields] == [("s", "string")]
        ty = self.sigs.types["runtime.errorString"]
        assert ty.kind == "named" and ty.underlying == "string" and ty.size == 16
        ty = self.sigs.types["runtime.pMask"]
        assert ty.kind == "named" and ty.underlying == "[]uint32" and ty.size == 24
        ty = self.sigs.types["internal/abi.Kind"]  # uint in go1.22, uint8 since go1.23
        assert ty.kind == "named" and (ty.underlying, ty.size) in (("uint", 8), ("uint8", 1))
        # every type string mentioned by a signature is either literal/predeclared or a known named type
        for name, ty in self.sigs.types.items():
            assert ty.name == name
            assert ty.kind in ("struct", "interface", "named")
            if ty.kind == "struct":
                for f in ty.fields:
                    assert f.type_str and "hash<" not in f.type_str and "hchan<" not in f.type_str

    def test_no_internal_spellings(self):
        for sig in self.sigs.functions.values():
            for p in sig.all_params + sig.results:
                assert "interface {}" not in p.type_str
                assert not p.type_str.startswith(("hash<", "*hash<", "hchan<", "*hchan<"))

    def test_json_roundtrip(self):
        d = self.sigs.to_json()
        back = GoSignatureSet.from_json(d)
        assert back.functions["main.parse"] == self.sigs.functions["main.parse"]
        assert back.types["main.point"] == self.sigs.types["main.point"]


class TestGoDwarfSignatures1225(GoDwarfSignatureTarget):
    VERSION = "go1.22.5"


class TestGoDwarfSignatures1271(GoDwarfSignatureTarget):
    VERSION = "go1.27.1"


class TestGoDwarfSignaturesMisc(unittest.TestCase):
    def test_stripped_binary_is_empty(self):
        for version in ("go1.22.5", "go1.27.1"):
            sigs = read_signatures(os.path.join(GO_CORPUS, version, "basics_stripped"))
            assert sigs.functions == {} and sigs.types == {}
            assert sigs.go_version is None

    def test_os_file_write(self):
        sigs = read_signatures(os.path.join(test_location, "x86_64", "langdetect_go"))
        sig = sigs.functions["os.(*File).Write"]
        assert sig.recv is not None and sig.recv.name == "f" and sig.recv.type_str == "*os.File"
        assert pairs(sig.params) == [("b", "[]uint8")]
        assert pairs(sig.results) == [("n", "int"), ("err", "error")]
        assert sigs.types["os.File"].kind == "struct"
        # out-of-line instances of inlinable functions resolve through their abstract origin
        sig = sigs.functions["syscall.Errno.Is"]
        assert sig.recv is not None and sig.recv.type_str == "syscall.Errno"
        assert pairs(sig.params) == [("target", "error")]
        assert pairs(sig.results) == [("~r0", "bool")]
        assert sigs.types["syscall.Errno"].underlying == "uintptr"


if __name__ == "__main__":
    unittest.main()
