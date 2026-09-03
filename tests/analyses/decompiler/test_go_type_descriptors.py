#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import time
import unittest

from elftools.elf.elffile import ELFFile

import angr
from angr.go.analyses.dwarf_signatures import DW_AT_GO_RUNTIME_TYPE, read_go_dwarf_signatures
from angr.go.analyses.type_descriptors import GoTypeDescriptors, read_go_type_descriptors
from angr.go.signature import GoNamedType
from angr.go.sim_type import GoSimStruct, GoSimTypeInterface, GoSimTypeMap, GoSimTypePointer
from angr.go.type_parser import GoTypeParser
from angr.go.utils.types import go_type_name_at
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")
GO_CORPUS = os.path.join(test_location, "x86_64", "go")

_PROJECTS: dict[str, angr.Project] = {}
_DESCRIPTORS: dict[str, GoTypeDescriptors] = {}


def corpus_path(version: str, prog: str) -> str:
    return os.path.join(GO_CORPUS, version, prog)


def project(version: str, prog: str) -> angr.Project:
    path = corpus_path(version, prog)
    if path not in _PROJECTS:
        _PROJECTS[path] = angr.Project(path, auto_load_libs=False)
    return _PROJECTS[path]


def descriptors(version: str, prog: str) -> GoTypeDescriptors:
    path = corpus_path(version, prog)
    if path not in _DESCRIPTORS:
        _DESCRIPTORS[path] = read_go_type_descriptors(project(version, prog), use_cache=False)
    return _DESCRIPTORS[path]


def fields(ty: GoNamedType) -> list[tuple[str, str, int]]:
    return [(f.name, f.type_str, f.offset) for f in ty.fields]


# DWARF spells unexported fields of anonymous structs with their package (`struct { runtime.n int32 }`) and
# `interface {}` for `any`; descriptors use the canonical spelling.
_QUALIFIED_FIELD_RE = re.compile(r"(?<=[{;] )[\w./]+\.(?=\w+ [^}])")
_LOCAL_SUFFIX_RE = re.compile(r"·\d+")


def normalize_dwarf(s: str) -> str:
    return _QUALIFIED_FIELD_RE.sub("", s.replace("interface {}", "any"))


def same_type(descriptor: str, dwarf: str) -> bool:
    # go.shape names are taken verbatim from the compiler by both readers; local types carry a DWARF-only ·N suffix
    dwarf = _LOCAL_SUFFIX_RE.sub("", dwarf)
    return _LOCAL_SUFFIX_RE.sub("", descriptor) in (dwarf, normalize_dwarf(dwarf))


def dwarf_runtime_types(path: str) -> dict[int, str]:
    """``DW_AT_go_runtime_type`` (an offset from runtime.types) -> DWARF type name, for every named type DIE."""
    out: dict[int, str] = {}
    with open(path, "rb") as f:
        dwarf = ELFFile(f).get_dwarf_info()
        for cu in dwarf.iter_CUs():
            for die in cu.iter_DIEs():
                attrs = die.attributes
                rt = attrs.get(DW_AT_GO_RUNTIME_TYPE) or attrs.get("DW_AT_go_runtime_type")
                if rt is None or not rt.value or "DW_AT_name" not in attrs:
                    continue
                out.setdefault(rt.value, attrs["DW_AT_name"].value.decode())
    return out


class GoTypeDescriptorTarget(unittest.TestCase):
    """Per-toolchain base."""

    VERSION: str = ""

    @classmethod
    def setUpClass(cls):
        if not cls.VERSION:
            raise unittest.SkipTest("abstract target")

    def test_metadata(self):
        for prog in ("basics", "builtins", "iface"):
            d = descriptors(self.VERSION, prog)
            assert d.go_version == self.VERSION
            assert d.types.go_version == self.VERSION and d.types.goarch == "amd64"
            assert d.moduledata_addr is not None and d.types_addr is not None
            assert len(d.addr_to_name) > 300 and len(d.types.types) > 100 and len(d.itabs) >= 7
            assert d.types.functions == {}
            for name, addr in d.name_to_addr.items():
                assert d.addr_to_name[addr] == name
            for ty in d.types.types.values():
                assert ty.kind in ("struct", "interface", "named")
                assert ty.size is not None and ty.align is not None

    def test_node_struct(self):
        d = descriptors(self.VERSION, "builtins")
        ty = d.types.types["main.node"]
        assert ty.kind == "struct" and ty.size == 16 and ty.align == 8
        assert fields(ty) == [("val", "int", 0), ("next", "*main.node", 8)]
        addr = d.name_to_addr["main.node"]
        assert d.addr_to_name[addr] == "main.node"
        assert d.name_to_addr["*main.node"] != addr

    def test_iface_types(self):
        d = descriptors(self.VERSION, "iface")
        rect = d.types.types["main.Rect"]
        assert rect.kind == "struct" and rect.size == 16 and fields(rect) == [("w", "int", 0), ("h", "int", 8)]
        square = d.types.types["main.Square"]
        assert square.kind == "struct" and square.size == 8 and fields(square) == [("side", "int", 0)]
        shape = d.types.types["main.Shape"]
        assert shape.kind == "interface" and shape.size == 16 and shape.align == 8
        assert shape.methods == [("Area", "func() int"), ("Name", "func() string")]
        assert {"*main.Rect", "*main.Square", "*main.Shape"} <= set(d.name_to_addr)
        assert {n for n in d.types.types if n.startswith("main.")} == {"main.Rect", "main.Square", "main.Shape"}

    def test_os_file(self):
        for prog in ("builtins", "iface"):
            ty = descriptors(self.VERSION, prog).types.types["os.File"]
            assert ty.kind == "struct" and ty.size == 8 and ty.align == 8
            assert fields(ty) == [("file", "*os.file", 0)]

    def test_predeclared_types_have_no_records(self):
        d = descriptors(self.VERSION, "iface")
        for name in ("error", "any", "int", "string", "uint8", "unsafe.Pointer"):
            assert name not in d.types.types
            assert name in d.name_to_addr
        names = set(d.addr_to_name.values())
        assert "byte" not in names and "interface {}" not in names
        assert not any("interface {}" in n for n in names)
        ty = d.types.types["errors.errorString"]
        assert ty.kind == "struct" and fields(ty) == [("s", "string", 0)]
        ty = d.types.types["runtime.errorString"]
        assert ty.kind == "named" and ty.underlying == "string" and ty.size == 16

    def test_composite_spellings_parse(self):
        d = descriptors(self.VERSION, "conc")
        names = set(d.addr_to_name.values())
        assert {"[]uint8", "func()", "chan int", "chan<- int", "struct {}", "*main.counter"} <= names
        parser = GoTypeParser(project(self.VERSION, "conc").arch, d.types.types.get)
        for name in names:
            if re.search(r"go\.shape\.(struct|interface) ", name):
                continue  # the parser cannot scan shape names spelled with a literal
            parser.parse(name)

    def test_maps(self):
        d = descriptors(self.VERSION, "maps")
        assert {"map[string]int", "map[int]string"} <= set(d.name_to_addr)
        parser = GoTypeParser(project(self.VERSION, "maps").arch, d.types.types.get)
        assert isinstance(parser.parse("map[string]int"), GoSimTypeMap)

    def test_itabs(self):
        d = descriptors(self.VERSION, "iface")
        pairs = set(d.itabs.values())
        assert {
            ("main.Shape", "main.Rect"),
            ("main.Shape", "*main.Square"),
            ("io.Writer", "*os.File"),
            ("error", "*errors.errorString"),
        } <= pairs
        mem = project(self.VERSION, "iface").loader.memory
        for addr, (iface, concrete) in d.itabs.items():
            assert addr % 8 == 0
            assert mem.unpack_word(addr, 8) == d.name_to_addr[iface]
            assert mem.unpack_word(addr + 8, 8) == d.name_to_addr[concrete]
            assert d.types.types[iface].kind == "interface" if iface != "error" else True

    def test_stripped_matches_unstripped(self):
        for prog in ("basics", "builtins", "iface", "maps"):
            full = descriptors(self.VERSION, prog)
            stripped = descriptors(self.VERSION, prog + "_stripped")
            assert project(self.VERSION, prog + "_stripped").loader.find_symbol("runtime.firstmoduledata") is None
            assert stripped.moduledata_addr is not None and stripped.go_version == self.VERSION
            main_full = {n: t for n, t in full.types.types.items() if n.startswith("main.")}
            main_stripped = {n: t for n, t in stripped.types.types.items() if n.startswith("main.")}
            assert main_full == main_stripped
            assert main_full or prog in ("basics", "maps")
            assert set(full.addr_to_name.values()) == set(stripped.addr_to_name.values())
            assert set(full.itabs.values()) == set(stripped.itabs.values())

    def test_basics_point_is_dead_stripped(self):
        # nothing in basics needs type:main.point at run time (no boxing, reflection or heap allocation of it),
        # so the linker drops the descriptor; DWARF still describes the type but points its runtime type at 0
        d = descriptors(self.VERSION, "basics")
        dwarf = read_go_dwarf_signatures(project(self.VERSION, "basics"))
        assert fields(dwarf.types["main.point"]) == [("x", "int", 0), ("y", "int", 8)]
        assert "main.point" not in d.types.types and "*main.point" not in d.name_to_addr
        assert not any(n.startswith("main.") for n in d.types.types)

    def test_agrees_with_dwarf(self):
        for prog in ("basics", "iface"):
            d = descriptors(self.VERSION, prog)
            dwarf = read_go_dwarf_signatures(project(self.VERSION, prog))
            structs = named = 0
            for name, ty in d.types.types.items():
                other = dwarf.types.get(name)
                if other is None:
                    continue
                assert ty.kind == other.kind, name
                if ty.kind == "struct":
                    structs += 1
                    assert ty.size == other.size, name
                    assert [(f.name, f.offset) for f in ty.fields] == [(f.name, f.offset) for f in other.fields], name
                    for f, g in zip(ty.fields, other.fields):
                        assert same_type(f.type_str, g.type_str), (name, f, g)
                elif ty.kind == "named":
                    named += 1
                    assert ty.size == other.size, name
                    assert same_type(ty.underlying, other.underlying), name
            assert structs > 100 and named > 20

    def test_dwarf_runtime_type_addresses(self):
        # DW_AT_go_runtime_type is a section offset relative to runtime.types (go1.22 spells it as an absolute
        # address on base types); descriptors no typelink reaches are parsed on demand
        d = descriptors(self.VERSION, "iface")
        checked = on_demand = 0
        for off, dwarf_name in dwarf_runtime_types(corpus_path(self.VERSION, "iface")).items():
            addr = off if off in d.addr_to_name else d.types_addr + off
            name = d.addr_to_name.get(addr)
            if name is None:
                name = d.resolve(addr)
                on_demand += 1
                assert name is not None and d.addr_to_name[addr] == name and d.name_to_addr[name] == addr
            if not dwarf_name.startswith("noalg."):  # DWARF-only naming of map bucket/group types
                assert same_type(name, dwarf_name), (name, dwarf_name)
            checked += 1
        assert checked > 300 and on_demand > 0
        assert d.resolve(d.types_addr + 1) is None and d.resolve(0) is None
        assert "interface { Is(error) bool }" in d.name_to_addr

    def test_parse_time(self):
        for prog in ("basics", "iface"):
            p = project(self.VERSION, prog)
            start = time.perf_counter()
            d = read_go_type_descriptors(p, use_cache=False)
            elapsed = time.perf_counter() - start
            assert d.moduledata_addr is not None
            assert elapsed < 1.0, elapsed


class TestGoTypeDescriptors1225(GoTypeDescriptorTarget):
    VERSION = "go1.22.5"


class TestGoTypeDescriptors1271(GoTypeDescriptorTarget):
    VERSION = "go1.27.1"


class TestGoTypesPlugin(unittest.TestCase):
    def test_plugin(self):
        p = angr.Project(corpus_path("go1.27.1", "iface"), auto_load_libs=False)
        kb = p.kb
        gt = kb.go_types
        assert not gt.loaded
        addr = gt.addr_of("main.Rect")
        assert gt.loaded and addr is not None
        assert gt.name_at(addr) == "main.Rect" and gt.name_at(0) is None and gt.addr_of("main.nope") is None
        assert gt.go_version == "go1.27.1"
        assert go_type_name_at(p, addr) == "main.Rect"

        ty = gt.type_at(addr)
        assert isinstance(ty, GoSimStruct) and ty.go_name == "main.Rect"
        assert list(ty.fields) == ["w", "h"] and ty.offsets["h"] == 8
        shape = gt.type_at(gt.addr_of("main.Shape"))
        assert isinstance(shape, GoSimTypeInterface) and [m for m, _ in shape.methods] == ["Area", "Name"]
        assert isinstance(gt.type_at(gt.addr_of("*main.Square")), GoSimTypePointer)
        assert gt.type_at(0) is None

        itab_addr = next(a for a, pair in gt.descriptors.itabs.items() if pair == ("io.Writer", "*os.File"))
        assert gt.itab_at(itab_addr) == ("io.Writer", "*os.File") and gt.itab_at(itab_addr + 8) is None
        assert gt.itab_at(0) is None and gt.name_at(itab_addr) is None

        # DWARF (parameter names) first, the descriptors second, the stdlib database last
        sigs = kb.go_signatures
        sigs.load_sources()
        assert sigs._sources[0].functions and sigs._sources[1] is gt.types
        assert sigs.named_type("main.Rect") is gt.types.types["main.Rect"] or sigs.named_type("main.Rect").fields
        assert gt.copy().descriptors is gt.descriptors

    def test_stripped_plugin_is_the_first_source(self):
        p = angr.Project(corpus_path("go1.22.5", "iface_stripped"), auto_load_libs=False)
        sigs = p.kb.go_signatures
        sigs.load_sources()
        assert sigs._sources[0] is p.kb.go_types.types
        assert sigs.go_version == "go1.22.5"
        shape = sigs.type("main.Shape")
        assert isinstance(shape, GoSimTypeInterface) and len(shape.methods) == 2
        assert isinstance(sigs.type("*main.Square"), GoSimTypePointer)

    def test_non_go_binary(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        d = read_go_type_descriptors(p, use_cache=False)
        assert d.moduledata_addr is None and not d.addr_to_name and not d.types.types and not d.itabs
        assert p.kb.go_types.name_at(p.entry) is None

    def test_langdetect_sample(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "langdetect_go"), auto_load_libs=False)
        d = read_go_type_descriptors(p, use_cache=False)
        assert d.go_version == "go1.22.5" and d.types.types["os.File"].size == 8
        assert ("io.Writer", "*os.File") in d.itabs.values()

    def test_process_cache(self):
        p = angr.Project(corpus_path("go1.22.5", "builtins"), auto_load_libs=False)
        assert read_go_type_descriptors(p) is read_go_type_descriptors(p)
        assert read_go_type_descriptors(p) is not read_go_type_descriptors(p, use_cache=False)


if __name__ == "__main__":
    unittest.main()
