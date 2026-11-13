# Tests for BinaryDecompiler: whole-binary decompilation that walks the call tree from the leaves to the root and then
# back from the root to the leaves, so that the types each function learns reach every other function.
# pylint: disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest
from unittest import mock

from archinfo import ArchAMD64

import angr
from angr.analyses.decompiler import DecompilationStatus, Decompiler, SecondPassOrder
from angr.analyses.decompiler.cross_function_type_inference import CrossFunctionTypeInference
from angr.analyses.decompiler.struct_union import pointer_to_layout
from angr.sim_type import (
    SimStruct,
    SimTypeArray,
    SimTypeChar,
    SimTypeFixedSizeArray,
    SimTypeInt,
    SimTypeLongLong,
    SimTypePointer,
    TypeRef,
)
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

# Ground truth from tests_src/decompiler/binary_struct_propagation.c. Only the members the program accesses can be
# recovered, so these are the offsets of the accessed members (nested struct point and the tag array flattened).
#
# struct conn { int fd@0; int state@4; char *host@8; struct point pos@16 {x@16, y@20}; long bytes_in@24;
#               long bytes_out@32; unsigned short port@40; char tag[6]@42 (tag[0]@42, tag[5]@47); struct conn *next@48 }
CONN_SIZE = 56
CONN_OFFSETS = {0, 4, 8, 16, 20, 24, 32, 40, 42, 47, 48}
# struct stats { long requests@0; long errors@8; int max_conns@16; int cur_conns@20; long total_bytes@24;
#                struct point origin@32 {x@32, y@36}; char name[16]@40 }
STATS_SIZE = 56
STATS_OFFSETS = {0, 8, 16, 20, 24, 32, 36, 40}

# the functions whose first argument is the struct conn pointer, and the members each one touches itself
CONN_FUNCTIONS = {
    "read_side": {0, 24},
    "write_side": {4, 32},
    "log_host": {8, 40},
    "log_pos": {16, 20},
    "tag_chars": {42, 47},
    "handle_io": set(),
    "log_conn": set(),
    "serve": {48},
    "drain_a": {4},
    "drain_b": {40, 48},
}
# (caller, callee) edges of the call tree
CALL_EDGES = {
    ("main", "serve"),
    ("serve", "handle_io"),
    ("serve", "log_conn"),
    ("handle_io", "read_side"),
    ("handle_io", "write_side"),
    ("log_conn", "log_host"),
    ("log_conn", "log_pos"),
    ("log_conn", "tag_chars"),
    ("main", "drain_a"),
    ("drain_a", "drain_b"),
    ("drain_b", "drain_a"),
    ("main", "find_fd"),
    ("main", "count_conns"),
    ("main", "set_name"),
    ("main", "clamp"),
}

BINARIES = ("binary_struct_propagation", "binary_struct_propagation_O2")


def _resolve(ty):
    while isinstance(ty, TypeRef):
        ty = ty.ty
    return ty


def _struct(ty) -> SimStruct | None:
    ty = _resolve(ty)
    if isinstance(ty, SimTypePointer):
        ty = _resolve(ty.pts_to)
    return ty if isinstance(ty, SimStruct) else None


def _real_fields(struct: SimStruct) -> dict[int, object]:
    return {
        struct.offsets[name]: _resolve(fty) for name, fty in struct.fields.items() if not name.startswith("padding_")
    }


def _flat_offsets(struct: SimStruct, base: int = 0) -> set[int]:
    # the start offsets of every scalar member, with nested structs flattened (a recovered layout may keep pos as a
    # struct point or flatten it into two ints; both are right)
    offsets = set()
    for off, fty in _real_fields(struct).items():
        if isinstance(fty, SimStruct):
            offsets |= _flat_offsets(fty, base + off)
        else:
            offsets.add(base + off)
    return offsets


def _end(struct: SimStruct) -> int:
    end = 0
    for off, fty in _real_fields(struct).items():
        size = fty.size // 8 if fty.size is not None else 1
        end = max(end, off + size)
    return end


def _union_struct_names(text: str) -> set[str]:
    return set(re.findall(r"\bustruct_\d+\b", text))


class _Run:
    """
    One BinaryDecompiler run on a binary, with the prototype of every function snapshotted after each pass.
    """

    def __init__(self, binary: str, second_pass=SecondPassOrder.ROOT_TO_LEAF):
        self.proj = angr.Project(os.path.join(test_location, "x86_64", "decompiler", binary), auto_load_libs=False)
        self.protos: dict[int, list] = {}
        self.order: list[tuple[int, int]] = []

        def _snapshot(addr, rec, dec):  # pylint:disable=unused-argument
            self.order.append((2 if rec.second_status is not DecompilationStatus.NOT_RUN else 1, addr))
            self.protos.setdefault(addr, []).append(self.proj.kb.functions[addr].prototype)

        self.bd = self.proj.analyses.BinaryDecompiler(
            fail_fast=True, second_pass=second_pass, function_callback=_snapshot
        )
        self.funcs = self.proj.kb.functions

    def addr(self, name: str) -> int:
        return self.funcs[name].addr

    def arg_struct(self, name: str, pass_idx: int, arg: int = 0) -> SimStruct | None:
        proto = self.protos[self.addr(name)][pass_idx - 1]
        assert proto is not None and len(proto.args) > arg, (name, proto)
        return _struct(proto.args[arg])

    def global_type(self, name: str):
        gm = self.proj.kb.dec_variables["global"]
        matches = [v for v in gm._variables if v.name == name]
        assert matches, f"no global variable {name} recovered"
        return gm.get_variable_type(matches[0])

    def text(self, name: str) -> str:
        text = self.bd.records[self.addr(name)].text
        assert text is not None, name
        return text


_RUNS: dict[tuple[str, SecondPassOrder], _Run] = {}


def _run(binary: str, second_pass=SecondPassOrder.ROOT_TO_LEAF) -> _Run:
    key = (binary, second_pass)
    if key not in _RUNS:
        _RUNS[key] = _Run(binary, second_pass)
    return _RUNS[key]


class TestBinaryDecompiler(unittest.TestCase):
    #
    # The order of the two passes
    #

    def test_call_tree_order(self):
        for binary in BINARIES:
            with self.subTest(binary=binary):
                run = _run(binary)
                bd = run.bd
                first = {addr: i for i, addr in enumerate(bd.first_pass_order)}

                # every function is decompiled exactly once per pass, and the second pass walks the first backwards
                assert sorted(bd.first_pass_order) == sorted(bd.records)
                assert len(first) == len(bd.first_pass_order)
                assert bd.second_pass_order == list(reversed(bd.first_pass_order))
                assert [addr for p, addr in run.order if p == 1] == bd.first_pass_order
                assert [addr for p, addr in run.order if p == 2] == bd.second_pass_order

                # pass 1 decompiles every callee before its callers, except inside the drain_a <-> drain_b cycle
                for caller, callee in CALL_EDGES:
                    if {caller, callee} == {"drain_a", "drain_b"}:
                        continue
                    assert first[run.addr(callee)] < first[run.addr(caller)], (binary, caller, callee)

                # the cycle is decompiled as one unit after everything it calls and before main
                a, b = first[run.addr("drain_a")], first[run.addr("drain_b")]
                assert abs(a - b) == 1, (binary, a, b)
                # main enters the cycle at drain_a, so the root-to-leaf pass reaches drain_a before drain_b
                assert b < a, (binary, a, b)
                assert max(a, b) < first[run.addr("main")]

                # main is a root, the bottom of every chain is a leaf, and the middle of the tree is neither
                assert run.addr("main") in bd.roots
                for leaf in ("read_side", "write_side", "log_host", "log_pos", "tag_chars", "clamp", "count_conns"):
                    assert run.addr(leaf) in bd.leaves, (binary, leaf)
                for middle in ("handle_io", "log_conn", "serve"):
                    assert run.addr(middle) not in bd.leaves and run.addr(middle) not in bd.roots, (binary, middle)

    def test_second_pass_orders(self):
        run = _run(BINARIES[0], SecondPassOrder.LEAF_TO_ROOT)
        assert run.bd.second_pass_order == run.bd.first_pass_order

        proj = angr.Project(os.path.join(test_location, "x86_64", "decompiler", BINARIES[0]), auto_load_libs=False)
        bd = proj.analyses.BinaryDecompiler(fail_fast=True, second_pass="none", functions=["clamp", "main"])
        assert bd.second_pass_order == []
        assert all(rec.second_status is DecompilationStatus.NOT_RUN for rec in bd.records.values())
        assert all(rec.first_status is DecompilationStatus.OK for rec in bd.records.values())

    def test_function_subset(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "decompiler", BINARIES[0]), auto_load_libs=False)
        names = ["serve", "handle_io", "read_side", "write_side"]
        bd = proj.analyses.BinaryDecompiler(fail_fast=True, functions=names)
        funcs = proj.kb.functions
        assert [funcs[a].name for a in bd.first_pass_order[:2]] == ["read_side", "write_side"]
        assert [funcs[a].name for a in bd.first_pass_order[2:]] == ["handle_io", "serve"]
        assert bd.roots == [funcs["serve"].addr]
        assert not bd.failed

    #
    # Propagation
    #

    def test_second_pass_reaches_sibling_leaves(self):
        # read_side and write_side see disjoint members of the same struct conn. After the first pass each one only
        # knows its own members; the union handle_io builds reaches both of them only through the second pass.
        for binary in BINARIES:
            with self.subTest(binary=binary):
                run = _run(binary)
                for leaf, sibling in (("read_side", "write_side"), ("write_side", "read_side")):
                    own, theirs = CONN_FUNCTIONS[leaf], CONN_FUNCTIONS[sibling]
                    first = run.arg_struct(leaf, 1)
                    assert first is not None and _flat_offsets(first) >= own, (binary, leaf, first)
                    assert not _flat_offsets(first) & theirs, (binary, leaf, first.fields)

                    second = run.arg_struct(leaf, 2)
                    assert second is not None, (binary, leaf)
                    assert _flat_offsets(second) >= own | theirs, (binary, leaf, second.fields)
                    assert run.bd.records[run.addr(leaf)].changed_in_second_pass, (binary, leaf)

                    # the rendered leaf now accesses the sibling's members through the one shared typedef
                    text = run.text(leaf)
                    assert _union_struct_names(text), (binary, leaf, text)
                    assert f"{run.arg_struct(sibling, 2).name} *a0" in text, (binary, leaf, text)

    def test_pointer_global_struct(self):
        # g_head is walked by count_conns and find_fd (next@48, fd@0) and written by main
        for binary in BINARIES:
            with self.subTest(binary=binary):
                run = _run(binary)
                ty = run.global_type("g_head")
                assert isinstance(_resolve(ty), SimTypePointer), (binary, ty)
                struct = _struct(ty)
                assert struct is not None, (binary, ty)
                assert _flat_offsets(struct) >= {0, 48}, (binary, struct.fields)
                # the list link is typed as a pointer
                assert isinstance(_real_fields(struct)[48], SimTypePointer), (binary, struct.fields)

    #
    # Precision
    #

    def test_scalars_and_library_prototypes_stay_untouched(self):
        for binary in BINARIES:
            with self.subTest(binary=binary):
                run = _run(binary)
                clamp = run.funcs["clamp"].prototype
                assert clamp is not None and len(clamp.args) == 3
                assert not any(_struct(a) is not None for a in clamp.args), (binary, clamp)
                for name in ("find_fd", "count_conns", "set_name"):
                    proto = run.funcs[name].prototype
                    assert proto is not None
                    assert not any(_struct(a) is not None for a in proto.args), (binary, name, proto)

                # strncpy is handed a member of g_stats; its library prototype must not be refined into a struct
                for name in ("strncpy", "printf", "calloc"):
                    if name not in run.funcs:
                        continue
                    proto = run.funcs[name].prototype
                    if proto is not None:
                        assert not any(_struct(a) is not None for a in proto.args), (binary, name, proto)
                for text in (rec.text for rec in run.bd.records.values() if rec.text):
                    assert "strncpy(" not in text or "ustruct" not in text.split("strncpy(")[1].split(")")[0]

    def test_no_members_past_the_struct_end(self):
        for binary in BINARIES:
            with self.subTest(binary=binary):
                run = _run(binary)
                for name in CONN_FUNCTIONS:
                    for pass_idx in (1, 2):
                        struct = run.arg_struct(name, pass_idx)
                        if struct is not None:
                            assert _end(struct) <= CONN_SIZE, (binary, name, pass_idx, struct.fields)
                head = _struct(run.global_type("g_head"))
                assert head is not None and _end(head) <= CONN_SIZE, (binary, head)
                stats = _resolve(run.global_type("g_stats"))
                if isinstance(stats, SimStruct):
                    assert _end(stats) <= STATS_SIZE, (binary, stats.fields)
                elif isinstance(stats, SimTypeArray):
                    assert stats.size // 8 <= STATS_SIZE, (binary, stats)

    def test_every_union_struct_is_declared(self):
        for binary in BINARIES:
            with self.subTest(binary=binary):
                run = _run(binary)
                for rec in run.bd.records.values():
                    assert rec.text is not None, (binary, rec.name, rec.errors)
                    for name in _union_struct_names(rec.text):
                        assert f"typedef struct {name} " in rec.text, (binary, rec.name, name, rec.text)

    #
    # Robustness
    #

    def test_a_crashing_function_does_not_stop_the_run(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "decompiler", BINARIES[0]), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        clamp = cfg.functions["clamp"].addr
        original_init = Decompiler.__init__

        def _init(self, func, *args, **kwargs):
            addr = func.addr if hasattr(func, "addr") else func
            if addr == clamp:
                raise RuntimeError("boom")
            original_init(self, func, *args, **kwargs)

        names = ["clamp", "find_fd", "main"]
        with mock.patch.object(Decompiler, "__init__", _init):
            bd = proj.analyses.BinaryDecompiler(cfg=cfg, fail_fast=False, functions=names)
            assert bd.failed == [clamp]
            rec = bd.records[clamp]
            assert rec.first_status is DecompilationStatus.FAILED
            assert rec.second_status is DecompilationStatus.FAILED
            assert rec.text is None and any("boom" in err for err in rec.errors)
            for name in ("find_fd", "main"):
                other = bd.records[cfg.functions[name].addr]
                assert other.first_status is DecompilationStatus.OK, (name, other.errors)
                assert other.second_status is DecompilationStatus.OK, (name, other.errors)
                assert other.text is not None

            # with fail_fast, the crash propagates
            with self.assertRaisesRegex(RuntimeError, "boom"):
                proj.analyses.BinaryDecompiler(cfg=cfg, fail_fast=True, functions=names)

    def test_timeout(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "decompiler", BINARIES[0]), auto_load_libs=False)
        bd = proj.analyses.BinaryDecompiler(fail_fast=False, functions=["main"], timeout=1e-6)
        rec = bd.records[proj.kb.functions["main"].addr]
        assert rec.first_status is DecompilationStatus.TIMEOUT, rec
        assert rec.second_status is DecompilationStatus.TIMEOUT, rec
        assert bd.failed == [rec.addr]

    #
    # Full recovery. These assert the ground truth and do not hold yet; each names the gap it is waiting on.
    #

    def test_every_function_sees_the_whole_conn_struct(self):
        # every function on the chain sees every member of struct conn after the second pass: the leaves' members
        # reach the callers through each level of the tree, adjacent same-size members (pos.x/pos.y, tag[0]/tag[5])
        # are kept as members rather than array elements, and the union comes back down to every leaf
        for binary in BINARIES:
            run = _run(binary)
            for name in CONN_FUNCTIONS:
                struct = run.arg_struct(name, 2)
                assert struct is not None, (binary, name)
                assert _flat_offsets(struct) >= CONN_OFFSETS, (binary, name, sorted(_flat_offsets(struct)))
                assert _end(struct) <= CONN_SIZE, (binary, name, struct.fields)
            names = {run.arg_struct(name, 2).name for name in CONN_FUNCTIONS}
            assert len(names) == 1, (binary, names)

    def test_by_value_global_struct_has_every_member(self):
        # g_stats is touched by value at every depth of the tree, each function seeing other members: two adjacent ints
        # (max_conns/cur_conns in serve, origin.x/origin.y in log_pos and main) that read like an int array, a lone
        # long at offset 0 (read_side), and a member whose address alone is handed to strncpy (name in set_name). It is
        # one struct with every member, and every function renders member accesses on it.
        for binary in BINARIES:
            run = _run(binary)
            ty = _resolve(run.global_type("g_stats"))
            assert isinstance(ty, SimStruct), (binary, ty)
            assert _flat_offsets(ty) >= STATS_OFFSETS, (binary, sorted(_flat_offsets(ty)))
            assert _end(ty) <= STATS_SIZE, (binary, ty.fields)
            for name in ("read_side", "write_side", "log_pos", "log_conn", "serve", "main", "set_name"):
                text = run.text(name)
                assert re.search(r"\bg_stats\.\w+", text), (binary, name, text)

    def test_pushed_union_never_hides_a_callee_access(self):
        # the union pushed into a callee covers every member the callee accesses itself, so the second pass never
        # renders one of its accesses as a dereference of padding
        for binary in BINARIES:
            run = _run(binary)
            for name in CONN_FUNCTIONS:
                text = run.text(name)
                assert not re.search(r"->padding_\w+", text), (binary, name, text)


class TestUnionCoversAccesses(unittest.TestCase):
    def test_every_access_must_land_inside_a_member(self):
        arch = ArchAMD64()
        union = pointer_to_layout(
            {
                0: SimTypeInt().with_arch(arch),
                8: SimTypeLongLong().with_arch(arch),
                42: SimTypeFixedSizeArray(SimTypeChar(), 6).with_arch(arch),
            },
            arch,
        ).pts_to
        covers = CrossFunctionTypeInference._union_covers_accesses
        assert covers(union, {0: 32, 8: 64})
        # inside a wider member: tag[5] lies within the char[6] at 42, the low half of the long at 8
        assert covers(union, {47: 8, 8: 32})
        # an access in padding, or one wider than the member it starts in, is hidden by the union
        assert not covers(union, {16: 32})
        assert not covers(union, {0: 64})
        assert not covers(union, {46: 32})


if __name__ == "__main__":
    unittest.main()
