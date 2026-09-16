#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest
from unittest import mock

from cle.backends.blob import Blob

import angr
from angr.ailment import Manager
from angr.ailment.block import Block
from angr.ailment.expression import (
    Const,
    DirtyExpression,
    Insert,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import CAS, DirtyStatement, Jump, Store, WeakAssignment
from angr.analyses.decompiler.structured_codegen.rust import (
    RustConstant,
    RustExpression,
    RustSimTypeReference,
    RustStructuredCodeGenerator,
)
from angr.analyses.decompiler.structurer_nodes import (
    IncompleteSwitchCaseHeadStatement,
    IncompleteSwitchCaseNode,
    SequenceNode,
)
from angr.rust.optimization_passes.utils import extract_str, extract_str_from_addr, looks_like_text
from angr.rust.sim_type import RustSimTypeInt, RustSimTypeStrRef
from angr.sim_type import SimStruct, SimTypeBottom
from angr.utils.loader import is_in_section, is_known_writable_address, is_readable_address, object_has_sections
from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")

# what the Rust backend emits for a node it has no handler for
PLACEHOLDER = "unsupported instruction"


def _render(node):
    return "".join(chunk for chunk, _ in node.c_repr_chunks())


class TestRustCodegenHandlers(unittest.TestCase):
    """
    _handle_AILBlock() substitutes a placeholder for any statement the backend has no handler for, so a missing
    handler silently drops whatever the statement contained.
    """

    @classmethod
    def setUpClass(cls):
        # any binary will do: we only need a constructed Rust code generator to drive handlers with
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, show_progressbar=False)
        dec = proj.analyses.Decompiler(proj.kb.functions["main"], cfg=cfg.model, flavor="rust", fail_fast=True)
        assert isinstance(dec.codegen, RustStructuredCodeGenerator)
        cls.proj = proj
        cls.codegen = dec.codegen

    def _manager(self):
        return Manager()

    @staticmethod
    def _vvar(m, varid, bits=64, category=VirtualVariableCategory.REGISTER):
        return VirtualVariable(m.next_atom(), varid, bits, category)

    def test_handler_table_covers_everything_the_c_backend_covers(self):
        """A missing handler degrades silently, so guard the whole class rather than one node type at a time."""
        proj = self.proj
        cfg = proj.kb.cfgs.get_most_accurate()
        c_dec = proj.analyses.Decompiler(proj.kb.functions["main"], cfg=cfg, flavor="pseudocode", fail_fast=True)
        assert c_dec.codegen is not None

        missing = set(c_dec.codegen._handlers) - set(self.codegen._handlers)
        assert not missing, f"Rust backend has no handler for {sorted(str(k) for k in missing)}"

    def test_operators_without_a_renderer_keep_their_operands(self):
        """The operator name is derived from the VEX op, so the renderer table cannot enumerate it."""
        cases = [
            # PowerPC renders essentially every conditional through CmpORD.
            ("ppc", "brancher", 0x1000048C, "CmpORD("),
            # ARM's division helper counts leading zeros (Iop_ClzNat32 since libVEX 3.27).
            ("armel", "test_division", 0x8678, "ClzNat("),
        ]

        for arch, name, function_addr, rendered in cases:
            with self.subTest(binary=name):
                proj = angr.Project(os.path.join(test_location, arch, name), auto_load_libs=False)
                cfg = proj.analyses.CFGFast(normalize=True, data_references=True, show_progressbar=False)
                proj.analyses.CompleteCallingConventions(recover_variables=True)
                dec = proj.analyses.Decompiler(
                    proj.kb.functions[function_addr], cfg=cfg.model, flavor="rust", fail_fast=True
                )
                assert dec.codegen is not None
                text = dec.codegen.text
                assert text is not None

                self.assertIn(rendered, text)
                # the operand used to be discarded, leaving the operator name as bare text
                self.assertNotIn("UnaryOp ", text)
                self.assertNotIn("BinaryOp ", text)

    def test_insert(self):
        m = self._manager()
        expr = Insert(
            m.next_atom(),
            self._vvar(m, 1),
            Const(m.next_atom(), 0, 8),
            self._vvar(m, 2, bits=32),
            "Iend_LE",
        )

        out = _render(self.codegen._handle(expr))
        assert "_INSERT(" in out
        assert PLACEHOLDER not in out

    def test_dirty_statement(self):
        m = self._manager()
        dirty = DirtyExpression(m.next_atom(), "amd64g_dirtyhelper_RDTSC", [], bits=64)
        stmt = DirtyStatement(m.next_atom(), dirty, ins_addr=0x400100)

        out = _render(self.codegen._handle(stmt, is_expr=False))
        assert "amd64g_dirtyhelper_RDTSC" in out
        assert PLACEHOLDER not in out

    def test_weak_assignment(self):
        m = self._manager()
        stmt = WeakAssignment(m.next_atom(), self._vvar(m, 1), self._vvar(m, 2), ins_addr=0x400100)

        out = _render(self.codegen._handle(stmt, is_expr=False))
        assert "=" in out
        assert PLACEHOLDER not in out

    def test_cas(self):
        m = self._manager()
        stmt = CAS(
            m.next_atom(),
            Const(m.next_atom(), 0x1000, 64),
            Const(m.next_atom(), 1, 32),
            None,
            Const(m.next_atom(), 0, 32),
            None,
            self._vvar(m, 2, bits=32),
            None,
            "Iend_LE",
            ins_addr=0x400100,
        )

        out = _render(self.codegen._handle(stmt, is_expr=False))
        assert "atomic_compare_exchange" in out
        assert PLACEHOLDER not in out

    def test_incomplete_switch_case_head_statement(self):
        m = self._manager()
        case_blocks = [Block(0x400200 + i, 1, statements=[]) for i in range(2)]
        stmt = IncompleteSwitchCaseHeadStatement(
            m.next_atom(),
            self._vvar(m, 1),
            [
                (case_blocks[0], 0, 0x400300, None, 0x400210),
                (case_blocks[1], 1, 0x400400, None, 0x400220),
                (None, "default", 0x400500, None, 0x400230),
            ],
            ins_addr=0x400100,
        )

        out = _render(self.codegen._handle(stmt, is_expr=False))
        # every case target has to survive, plus the default
        assert "0x400300" in out
        assert "0x400400" in out
        assert "0x400500" in out
        assert PLACEHOLDER not in out

    def test_incomplete_switch_case_node(self):
        m = self._manager()
        head = Block(
            0x400100, 1, statements=[Jump(m.next_atom(), Const(m.next_atom(), 0x400200, 64), ins_addr=0x400100)]
        )
        cases = [
            SequenceNode(
                0x400200,
                nodes=[
                    Block(
                        0x400200,
                        1,
                        statements=[Jump(m.next_atom(), Const(m.next_atom(), 0x400300, 64), ins_addr=0x400200)],
                    )
                ],
            )
        ]
        node = IncompleteSwitchCaseNode(0x400100, head, cases)

        out = _render(self.codegen._handle(node, is_expr=False))
        assert "incomplete" in out
        assert "0x400200" in out
        assert PLACEHOLDER not in out

    def test_bbbq_rust_flavor_has_no_placeholders(self):
        bin_path = os.path.join(test_location, "x86_64", "bbbq")
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x410920, expand_call_tree=False, run_ccc=False)
        proj.analyses.RustSymbolRecovery()
        proj.analyses.TypeDBLoader()
        dec = proj.analyses.Decompiler(0x410920, cfg=cfg.model, flavor="rust", fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        text = dec.codegen.text
        assert PLACEHOLDER not in text
        # the bit-insertions that used to be dropped are rendered now
        assert "_INSERT(" in text


class TestRustStoreWidth(unittest.TestCase):
    """A store's emitted Rust has to write as many bytes as the AIL store writes."""

    @classmethod
    def setUpClass(cls):
        # any binary will do: we only need a constructed Rust code generator to drive the handler with
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, show_progressbar=False)
        dec = proj.analyses.Decompiler(proj.kb.functions["main"], cfg=cfg.model, flavor="rust", fail_fast=True)
        assert isinstance(dec.codegen, RustStructuredCodeGenerator)
        cls.codegen = dec.codegen

    def _store(self, idx: int, value_type, value_bits: int, size: int):
        # the destination is what _access turns into the dereference, so its type is the width written
        data = Const(idx, 0, value_bits, type=value_type)
        # an address inside no section, so the constant handler cannot retype it as a string or a function pointer
        stmt = Store(idx, Const(idx, 0x7FFF00000000, 64), data, size, "Iend_LE")
        return self.codegen._handle(stmt, is_expr=False)

    def test_value_typed_narrower_than_the_store(self):
        assert self._store(1, RustSimTypeInt(size=32, signed=False), 32, 8).lhs.type.size == 64

    def test_value_typed_wider_than_the_store(self):
        assert self._store(2, RustSimTypeInt(size=64, signed=False), 64, 1).lhs.type.size == 8

    def test_value_with_no_inferred_type(self):
        # SimTypeBottom carries no size at all, so the store width is the only information there is
        store = self._store(3, SimTypeBottom(), 128, 16)
        assert store.lhs.type.size == 128
        # Rust has a native 128-bit integer, so the repaired width is spelled directly
        assert "u128" in _render(store)

    def test_value_typed_correctly_is_left_alone(self):
        assert self._store(4, RustSimTypeInt(size=64, signed=False), 64, 8).lhs.type.size == 64

    def test_aggregate_value_is_not_cast(self):
        # a scalar cast cannot change the width of a &str, so the mismatch is reported, not "repaired"
        store = self._store(5, RustSimTypeStrRef(), 128, 8)
        assert store.lhs.type.size == 128

    def test_value_with_no_type_at_all(self):
        """A value whose type comes back None must not take the handler down.

        RustIndexedVariable and RustBinaryOp both return None for a type they cannot work out.
        Guarding only the diagnostic, as the C backend does, moves the crash from the diagnostic
        into _access ("no type whatsoever for dereference"), so the value is retyped instead.
        """

        class Untyped(RustExpression):
            """stands in for any Rust expression whose type comes back None"""

            __slots__ = ()

            @property
            def type(self):
                return None

            def c_repr_chunks(self, indent=0, asexpr=False):
                yield "UNTYPED", self

        untyped = Untyped(codegen=self.codegen)
        real_handle = self.codegen._handle

        def handle(node, **kwargs):
            # the AIL layer does not preserve object identity, so key on the constant's value
            return untyped if getattr(node, "value", None) == 0xD1CE else real_handle(node, **kwargs)

        stmt = Store(6, Const(6, 0x7FFF00000000, 64), Const(6, 0xD1CE, 64), 8, "Iend_LE")
        with mock.patch.object(self.codegen, "_handle", handle):
            store = RustStructuredCodeGenerator._handle_Stmt_Store(self.codegen, stmt)
        assert store.lhs.type.size == 64


class TestRustCodegenMalformedConstantReferences(unittest.TestCase):
    """
    The Rust backend treats a constant as a &str fat pointer and a pointer's pointee as a struct without
    establishing that either really is one. Both guesses used to raise out of the code generator, and the
    Decompiler's resilience turned that into an empty function body -- a silent, total loss of output.
    """

    @classmethod
    def setUpClass(cls):
        # df.o holds a constant one word short of the end of a mapped region whose first word points into
        # a read-only section, which is exactly what the &str heuristic accepts and then reads past.
        bin_path = os.path.join(test_location, "x86_64", "df.o")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, show_progressbar=False)
        dec = proj.analyses.Decompiler(proj.kb.functions[0x4033E5], cfg=cfg.model, flavor="rust", fail_fast=True)
        assert isinstance(dec.codegen, RustStructuredCodeGenerator)
        cls.proj = proj
        cls.codegen = dec.codegen

    def test_const_whose_str_length_word_is_unmapped(self):
        proj = self.proj
        m = Manager()
        addr = 0x405600

        # preconditions: the constant is in a readable section, its first word points into a read-only
        # section -- so the &str heuristic engages -- but the length word beside it is not mapped at all.
        section = proj.loader.find_section_containing(addr)
        assert section is not None and section.is_readable
        pointee = proj.loader.find_section_containing(proj.loader.memory.unpack(addr, proj.arch.struct_fmt())[0])
        assert pointee is not None and pointee.is_readable and not pointee.is_writable
        with self.assertRaises(KeyError):
            proj.loader.memory.unpack(addr + proj.arch.bytes, proj.arch.struct_fmt())

        out = self.codegen._handle_Expr_Const(Const(m.next_atom(), addr, proj.arch.bits))
        # not a string: rendered as the plain constant it is
        assert isinstance(out, RustConstant)
        assert f"{addr:x}" in _render(out).lower().replace("_", "")

    def test_access_constant_offset_through_a_struct_with_no_fields(self):
        # a type database can hand the code generator a declared-but-empty struct; there is no field to
        # select an offset within, so the access has to fall back to a pointer cast rather than blow up
        proj = self.proj
        struct_type = SimStruct({}, name="opaque").with_arch(proj.arch)
        assert isinstance(struct_type, SimStruct)
        assert not struct_type.offsets

        expr = RustConstant(0x1000, RustSimTypeReference(struct_type).with_arch(proj.arch), codegen=self.codegen)
        out = self.codegen._access_constant_offset(expr, 0, SimTypeBottom(), True)
        # falls through to the pointer cast the C backend already produces
        assert _render(out) == "*(0x1000 as *u8)"


class TestRustStringRecoveryWithoutASectionTable(unittest.TestCase):
    """
    The Oxidizer asked ``find_section_containing`` before it would read a Rust ``&str``, so an object that
    publishes no section table -- a monolithic image compiled from Rust, loaded through cle's Blob backend --
    recovered no ``&str`` at all. Nothing raised and nothing was reported; the strings were simply absent.
    """

    BIN = os.path.join(test_location, "x86_64", "rust_hello_world")
    MAIN = 0x408A20
    FAT_POINTER = 0x45A148
    LITERAL = "Hello, world!\n"
    RENDERED = '"Hello, world!\\n"'  # how the code generator writes it back out
    EMPTY_STR_REFS = (0x45A4B0, 0x45A4D0, 0x45A4F0, 0x45A848)  # fat pointers whose length word is zero

    @classmethod
    def setUpClass(cls):
        cls.elf = angr.Project(cls.BIN, auto_load_libs=False)
        base = cls.elf.loader.main_object.mapped_base
        cls.base = base
        # The same bytes with the section table removed: mapped the way the image's own program headers
        # say, at the image's own link base, so every address the image stores in itself still resolves.
        segments = [(s.offset, s.vaddr - base, s.filesize) for s in cls.elf.loader.main_object.segments if s.filesize]
        cls.blob = angr.Project(
            cls.BIN,
            auto_load_libs=False,
            main_opts={
                "backend": "blob",
                "arch": cls.elf.arch.name,
                "base_addr": 0,
                "entry_point": cls.elf.entry - base,
                "segments": segments,
            },
        )

    def test_the_blob_publishes_no_sections(self):
        # the preconditions the recovery has to cope with, rather than an assumption about them
        assert isinstance(self.blob.loader.main_object, Blob)
        assert not self.blob.loader.main_object.sections
        assert self.blob.loader.main_object.segments
        assert not object_has_sections(self.blob, self.FAT_POINTER - self.base)
        assert not is_in_section(self.blob, self.FAT_POINTER - self.base)
        assert is_readable_address(self.blob, self.FAT_POINTER - self.base)
        assert not is_known_writable_address(self.blob, self.FAT_POINTER - self.base)
        # the same address in the ELF sits in .data.rel.ro, which is a writable section
        assert object_has_sections(self.elf, self.FAT_POINTER)
        assert is_in_section(self.elf, self.FAT_POINTER)
        assert is_known_writable_address(self.elf, self.FAT_POINTER)

    def test_str_ref_is_read_through_a_blob(self):
        assert extract_str_from_addr(self.elf, self.FAT_POINTER) == self.LITERAL
        assert extract_str_from_addr(self.blob, self.FAT_POINTER - self.base) == self.LITERAL

    def test_one_byte_of_a_pointer_is_not_a_string(self):
        # (0x45a148, 1) is a fat pointer and a piece count, not a pointer and a length. In the ELF the
        # writable section says so; in the blob nothing does, and only the text filter keeps the low byte
        # of the pointer -- "W" -- from being reported as a one-character literal.
        assert extract_str(self.elf, self.FAT_POINTER, 1) is None
        assert extract_str(self.blob, self.FAT_POINTER - self.base, 1) is None
        assert not looks_like_text("W")
        assert looks_like_text(self.LITERAL)

    def test_a_hole_between_an_elf_s_sections_is_not_read(self):
        # the ELF header sits inside a read-only segment and inside no section. An object that publishes
        # sections and does not cover an address with one is saying something, so the loosening this change
        # makes for a blob must not reach here -- including for bytes that would pass the text filter.
        header = self.elf.loader.main_object.mapped_base
        assert object_has_sections(self.elf, header)
        assert not is_in_section(self.elf, header)
        assert is_readable_address(self.elf, header)
        assert extract_str(self.elf, header, 8) is None
        assert bytes(self.elf.loader.memory.load(header + 1, 3)) == b"ELF"
        assert extract_str(self.elf, header + 1, 3) is None

        # and through the other entry point. fauxware's program headers hold what reads as a fat pointer,
        # (0x400238, 28), whose data pointer is .interp -- so the text filter would not reject it either.
        fauxware = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        hole = 0x400090
        assert not is_in_section(fauxware, hole)
        assert fauxware.loader.memory.unpack(hole, fauxware.arch.struct_fmt())[0] == 0x400238
        assert is_in_section(fauxware, 0x400238)
        assert extract_str_from_addr(fauxware, hole) is None

    def test_an_empty_str_ref_reads_as_empty_where_a_section_says_so(self):
        # a fat pointer whose length word is zero. The code generator has always rendered that as "" when
        # a section said the pointer was constant data, and it still does; a blob has no section to say it.
        for addr in self.EMPTY_STR_REFS:
            assert is_in_section(self.elf, addr)
            assert extract_str_from_addr(self.elf, addr) == ""
            assert extract_str_from_addr(self.blob, addr - self.base) is None

    def test_decompiling_a_blob_inlines_the_literal(self):
        proj = self.blob
        cfg = proj.analyses.CFGFast(normalize=True, show_progressbar=False)
        func = proj.kb.functions.function(addr=self.MAIN - self.base)
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg.model, flavor="rust", fail_fast=True)
        assert dec.codegen is not None
        print_decompilation_result(dec)
        assert self.RENDERED in dec.codegen.text


if __name__ == "__main__":
    unittest.main()
