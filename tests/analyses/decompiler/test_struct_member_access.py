#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
import re
import unittest

import archinfo

import angr
import networkx

from angr import default_cc
from angr.ailment import Block, Manager
from angr.ailment.expression import (
    BinaryOp,
    Const,
    Extract,
    Insert,
    Load,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import Assignment
from angr.analyses.decompiler.clinic import Clinic
from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CExpression,
    CStructuredCodeGenerator,
)
from angr.analyses.decompiler.variable_map import VariableMap
from angr.sim_type import (
    PointerDisposition,
    SimCppClass,
    SimStruct,
    SimTypeBottom,
    SimTypeFunction,
    SimTypeInt,
    SimTypeLongLong,
    SimTypePointer,
)
from angr.sim_variable import SimStackVariable
from angr.utils.vvar_set import VVarSet
from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestStructMemberAccess(unittest.TestCase):
    def test_struct_member_write(self):
        self._check_struct_member_write(None)

    def test_struct_member_write_in_pointer(self):
        # the callee is known to read the struct: the members are merged into one stack variable during SSA
        self._check_struct_member_write(PointerDisposition.IN)

    def _check_struct_member_write(self, disposition: PointerDisposition | None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "struct_member_access")
        proj = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

        cfg = proj.analyses.CFG(data_references=True, normalize=True)

        main_func = cfg.functions["main"]
        foo_func = cfg.functions["foo"]

        angr.types.register_types(angr.types.parse_type("struct Inner {long long a; int b;}"))
        angr.types.register_types(angr.types.parse_type("struct Outer {char* a; struct Inner b;}"))

        foo_func.calling_convention = default_cc(
            proj.arch.name, platform=proj.simos.name if proj.simos is not None else None
        )(proj.arch)
        foo_func.prototype = angr.types.parse_type("void (struct Outer *a)").with_arch(proj.arch)
        if disposition is not None:
            foo_func.prototype.args[0].disposition = disposition

        dec = proj.analyses.Decompiler(main_func, cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        text = dec.codegen.text
        assert '.a = "123"' in text
        assert ".b.a = 2" in text
        assert ".b.b = 3" in text


class TestStructMemberSlotReuse(unittest.TestCase):
    def test_struct_member_read_before_overwrite(self):
        # gcc -O2 of: s.a = x; s.b = y; g(&s); old = s.a; s.a = y + 1; h(old); g(&s); return s.b;
        # the old s.a is reloaded into rdi before the slot is overwritten, so h() gets the old value
        f_addr, g_addr, h_addr = 0x401130, 0x401180, 0x401190
        code = bytes.fromhex(
            "55534889f34883c3014883ec184889e548893c244889ef4889742408e82f000000488b3c2448891c24e832000000"
            "4889efe81a000000488b4424084883c4185b5dc3662e0f1f8400000000000f1f4000"
            "488b074803470848894708c30f1f4000"  # g
            "48893d812e0000c3"  # h
        )
        proj = angr.load_shellcode(code, arch="AMD64", load_address=f_addr)
        cfg = proj.analyses.CFGFast(normalize=True, function_starts=[f_addr, g_addr, h_addr])
        proj.analyses.CompleteCallingConventions(recover_variables=False)
        proj.kb.functions[g_addr].name = "g"
        proj.kb.functions[h_addr].name = "h"
        arch = proj.arch
        struct = SimStruct({"a": SimTypeLongLong(), "b": SimTypeLongLong()}, name="S").with_arch(arch)
        proj.kb.functions[g_addr].prototype = SimTypeFunction(
            [SimTypePointer(struct)], SimTypeLongLong()
        ).with_arch(arch)
        proj.kb.functions[h_addr].prototype = SimTypeFunction([SimTypeLongLong()], SimTypeBottom()).with_arch(arch)

        dec = proj.analyses.Decompiler(proj.kb.functions[f_addr], cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        text = dec.codegen.text
        assert re.search(r"\b(v\d+)\.a = [^;]+;\s*h\(\1\.a\);", text) is None, text
        written = re.search(r"\b(v\d+)\.a = a0;", text)
        assert written is not None, text
        assert re.search(rf"\bh\({written.group(1)}\.a\);", text) is not None, text


class _FakeVariableManager:
    """Answers find_variables_by_atom() from a fixed {(stmt_idx, atom idx): (variable, offset)} table."""

    def __init__(self, atom_vars):
        self.atom_vars = atom_vars

    def find_variables_by_atom(self, block_addr, stmt_idx, atom, block_idx=None):  # pylint:disable=unused-argument
        v = self.atom_vars.get((stmt_idx, atom.idx))
        return {v} if v is not None else set()

    def unified_variable(self, variable):
        return variable


class _FakeVariablesPlugin:
    def __init__(self, manager):
        self.manager = manager

    def __getitem__(self, key):
        return self.manager

    def get_global_manager(self, flavor=None):  # pylint:disable=unused-argument
        return self

    def get_global_variables(self, addr):  # pylint:disable=unused-argument
        return set()


class _FakeKB:
    def __init__(self, manager):
        self.variables = _FakeVariablesPlugin(manager)


class _FakeFunction:
    addr = 0x400000


class _FakeLiveness:
    def __init__(self, block):
        self.model = type("model", (), {"live_outs": {(block.addr, block.idx): VVarSet()}})()


class TestStructMemberLinking(unittest.TestCase):
    """
    Links one hand-built block against a 0x34-byte struct-typed stack variable at -0x34. Neither shape occurs in the
    sweep binaries on master; devirtualized VM bodies produce both.
    """

    STRUCT = SimStackVariable(-0x34, 0x34, ident="s_34", name="s")

    @classmethod
    def _link(cls, statements, atom_vars):
        block = Block(0x400000, 0x10, statements=statements, idx=0)
        graph = networkx.DiGraph()
        graph.add_node(block)
        clinic = Clinic.__new__(Clinic)
        clinic.function = _FakeFunction()
        # only consulted for constants
        clinic.project = angr.load_shellcode(b"\x90", arch="AMD64")
        clinic.flavor = None
        clinic.entry_node_addr = (block.addr, block.idx)
        clinic.variable_map = VariableMap()
        clinic._stack_complex_types = {cls.STRUCT.offset: (cls.STRUCT, 0x34)}
        clinic._stack_complex_type_offsets = [cls.STRUCT.offset]
        clinic._stack_vvar_struct_cover = {}
        clinic._stack_vvars_outside_struct = set()
        clinic._pending_stack_memory_members = []
        clinic._link_variables_on_block(block, _FakeKB(_FakeVariableManager(atom_vars)))
        clinic._map_stack_vvars_to_struct_members(graph, _FakeLiveness(block))
        return clinic.variable_map

    def test_load_through_unmapped_vvar_is_not_a_member(self):
        # w covers the struct and is read after v overwrites part of it, so v stays its own variable; a load through
        # &v must then not read the struct either
        m = Manager()
        whole = VirtualVariable(m.next_atom(), 1, 0x34 * 8, VirtualVariableCategory.STACK, oident=-0x34)
        part = VirtualVariable(m.next_atom(), 2, 48, VirtualVariableCategory.STACK, oident=-18)
        part_use = VirtualVariable(m.next_atom(), 2, 48, VirtualVariableCategory.STACK, oident=-18)
        whole_use = VirtualVariable(m.next_atom(), 1, 0x34 * 8, VirtualVariableCategory.STACK, oident=-0x34)
        load = Load(
            m.next_atom(),
            BinaryOp(
                m.next_atom(),
                "Add",
                [UnaryOp(m.next_atom(), "Reference", part_use, bits=64), Const(m.next_atom(), 2, 64)],
                False,
                bits=64,
            ),
            2,
            "Iend_LE",
        )

        def reg(varid):
            return VirtualVariable(m.next_atom(), varid, 64, VirtualVariableCategory.REGISTER, oident=16)

        statements = [
            Assignment(m.next_atom(), whole, reg(10), ins_addr=0x400000),
            Assignment(m.next_atom(), part, reg(11), ins_addr=0x400004),
            Assignment(m.next_atom(), reg(12), load, ins_addr=0x400008),
            Assignment(m.next_atom(), reg(13), whole_use, ins_addr=0x40000C),
        ]
        part_var = SimStackVariable(-18, 6, ident="s_12")
        vm = self._link(
            statements,
            {
                (0, whole.idx): (self.STRUCT, 0),
                (1, part.idx): (part_var, 0),
                (2, part_use.idx): (part_var, 0),
                (2, load.idx): (part_var, 2),
                (3, whole_use.idx): (self.STRUCT, 0),
            },
        )
        assert vm.struct_member(part) is None
        assert vm.struct_member(load) is None

    def test_vvar_in_struct_region_variable_is_a_member(self):
        # the reference to v is linked to the variable of the whole region; v is still a member at its own offset
        m = Manager()
        part = VirtualVariable(m.next_atom(), 2, 32, VirtualVariableCategory.STACK, oident=-20)
        part_ref = VirtualVariable(m.next_atom(), 2, 32, VirtualVariableCategory.STACK, oident=-20)
        statements = [
            Assignment(
                m.next_atom(),
                part,
                VirtualVariable(m.next_atom(), 10, 32, VirtualVariableCategory.REGISTER, oident=16),
                ins_addr=0x400000,
            ),
            Assignment(
                m.next_atom(),
                VirtualVariable(m.next_atom(), 11, 64, VirtualVariableCategory.REGISTER, oident=24),
                UnaryOp(m.next_atom(), "Reference", part_ref, bits=64),
                ins_addr=0x400004,
            ),
        ]
        vm = self._link(
            statements,
            {(0, part.idx): (SimStackVariable(-20, 4, ident="s_14"), 0), (1, part_ref.idx): (self.STRUCT, None)},
        )
        assert vm.struct_member(part) == (self.STRUCT, 0x34 - 20)
        assert vm.struct_member(part_ref) == (self.STRUCT, 0x34 - 20)

    def test_vvar_linked_to_struct_and_other_variable_is_a_member(self):
        # one occurrence of the whole-struct vvar is linked to the struct, another to a separate variable at the same
        # slot; all of them must render as the struct
        m = Manager()
        whole = VirtualVariable(m.next_atom(), 2, 0x34 * 8, VirtualVariableCategory.STACK, oident=-0x34)
        whole_ref = VirtualVariable(m.next_atom(), 2, 0x34 * 8, VirtualVariableCategory.STACK, oident=-0x34)
        statements = [
            Assignment(
                m.next_atom(),
                whole,
                VirtualVariable(m.next_atom(), 10, 0x34 * 8, VirtualVariableCategory.REGISTER, oident=16),
                ins_addr=0x400000,
            ),
            Assignment(
                m.next_atom(),
                VirtualVariable(m.next_atom(), 11, 64, VirtualVariableCategory.REGISTER, oident=24),
                UnaryOp(m.next_atom(), "Reference", whole_ref, bits=64),
                ins_addr=0x400004,
            ),
        ]
        other = SimStackVariable(-0x34, 0x34, ident="s_34_other")
        vm = self._link(statements, {(0, whole.idx): (other, 0), (1, whole_ref.idx): (self.STRUCT, None)})
        assert vm.struct_member(whole) == (self.STRUCT, 0)
        assert vm.struct_member(whole_ref) == (self.STRUCT, 0)

    def test_vvars_of_one_variable_are_mapped_together(self):
        # a and b belong to one variable x; b overwrites bytes of w while w is still read, so b stays x, and then a
        # must stay x too
        m = Manager()

        def stack(varid, offset):
            return VirtualVariable(m.next_atom(), varid, 32, VirtualVariableCategory.STACK, oident=offset)

        def reg(varid):
            return VirtualVariable(m.next_atom(), varid, 32, VirtualVariableCategory.REGISTER, oident=16)

        w, b, a, w_use = stack(1, -0x34), stack(2, -0x34), stack(3, -0x30), stack(1, -0x34)
        statements = [
            Assignment(m.next_atom(), w, reg(10), ins_addr=0x400000),
            Assignment(m.next_atom(), b, reg(11), ins_addr=0x400004),
            Assignment(m.next_atom(), a, reg(12), ins_addr=0x400008),
            Assignment(m.next_atom(), reg(13), w_use, ins_addr=0x40000C),
        ]
        x = SimStackVariable(-0x34, 8, ident="s_34_x")
        vm = self._link(
            statements,
            {
                (0, w.idx): (self.STRUCT, 0),
                (1, b.idx): (x, 0),
                (2, a.idx): (x, 4),
                (3, w_use.idx): (self.STRUCT, 0),
            },
        )
        assert vm.struct_member(b) is None
        assert vm.struct_member(a) is None

    def test_taking_the_address_of_the_older_value_is_not_a_read(self):
        # w is only referenced after v overwrites part of it: the reference names the storage, so v is a member
        m = Manager()
        whole = VirtualVariable(m.next_atom(), 1, 0x34 * 8, VirtualVariableCategory.STACK, oident=-0x34)
        part = VirtualVariable(m.next_atom(), 2, 48, VirtualVariableCategory.STACK, oident=-18)
        whole_ref = VirtualVariable(m.next_atom(), 1, 0x34 * 8, VirtualVariableCategory.STACK, oident=-0x34)

        def reg(varid, bits):
            return VirtualVariable(m.next_atom(), varid, bits, VirtualVariableCategory.REGISTER, oident=16)

        statements = [
            Assignment(m.next_atom(), whole, reg(10, 0x34 * 8), ins_addr=0x400000),
            Assignment(m.next_atom(), part, reg(11, 48), ins_addr=0x400004),
            Assignment(
                m.next_atom(), reg(12, 64), UnaryOp(m.next_atom(), "Reference", whole_ref, bits=64), ins_addr=0x400008
            ),
        ]
        vm = self._link(
            statements,
            {
                (0, whole.idx): (self.STRUCT, 0),
                (1, part.idx): (SimStackVariable(-18, 6, ident="s_12"), 0),
                (2, whole_ref.idx): (self.STRUCT, None),
            },
        )
        assert vm.struct_member(part) == (self.STRUCT, 0x34 - 18)

    def _link_insert_then_read(self, read_offset: int):
        # n = Insert(w, 0, 8 bytes) is a variable of its own; w is read at read_offset afterwards
        m = Manager()
        bits = 0x34 * 8

        def whole(varid):
            return VirtualVariable(m.next_atom(), varid, bits, VirtualVariableCategory.STACK, oident=-0x34)

        def reg(varid, reg_bits):
            return VirtualVariable(m.next_atom(), varid, reg_bits, VirtualVariableCategory.REGISTER, oident=16)

        w, w_base, n, w_use = whole(1), whole(1), whole(2), whole(1)
        statements = [
            Assignment(m.next_atom(), w, reg(10, bits), ins_addr=0x400000),
            Assignment(
                m.next_atom(),
                n,
                Insert(m.next_atom(), w_base, Const(m.next_atom(), 0, 64), reg(11, 64), "Iend_LE"),
                ins_addr=0x400004,
            ),
            Assignment(
                m.next_atom(),
                reg(12, 32),
                Extract(m.next_atom(), 32, w_use, Const(m.next_atom(), read_offset, 64), "Iend_LE"),
                ins_addr=0x400008,
            ),
        ]
        other = SimStackVariable(-0x34, 0x34, ident="s_34_other")
        vm = self._link(
            statements,
            {
                (0, w.idx): (self.STRUCT, 0),
                (1, n.idx): (other, 0),
                (1, w_base.idx): (self.STRUCT, 0),
                (2, w_use.idx): (self.STRUCT, 0),
            },
        )
        return vm.struct_member(n)

    def test_insert_only_conflicts_with_reads_of_the_inserted_bytes(self):
        # the bytes of w that n did not replace are the same in both
        assert self._link_insert_then_read(16) == (self.STRUCT, 0)
        assert self._link_insert_then_read(4) is None


class _MinimalCodegen(CStructuredCodeGenerator):
    """The real code generator with only the state ``_access`` reads.

    Constructing a full ``CStructuredCodeGenerator`` needs a decompilation; ``_access`` itself
    needs an architecture and the node-numbering counters, so this initialises exactly those
    and leaves the method under test untouched.
    """

    class _Project:  # pylint:disable=too-few-public-methods
        def __init__(self, arch):
            self.arch = arch

    def __init__(self, arch):  # pylint:disable=super-init-not-called
        self.project = self._Project(arch)
        self.reset_ident_counters()
        self._next_node_idx = 0
        self.cstyle_null_cmp = False

    def _access_constant_offset(self, *args, **kwargs):
        # A tripwire rather than a stub: if the walk ever descends by a constant offset the test
        # has taken a different path and would otherwise pass for the wrong reason.
        raise AssertionError("_access should not reach _access_constant_offset here")


class _TypedExpression(CExpression):
    """A leaf expression that only has to carry a type."""

    def __init__(self, ty, codegen):
        super().__init__(codegen=codegen)
        self._ty = ty

    @property
    def type(self):
        return self._ty

    def c_repr_chunks(self, indent=0, asexpr=False):
        yield "x", self


class TestAccessOpaqueAggregate(unittest.TestCase):
    def test_access_through_pointer_to_member_less_class(self):
        # An opaque C++ class - one whose layout angr does not know - is built with no members
        # and a forced size, so its `offsets` is empty while its size is non-zero. Indexing
        # through a pointer to one used to select the greatest field offset not past the running
        # constant, which is `max()` over an empty sequence.
        #
        # The shape matters: two summed terms are needed for `_access` to enter its `while terms`
        # loop at all, because a lone expression becomes the kernel and the loop never runs. With
        # `p + i` the state on entry is a zero constant, a kernel stride of the class size and a
        # next stride of one, which is the state observed on a real binary that hit this.
        arch = archinfo.ArchX86()
        codegen = _MinimalCodegen(arch)
        opaque = SimCppClass(unique_name="Opaque", name="Opaque", members={}, size=32)
        assert not opaque.with_arch(arch).offsets

        pointer = _TypedExpression(SimTypePointer(opaque).with_arch(arch), codegen)
        index = _TypedExpression(SimTypeInt(signed=True).with_arch(arch), codegen)
        summed = CBinaryOp("Add", pointer, index, codegen=codegen)

        # bails out to pointer arithmetic instead of raising
        result = CStructuredCodeGenerator._access(codegen, summed, SimTypeInt(signed=True).with_arch(arch), False)
        assert isinstance(result, CExpression)


if __name__ == "__main__":
    unittest.main()
