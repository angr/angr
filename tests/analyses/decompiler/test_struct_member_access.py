#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
import re
import unittest

import archinfo

import angr
import networkx

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
from angr import ailment, default_cc
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
    SimTypeArray,
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

    @staticmethod
    def _decompile_shellcode_dec(code: bytes, *callee_addrs: int):
        # decompile the callees, then the caller at 0x400000 with the callees' prototypes available
        proj = angr.load_shellcode(code, arch="amd64", load_address=0x400000)
        cfg = proj.analyses.CFGFast(normalize=True, function_starts=[0x400000, *callee_addrs])
        proj.analyses.CompleteCallingConventions(recover_variables=False)
        for addr in callee_addrs:
            proj.analyses.Decompiler(addr, cfg=cfg.model, fail_fast=True)
        dec = proj.analyses.Decompiler(0x400000, cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        return proj, dec

    def _decompile_shellcode(self, code: bytes, *callee_addrs: int) -> str:
        return self._decompile_shellcode_dec(code, *callee_addrs)[1].codegen.text

    @staticmethod
    def _store_of_typed_zero(proj, dec, ty) -> str:
        # re-render the caller's `stack vvar = 0` with the constant typed as ty
        stmt = next(
            stmt
            for block in dec.clinic.graph.nodes
            for stmt in block.statements
            if isinstance(stmt, ailment.Stmt.Assignment) and isinstance(stmt.src, ailment.Expr.Const)
        )
        src = ailment.Expr.Const(None, 0, stmt.src.bits, type=ty.with_arch(proj.arch), **stmt.src.tags)
        typed = ailment.Stmt.Assignment(None, stmt.dst, src, **stmt.tags)
        return dec.codegen._handle_Stmt_Assignment(typed).c_repr().strip()

    def test_read_leading_member_of_stack_struct(self):
        # caller:
        #   push rbx; sub rsp, 0x20; mov rsi, rdi; mov rdi, rsp; call callee
        #   mov rax, [rsp]; mov ebx, [rax+4]; xor esi, esi; mov rdi, rsp; call callee
        #   mov eax, ebx; add rsp, 0x20; pop rbx; ret
        # callee:
        #   mov [rdi], rsi; mov dword ptr [rdi+8], 1; mov byte ptr [rdi+0xc], 2; ret
        code = bytes.fromhex(
            "534883ec204889fe4889e7e819000000488b04248b580431f64889e7e80800000089d84883c4205bc3"
            "488937c7470801000000c6470c02c3"
        )
        text = self._decompile_shellcode(code, 0x400029)
        m = re.search(r"^\s+st_\w+ (v\d+);", text, re.MULTILINE)
        assert m is not None, text
        var = m.group(1)
        # the pointer in the first member is dereferenced; the struct itself is never cast to a scalar
        assert re.search(rf"\({var}\.field_0 \+ 4\)", text) is not None, text
        assert re.search(rf"\)\s*{var}\b(?!\.)", text) is None, text

    def test_read_leading_element_of_stack_array(self):
        # caller:
        #   sub rsp, 0x28; mov rdi, rsp; call callee; mov rax, [rsp]; mov eax, [rax+4]; add rsp, 0x28; ret
        # callee:
        #   mov rax, [rdi+8]; add rax, [rdi+0x18]; ret
        code = bytes.fromhex("4883ec284889e7e80c000000488b04248b40044883c428c3488b470848034718c3")
        text = self._decompile_shellcode(code, 0x400018)
        m = re.search(r"^\s+unsigned long long (v\d+)\[\d+\];", text, re.MULTILINE)
        assert m is not None, text
        var = m.group(1)
        # the pointer in the first element is dereferenced, not the address of the array
        assert re.search(rf"\((\*{var}|{var}\[0\]) \+ 4\)", text) is not None, text

    def test_write_leading_element_of_stack_array(self):
        # caller:
        #   push rbx; sub rsp, 0x20; mov rbx, rdi; mov rdi, rsp; call callee
        #   mov [rsp], rbx; mov rdi, rsp; call callee; add rsp, 0x20; pop rbx; ret
        # callee:
        #   mov rax, [rdi+8]; add rax, [rdi+0x18]; ret
        code = bytes.fromhex("534883ec204889fb4889e7e81200000048891c244889e7e8060000004883c4205bc3488b470848034718c3")
        text = self._decompile_shellcode(code, 0x400022)
        m = re.search(r"^\s+unsigned long long (v\d+)\[\d+\];", text, re.MULTILINE)
        assert m is not None, text
        var = m.group(1)
        # an array is not assignable
        assert re.search(rf"^\s+(\*{var}|{var}\[0\]) = ", text, re.MULTILINE) is not None, text
        assert re.search(rf"^\s+{var} = ", text, re.MULTILINE) is None, text

    def test_read_stack_array_of_the_same_size(self):
        # caller:
        #   push rbx; sub rsp, 0x10; mov [rsp+8], rdi; lea rdi, [rsp+8]; call callee
        #   mov rax, [rsp+8]; add rsp, 0x10; pop rbx; ret
        # callee:
        #   mov dword ptr [rdi], 1; mov dword ptr [rdi+4], 2; ret
        code = bytes.fromhex(
            "534883ec1048897c2408488d7c2408e80b000000488b4424084883c4105bc3c70701000000c7470402000000c3"
        )
        text = self._decompile_shellcode(code, 0x40001F)
        m = re.search(r"^\s+unsigned int (v\d+)\[2\];", text, re.MULTILINE)
        assert m is not None, text
        var = m.group(1)
        # the 8 bytes in the array are returned, not its address
        assert re.search(rf"return \*\(\w+ \*\){var};", text) is not None, text

    def test_write_stack_array_of_the_same_size(self):
        # caller:
        #   push rbx; sub rsp, 0x10; lea rdi, [rsp+8]; call callee; mov qword ptr [rsp+8], 0
        #   lea rdi, [rsp+8]; call callee; add rsp, 0x10; pop rbx; ret
        # callee:
        #   mov dword ptr [rdi], 1; mov dword ptr [rdi+4], 2; ret
        code = bytes.fromhex(
            "534883ec10488d7c2408e81900000048c744240800000000488d7c2408e8060000004883c4105bc3"
            "c70701000000c7470402000000c3"
        )
        proj, dec = self._decompile_shellcode_dec(code, 0x400028)
        text = dec.codegen.text
        m = re.search(r"^\s+unsigned int (v\d+)\[2\];", text, re.MULTILINE)
        assert m is not None, text
        var = m.group(1)
        assert re.search(rf"^\s+\*\(\w+ \*\){var} = 0;", text, re.MULTILINE) is not None, text
        # a constant typed as the array itself is still the 8 bytes stored
        typed = self._store_of_typed_zero(proj, dec, SimTypeArray(SimTypeInt(signed=False), 2))
        assert re.fullmatch(rf"\*\(\w+ \*\){var} = 0;", typed) is not None, typed

    # caller:
    #   sub rsp, 0x28; mov rsi, rdi; mov rdi, rsp; call callee; mov <size> ptr [rsp], 0
    #   xor esi, esi; mov rdi, rsp; call callee; add rsp, 0x28; ret
    # callee:
    #   mov [rdi], rsi; mov dword ptr [rdi+8], 1; mov byte ptr [rdi+0xc], 2; ret
    STRUCT_WRITE_CALLEE = "488937c7470801000000c6470c02c3"

    def test_write_leading_member_of_stack_struct_composite_constant(self):
        # mov qword ptr [rsp], 0
        code = bytes.fromhex(
            "4883ec284889fe4889e7e81700000048c704240000000031f64889e7e8050000004883c428c3" + self.STRUCT_WRITE_CALLEE
        )
        proj, dec = self._decompile_shellcode_dec(code, 0x400026)
        # a constant typed as a struct of the size of the store is still an integer
        pair = SimStruct({"x": SimTypeInt(), "y": SimTypeInt()}, name="P")
        typed = self._store_of_typed_zero(proj, dec, pair)
        assert re.fullmatch(r"v\d+\.field_0 = 0;", typed) is not None, typed

    def test_write_leading_member_of_stack_struct_narrow(self):
        # mov byte ptr [rsp], 0
        code = bytes.fromhex(
            "4883ec284889fe4889e7e813000000c604240031f64889e7e8050000004883c428c3" + self.STRUCT_WRITE_CALLEE
        )
        proj, dec = self._decompile_shellcode_dec(code, 0x400022)
        assert re.search(r"^\s+\*\(char \*\)&v\d+\.field_0 = 0;", dec.codegen.text, re.MULTILINE) is not None
        # a constant typed as a struct of another size: one byte is written
        pair = SimStruct({"x": SimTypeInt(), "y": SimTypeInt()}, name="P")
        typed = self._store_of_typed_zero(proj, dec, pair)
        assert re.fullmatch(r"\*\(uint8_t \*\)&v\d+\.field_0 = 0;", typed) is not None, typed

    def test_write_leading_member_of_stack_struct_struct_source(self):
        # caller:
        #   push rbx; sub rsp, 0x20; mov rbx, rdi; mov rdi, rsp; call callee; mov [rsp], rbx
        #   mov rdi, rsp; call callee; add rsp, 0x20; pop rbx; ret
        # callee:
        #   mov dword ptr [rdi], 1; mov dword ptr [rdi+4], 2; mov qword ptr [rdi+8], 3; mov byte ptr [rdi+0x10], 4; ret
        code = bytes.fromhex(
            "534883ec204889fb4889e7e81200000048891c244889e7e8060000004883c4205bc3"
            "c70701000000c747040200000048c7470803000000c6471004c3"
        )
        proj, dec = self._decompile_shellcode_dec(code, 0x400022)
        stmt = next(
            stmt
            for block in dec.clinic.graph.nodes
            for stmt in block.statements
            if isinstance(stmt, ailment.Stmt.Assignment) and isinstance(stmt.src, ailment.Expr.VirtualVariable)
        )
        assert isinstance(stmt.dst, ailment.Expr.VirtualVariable) and stmt.dst.was_stack
        # retype the source as a struct of the size of the store: the two leading members are copied as a struct
        codegen = dec.codegen
        pair = SimStruct({"x": SimTypeInt(), "y": SimTypeInt()}, name="P").with_arch(proj.arch)
        src_var = codegen._variable_map.variable(stmt.src)
        proj.kb.dec_variables[0x400000].set_variable_type(src_var, pair)
        codegen.ailexpr2cnode.clear()
        text = codegen._handle_Stmt_Assignment(stmt).c_repr().strip()
        assert re.match(r"\*\(struct P \*\)&v\d+\.field_0 = ", text) is not None, text

    def test_leading_member_only_at_variable_base(self):
        # the caller of test_read_leading_element_of_stack_array
        code = bytes.fromhex("4883ec284889e7e80c000000488b04248b40044883c428c3488b470848034718c3")
        _, dec = self._decompile_shellcode_dec(code, 0x400018)
        ret = next(
            stmt
            for block in dec.clinic.graph.nodes
            for stmt in block.statements
            if isinstance(stmt, ailment.Stmt.Return)
        )
        vvar = ret.ret_exprs[0].addr.operands[0]
        assert isinstance(vvar, ailment.Expr.VirtualVariable) and vvar.was_stack
        codegen = dec.codegen
        var = codegen._variable_map.variable(vvar)
        assert re.fullmatch(r"\*v\d+", codegen._handle_VirtualVariable(vvar).c_repr()) is not None
        # linked 4 bytes into the variable, the vvar is not its leading element
        codegen._variable_map.set_variable(vvar, var, 4)
        assert re.fullmatch(r"v\d+", codegen._handle_VirtualVariable(vvar).c_repr()) is not None

    def test_register_carried_variable_typed_as_array_stays_plain(self):
        # the caller of test_read_stack_array_of_the_same_size
        code = bytes.fromhex(
            "534883ec1048897c2408488d7c2408e80b000000488b4424084883c4105bc3c70701000000c7470402000000c3"
        )
        proj, dec = self._decompile_shellcode_dec(code, 0x40001F)
        ret = next(
            stmt
            for block in dec.clinic.graph.nodes
            for stmt in block.statements
            if isinstance(stmt, ailment.Stmt.Return)
        )
        vvar = ret.ret_exprs[0]
        assert isinstance(vvar, ailment.Expr.VirtualVariable) and vvar.was_stack
        codegen = dec.codegen
        varman = proj.kb.dec_variables[0x400000]
        var = codegen._variable_map.variable(vvar)
        assert re.fullmatch(r"\*\(\w+ \*\)v\d+", codegen._handle_VirtualVariable(vvar).c_repr()) is not None
        # unified with a register variable, the array-typed variable is a spilled scalar
        reg_var = varman.get_variables(sort="reg")[0]
        varman.set_unified_variable(reg_var, varman.unified_variable(var))
        codegen._register_carried_variables = None
        assert re.fullmatch(r"\w+", codegen._handle_VirtualVariable(vvar).c_repr()) is not None

    def test_no_cast_to_an_array_type(self):
        # a register variable typed char[8] is assigned the difference of two integers
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "head.o")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        dec = proj.analyses.Decompiler(proj.kb.functions["elide_tail_lines_seekable"], cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        text = dec.codegen.text
        m = re.search(r"^\s+char (\w+)\[8\];  // rbp", text, re.MULTILINE)
        assert m is not None, text
        var = m.group(1)
        assert re.search(rf"^\s+{var} = a4 - \w+;", text, re.MULTILINE) is not None, text
        assert re.search(r"\(\w+\[\d+\]\)", text) is None, text

    def test_extract_from_dereferenced_leading_member(self):
        # caller:
        #   push rbx; push rbp; sub rsp, 0x28; mov rdi, rsp; call callee; mov rbx, [rsp]; mov ebp, [rsp]
        #   mov rdi, rsp; call callee; mov edi, ebp; call sink; add rax, rbx; add rsp, 0x28; pop rbp; pop rbx; ret
        # callee:
        #   mov dword ptr [rdi+0x10], 1; mov byte ptr [rdi+0x14], 2; ret
        # sink:
        #   lea eax, [rdi+1]; ret
        code = bytes.fromhex(
            "53554883ec284889e7e820000000488b1c248b2c244889e7e81100000089efe8160000004801d84883c4285d5bc3"
            "c7471001000000c6471402c38d4701c3"
        )
        text = self._decompile_shellcode(code, 0x40002E, 0x40003A)
        m = re.search(r"^\s+st_\w+ (v\d+);", text, re.MULTILINE)
        assert m is not None, text
        var = m.group(1)
        # the low 4 of the leading 8 bytes: no address of a dereference
        assert re.search(rf" \*\(unsigned int \*\)&?{var}\.padding_0(\[0\])?;", text) is not None, text
        assert "&*" not in text, text


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
        clinic._stack_vvars_outside_struct = {}
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

    def test_load_linked_to_unmapped_variable_is_not_a_member(self):
        # x overwrites bytes of w that are read afterwards and stays its own variable; p does not and is a member. a
        # load through &p that reads x must not read the struct
        m = Manager()

        def stack(varid, offset, size):
            return VirtualVariable(m.next_atom(), varid, size * 8, VirtualVariableCategory.STACK, oident=offset)

        def reg(varid, bits=64):
            return VirtualVariable(m.next_atom(), varid, bits, VirtualVariableCategory.REGISTER, oident=16)

        whole, p, x = stack(1, -0x34, 0x34), stack(2, -18, 6), stack(3, -24, 16)
        p_use, whole_use = stack(2, -18, 6), stack(1, -0x34, 0x34)
        load = Load(
            m.next_atom(),
            BinaryOp(
                m.next_atom(),
                "Add",
                [UnaryOp(m.next_atom(), "Reference", p_use, bits=64), Const(m.next_atom(), 2, 64)],
                False,
                bits=64,
            ),
            4,
            "Iend_LE",
        )
        statements = [
            Assignment(m.next_atom(), whole, reg(10, 0x34 * 8), ins_addr=0x400000),
            Assignment(m.next_atom(), p, reg(11, 48), ins_addr=0x400004),
            Assignment(m.next_atom(), x, reg(12, 128), ins_addr=0x400008),
            Assignment(m.next_atom(), reg(13, 32), load, ins_addr=0x40000C),
            Assignment(
                m.next_atom(),
                reg(14, 32),
                Extract(m.next_atom(), 32, whole_use, Const(m.next_atom(), 0x34 - 24, 64), "Iend_LE"),
                ins_addr=0x400010,
            ),
        ]
        p_var = SimStackVariable(-18, 6, ident="s_12")
        x_var = SimStackVariable(-24, 16, ident="s_18")
        vm = self._link(
            statements,
            {
                (0, whole.idx): (self.STRUCT, 0),
                (1, p.idx): (p_var, 0),
                (2, x.idx): (x_var, 0),
                (3, p_use.idx): (p_var, 0),
                (3, load.idx): (x_var, 8),
                (4, whole_use.idx): (self.STRUCT, 0),
            },
        )
        assert vm.struct_member(p) == (self.STRUCT, 0x34 - 18)
        assert vm.struct_member(x) is None
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
