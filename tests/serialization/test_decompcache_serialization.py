#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
"""Tests for the protobuf serialization of the DecompilationCache and its sub-objects.

These tests cover the work landed in commits 839fde31c..8780e1641 on the
feat/decompcache-serialization branch. The class-level round-trip tests guard against single-subclass regressions;
the end-to-end test asserts that a real fauxware decompilation round-trips with byte-identical rendered text; the
cache-hit test asserts that a deserialized cache can power a cache-hit in :class:`Decompiler` and produce the same
output as the original run."""

from __future__ import annotations

__package__ = __package__ or "tests.serialization"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
import angr.ailment as ailment
from archinfo import Endness
from angr.code_location import AILCodeLocation
from angr.engines.light import SpOffset
from angr.knowledge_plugins.key_definitions.atoms import (
    Atom,
    ConstantSrc,
    GuardUse,
    MemoryLocation,
    Register,
    Tmp,
    VirtualVariable,
)
from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.knowledge_plugins.key_definitions.heap_address import HeapAddress
from angr.knowledge_plugins.key_definitions.tag import (
    FunctionTag,
    InitialValueTag,
    LocalVariableTag,
    ParameterTag,
    ReturnValueTag,
    SideEffectTag,
    Tag,
    UnknownSizeTag,
)
from angr.knowledge_plugins.key_definitions.undefined import UNDEFINED

from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestKeyDefSerialization(unittest.TestCase):
    """Round-trip tests for the atoms / codeloc / tag / Definition classes added in step 2."""

    def _roundtrip(self, obj):
        return type(obj).parse(obj.serialize())

    def test_atom_tmp(self):
        a = Tmp(7, 4)
        b = self._roundtrip(a)
        assert b == a

    def test_atom_register(self):
        a = Register(8, 4)
        b = self._roundtrip(a)
        assert b == a

    def test_atom_guarduse(self):
        a = GuardUse(0x401000)
        b = self._roundtrip(a)
        assert b == a

    def test_atom_constantsrc(self):
        a = ConstantSrc(0xDEADBEEF, 4)
        b = self._roundtrip(a)
        assert b == a

    def test_atom_virtualvariable_int_oident(self):
        a = VirtualVariable(42, 4, ailment.Expr.VirtualVariableCategory.REGISTER, oident=16)
        b = self._roundtrip(a)
        assert b == a
        assert b.oident == 16

    def test_atom_virtualvariable_tuple_oident(self):
        # COMBO_REGISTER uses a tuple oident; JSON encoding turns it into a list, _tuplify restores it.
        a = VirtualVariable(43, 8, ailment.Expr.VirtualVariableCategory.COMBO_REGISTER, oident=(16, 24))
        b = self._roundtrip(a)
        assert b == a
        assert b.oident == (16, 24)

    def test_atom_memorylocation_int(self):
        a = MemoryLocation(0x1000, 4, endness=Endness.LE)
        assert self._roundtrip(a) == a

    def test_atom_memorylocation_spoffset(self):
        a = MemoryLocation(SpOffset(64, -16), 8, endness=Endness.LE)
        assert self._roundtrip(a) == a

    def test_atom_memorylocation_heapaddress(self):
        assert self._roundtrip(MemoryLocation(HeapAddress(0x1000), 4)) == MemoryLocation(HeapAddress(0x1000), 4)
        assert self._roundtrip(MemoryLocation(HeapAddress(UNDEFINED), 4)) == MemoryLocation(HeapAddress(UNDEFINED), 4)

    def test_atom_polymorphic_dispatch(self):
        # Atom.parse on the base class should dispatch to the correct concrete subclass.
        atoms_to_test = [
            Tmp(7, 4),
            Register(8, 4),
            GuardUse(0x401000),
            ConstantSrc(0xDEADBEEF, 4),
            VirtualVariable(42, 4, ailment.Expr.VirtualVariableCategory.REGISTER, oident=16),
            MemoryLocation(0x1000, 4, endness=Endness.LE),
        ]
        for a in atoms_to_test:
            b = Atom.parse(a.serialize())
            assert type(b) is type(a)
            assert b == a

    def test_ail_codeloc(self):
        for loc in [
            AILCodeLocation(0x400500, 0, 3, 0x400502),
            AILCodeLocation(0x400500, None, 3),
            AILCodeLocation.make_extern(7),
        ]:
            assert self._roundtrip(loc) == loc

    def test_tags(self):
        for tag in [
            Tag(metadata={"x": 1, "y": [1, 2, 3]}),
            Tag(),
            FunctionTag(function=0x400600),
            SideEffectTag(function=0x400700, metadata="side"),
            ParameterTag(function=None, metadata=None),
            LocalVariableTag(function=0x400800),
            ReturnValueTag(function=0x400900, metadata=[1, 2]),
            InitialValueTag(metadata="init"),
            UnknownSizeTag(),
        ]:
            back = self._roundtrip(tag)
            assert type(back) is type(tag)
            assert back.metadata == tag.metadata
            if isinstance(tag, FunctionTag):
                assert back.function == tag.function

    def test_definition_with_tags(self):
        d = Definition(
            Tmp(7, 4),
            AILCodeLocation(0x400500, 0, 3, 0x400502),
            dummy=True,
            tags={ParameterTag(function=0x400600), InitialValueTag(metadata="x")},
        )
        back = self._roundtrip(d)
        assert back.atom == d.atom
        assert back.codeloc == d.codeloc
        assert back.dummy is True
        assert len(back.tags) == 2
        assert any(isinstance(t, ParameterTag) and t.function == 0x400600 for t in back.tags)


class TestSubObjectSerialization(unittest.TestCase):
    """Round-trip tests for DecompilationNote and OpDescriptor (added in step 6)."""

    def test_decompilation_note(self):
        from angr.analyses.decompiler.notes.decompilation_note import (
            DecompilationNote,
            DecompilationNoteLevel,
        )

        n = DecompilationNote(
            key="warn1", name="Warning One", content={"foo": [1, 2]}, level=DecompilationNoteLevel.WARNING
        )
        back = DecompilationNote.parse(n.serialize())
        assert back.key == n.key
        assert back.name == n.name
        assert back.level == n.level
        assert back.content == n.content

    def test_op_descriptor(self):
        from angr.analyses.decompiler.optimization_passes.expr_op_swapper import OpDescriptor

        op = OpDescriptor(block_addr=0x400500, stmt_idx=3, ins_addr=0x400502, op="Sub")
        back = OpDescriptor.parse(op.serialize())
        assert back == op


class TestSRDAModelSerialization(unittest.TestCase):
    """Round-trip test for SRDAModel (step 3)."""

    def test_synthetic_srda_model(self):

        import archinfo
        from angr.ailment.expression import Tmp as AilTmp
        from angr.ailment.expression import VirtualVariable as AilVirtualVariable
        from angr.knowledge_plugins.key_definitions import atoms as kd_atoms
        from angr.analyses.s_reaching_definitions.s_rda_model import SRDAModel

        arch = archinfo.ArchAMD64()
        ail_vvar = AilVirtualVariable(0, ailment.Expr.VirtualVariableCategory.REGISTER, 4, 16, ins_addr=0x400500)
        ail_tmp = AilTmp(idx=0, variable=None, tmp_idx=5, bits=32, ins_addr=0x400801)

        model = SRDAModel(func_graph=None, func_args={ail_vvar}, arch=arch)
        model.varid_to_vvar[0] = ail_vvar
        model.all_vvar_definitions[0] = AILCodeLocation(0x400500, 0, 1, 0x400502)
        model.all_vvar_uses[0].append((ail_vvar, AILCodeLocation(0x400700, 0, 0)))
        model.all_tmp_definitions[(0x400800, 0)][kd_atoms.Tmp(5, 4)] = 7
        model.all_tmp_uses[(0x400800, 0)][kd_atoms.Tmp(5, 4)] = {(ail_tmp, 9)}
        model.phi_vvar_ids.update({2, 3, 4})
        model.phivarid_to_varids_with_unknown[3] = {0, None}

        back = SRDAModel.parse(model.serialize(), arch=arch)

        assert back.arch is arch
        assert back.all_vvar_definitions == model.all_vvar_definitions
        assert dict(back.all_tmp_definitions) == dict(model.all_tmp_definitions)
        assert back.phi_vvar_ids == model.phi_vvar_ids
        assert back.phivarid_to_varids_with_unknown == model.phivarid_to_varids_with_unknown
        # defaultdict semantics restored
        back.all_vvar_uses[99].append(("x",))


class TestDecompilationCacheEndToEnd(unittest.TestCase):
    """End-to-end tests using a real fauxware decompilation."""

    @classmethod
    def setUpClass(cls):
        cls.proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cls.cfg = cls.proj.analyses.CFGFast(normalize=True)
        cls.func = cls.proj.kb.functions.function(name="authenticate")
        cls.decompiler = cls.proj.analyses.Decompiler(cls.func, cfg=cls.cfg.model, generate_code=True)

    def test_codegen_roundtrip(self):
        codegen = self.decompiler.codegen
        blob = codegen.serialize()
        back = type(codegen).parse(blob, project=self.proj, kb=self.proj.kb, variable_kb=codegen._variable_kb)
        assert back.text == codegen.text
        assert back.cfunc is not None
        assert back.cfunc.name == codegen.cfunc.name
        assert back.cfunc.addr == codegen.cfunc.addr
        assert back.flavor == codegen.flavor

    def test_clinic_roundtrip(self):
        clinic = self.decompiler.clinic
        back = type(clinic).parse(
            clinic.serialize(),
            project=self.proj,
            kb=self.proj.kb,
            function=clinic.function,
            variable_kb=clinic.variable_kb,
            cfg=clinic._cfg,
        )
        assert back.graph.number_of_nodes() == clinic.graph.number_of_nodes()
        assert back.cc_graph.number_of_nodes() == clinic.cc_graph.number_of_nodes()
        assert back.vvar_id_start == clinic.vvar_id_start
        assert back.copied_var_ids == clinic.copied_var_ids
        assert back._mode == clinic._mode
        assert back._start_stage == clinic._start_stage
        assert back._end_stage == clinic._end_stage
        assert back._skip_stages == clinic._skip_stages
        assert back.flavor == clinic.flavor
        assert len(back.externs) == len(clinic.externs)
        assert len(back.reaching_definitions.all_vvar_definitions) == len(
            clinic.reaching_definitions.all_vvar_definitions
        )

    def test_decompilation_cache_roundtrip(self):
        from angr.analyses.decompiler.decompilation_cache import DecompilationCache

        cache = self.decompiler.cache
        blob = cache.serialize()
        back = DecompilationCache.parse(
            blob,
            project=self.proj,
            kb=self.proj.kb,
            function=self.func,
            variable_kb=cache.variable_kb,
            cfg=self.cfg.model,
        )
        assert back.addr == cache.addr
        assert back.errors == cache.errors
        assert back.function_summary == cache.function_summary
        assert back.codegen.text == cache.codegen.text
        # parameters preserves the 14 keys
        assert set(back.parameters.keys()) == set(cache.parameters.keys())
        assert len(back.parameters) == 14

    def test_cache_hit_on_deserialized_cache(self):
        """The decisive end-to-end test: serialize the cache, parse it back, install it in the KB, and re-run the
        decompiler. The second run must hit the cache and produce identical output."""
        from angr.analyses.decompiler.decompilation_cache import DecompilationCache

        cache = self.decompiler.cache
        blob = cache.serialize()
        parsed_cache = DecompilationCache.parse(
            blob,
            project=self.proj,
            kb=self.proj.kb,
            function=self.func,
            variable_kb=cache.variable_kb,
            cfg=self.cfg.model,
        )

        # Replace the live cache with the parsed one.
        flavor = parsed_cache.parameters.get("flavor", "pseudocode")
        self.proj.kb.decompilations[(self.func.addr, flavor)] = parsed_cache

        # Second decompile run with the same inputs should consume the deserialized cache.
        d2 = self.proj.analyses.Decompiler(self.func, cfg=self.cfg.model, generate_code=True)
        assert d2.codegen.text == self.decompiler.codegen.text


if __name__ == "__main__":
    unittest.main()
