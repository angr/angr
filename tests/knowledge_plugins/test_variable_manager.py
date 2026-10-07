#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins"  # pylint:disable=redefined-builtin

import os
import pickle
import tempfile
import unittest
from collections import OrderedDict
from unittest import mock

import angr
from angr.ailment.expression import VirtualVariable, VirtualVariableCategory
from angr.angrdb import AngrDB
from angr.calling_conventions import SimCCSystemVAMD64
from angr.code_location import CodeLocation, ExternalCodeLocation
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.knowledge_plugins.variables import variable_manager as variable_manager_mod
from angr.knowledge_plugins.variables.spilling_vardict import SpillingVariableInternalDict
from angr.sim_type import SimStruct, SimTypeFunction, SimTypeInt, SimTypeLongLong
from angr.sim_variable import SimComboRegisterVariable, SimRegisterVariable, SimStackVariable
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestVariableManager(unittest.TestCase):
    def test_variable_manager_internal_pickle(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        vm = p.kb.variables

        # Create a VariableManagerInternal and generate some variable idents
        vmi = vm.get_function_manager(0x400000)
        ident0 = vmi.next_variable_ident("stack")
        ident1 = vmi.next_variable_ident("stack")
        ident2 = vmi.next_variable_ident("register")
        assert ident0 == "is_0"
        assert ident1 == "is_1"
        assert ident2 == "ir_0"

        # Pickle round-trip
        data = pickle.dumps(vmi)
        vmi2 = pickle.loads(data)

        # The counters should continue from where they left off
        ident3 = vmi2.next_variable_ident("stack")
        ident4 = vmi2.next_variable_ident("register")
        assert ident3 == "is_2"
        assert ident4 == "ir_1"

    def test_dec_variables_spill_evict_and_reload(self):
        # kb.dec_variables holds its per-function managers in a SpillingVariableInternalDict. Forcing a tiny cache
        # limit spills the least-recently-used entries to the RuntimeDb LMDB store, and they reload with identical
        # content on access.
        p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = p.analyses.CFGFast(normalize=True)
        for name in ("main", "authenticate"):
            p.analyses.Decompiler(name, cfg=cfg.model)

        dvm = p.kb.dec_variables
        fm = dvm.function_managers
        assert isinstance(fm, SpillingVariableInternalDict)
        assert len(fm) >= 2

        def content(internal):
            return sorted(v.ident for v in internal._variables)

        pre = {addr: content(fm[addr]) for addr in list(fm)}
        assert all(pre.values()), "each decompiled function should have variables"

        # force every entry out of the in-memory cache
        fm._cache_limit = 0
        fm._evict_lru()
        assert not fm._cache and len(fm._spilled) == len(pre)

        # accessing a spilled entry reloads it losslessly (with the manager reattached)
        for addr, expected in pre.items():
            reloaded = fm[addr]
            assert reloaded.manager is dvm
            assert content(reloaded) == expected

    def test_dec_variables_spilling_pickle_roundtrip(self):
        # A knowledge base whose dec_variables have been spilled pickles self-containedly (the non-durable RuntimeDb
        # reference is dropped) and the per-function variables survive the round-trip.
        p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = p.analyses.CFGFast(normalize=True)
        p.analyses.Decompiler("main", cfg=cfg.model)

        dvm = p.kb.dec_variables
        addr = next(iter(dvm.function_managers))
        pre = sorted(v.ident for v in dvm.function_managers[addr]._variables)
        # spill everything before pickling
        dvm.function_managers._cache_limit = 0
        dvm.function_managers._evict_lru()

        kb2 = pickle.loads(pickle.dumps(p.kb))
        dvm2 = kb2.dec_variables
        assert isinstance(dvm2.function_managers, SpillingVariableInternalDict)
        assert list(dvm2.function_managers) == [addr]
        post = sorted(v.ident for v in dvm2.function_managers[addr]._variables)
        assert post == pre

    def test_dec_variables_decompile_under_tiny_spill_limit(self):
        # Decompilation output is byte-identical whether dec_variables spill aggressively (cache limit 1, so every
        # function's manager is evicted as soon as the next function is decompiled) or spilling is disabled.
        binpath = os.path.join(test_location, "x86_64", "fauxware")
        func_names = ("main", "authenticate", "accepted", "rejected")

        p = angr.Project(binpath, auto_load_libs=False)
        cfg = p.analyses.CFGFast(normalize=True)
        fm = p.kb.dec_variables.function_managers
        assert isinstance(fm, SpillingVariableInternalDict)
        fm._cache_limit = 1

        texts = {}
        for name in func_names:
            dec = p.analyses.Decompiler(name, cfg=cfg.model)
            assert dec.codegen is not None and dec.codegen.text is not None
            texts[name] = dec.codegen.text
        assert fm._spilled, "decompiling multiple functions under cache limit 1 must have spilled entries"

        with mock.patch.object(variable_manager_mod, "USE_SPILLING_DVARS", False):
            p2 = angr.Project(binpath, auto_load_libs=False)
            cfg2 = p2.analyses.CFGFast(normalize=True)
            assert type(p2.kb.dec_variables.function_managers) is dict
            for name in func_names:
                dec2 = p2.analyses.Decompiler(name, cfg=cfg2.model)
                assert dec2.codegen is not None and dec2.codegen.text == texts[name]

    def test_same_offset_stack_vvarids(self):
        p = angr.load_shellcode(b"\x90", arch="AMD64")
        vmi = p.kb.variables.get_function_manager(0x400000)

        def record(var, varid: int, category: VirtualVariableCategory, oident):
            atom = VirtualVariable(varid, varid, 64, category, oident=oident)
            vmi.record_variable(CodeLocation(0x400000, varid, ins_addr=0x400000 + varid), var, 0, atom=atom)

        record(SimStackVariable(-8, 8, ident="is_0"), 1, VirtualVariableCategory.STACK, -8)
        record(SimStackVariable(-8, 8, ident="is_1"), 2, VirtualVariableCategory.STACK, -8)
        record(SimStackVariable(-16, 8, ident="is_2"), 3, VirtualVariableCategory.STACK, -16)
        record(SimRegisterVariable(16, 8, ident="ir_0"), 4, VirtualVariableCategory.REGISTER, 16)
        record(SimRegisterVariable(16, 8, ident="ir_1"), 5, VirtualVariableCategory.REGISTER, 16)
        # only stack variables that share an offset are candidates for unification
        assert vmi.same_offset_stack_vvarids() == {1, 2}

        # a phi variable counts as one more variable at its offset
        vmi.make_phi_node(0x400000, SimStackVariable(-16, 8, ident="is_2"), SimStackVariable(-16, 8, ident="is_3"))
        assert vmi.same_offset_stack_vvarids() == {1, 2, 3}

    def test_combo_register_variable_serialization_roundtrip(self):
        # a SimComboRegisterVariable (a value spanning several registers) survives serialize()/parse() as a regular,
        # a phi, and a unified variable, with all of its register offsets
        p = angr.load_shellcode(b"\x90", arch="AMD64")
        vmi = p.kb.dec_variables.get_function_manager(0x400000)

        rdx, rax = p.arch.registers["rdx"][0], p.arch.registers["rax"][0]
        combo = SimComboRegisterVariable((rdx, rax), 16, ident="ir_0", region=0x400000, name="pair")
        reg = SimRegisterVariable(rax, 8, ident="ir_1", region=0x400000)
        vmi.add_variable("register", rax, reg)
        vmi.write_to(combo, 0, CodeLocation(0x400000, 0, ins_addr=0x400000))
        vmi.read_from(combo, 8, CodeLocation(0x400000, 1, ins_addr=0x400004))
        vmi.set_variable_type(combo, SimTypeLongLong().with_arch(p.arch))
        combo_phi = SimComboRegisterVariable((rdx, rax), 16, ident="ir_2", region=0x400000)
        vmi._phi_variables[combo_phi] = {combo}
        vmi._variables_to_phivars[combo].add(combo_phi)
        unified = combo.copy()
        unified.ident = "ir_3"
        vmi.set_unified_variable(combo, unified)
        vmi.set_unified_variable(reg, reg.copy())

        vmi2 = variable_manager_mod.VariableManagerInternal.parse(
            vmi.serialize(), variable_manager=p.kb.dec_variables, func_addr=0x400000
        )
        combo2 = vmi2._ident_to_variable["ir_0"]
        assert isinstance(combo2, SimComboRegisterVariable)
        assert combo2 == combo and combo2.reg_offsets == (rdx, rax) and combo2.size == 16 and combo2.name == "pair"
        assert {v.ident for v in vmi2._variables} == {"ir_0", "ir_1"}
        assert vmi2._phi_variables == {combo_phi: {combo}}
        assert all(isinstance(v, SimComboRegisterVariable) for v in vmi2._phi_variables)
        assert vmi2._variables_to_phivars[combo] == {combo_phi}
        assert {(a.access_type, a.offset) for a in vmi2.get_variable_accesses(combo2)} == {(0, 0), (1, 8)}
        unified2 = vmi2.unified_variable(combo2)
        assert isinstance(unified2, SimComboRegisterVariable) and unified2 == unified
        assert unified2.reg_offsets == (rdx, rax)
        assert isinstance(vmi2.get_variable_type(combo2), SimTypeLongLong)

    def test_dec_variables_spill_combo_register_variable(self):
        # a by-value 16-byte struct argument lands in two registers and becomes a combo-register variable; evicting
        # that function's manager under a tiny cache limit serializes it, and it reloads intact
        p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = p.analyses.CFGFast(normalize=True)
        fm = p.kb.dec_variables.function_managers
        assert isinstance(fm, SpillingVariableInternalDict)
        fm._cache_limit = 1

        func = cfg.functions["authenticate"]
        pair = SimStruct(OrderedDict(a=SimTypeLongLong(), b=SimTypeLongLong()), name="pair_t", pack=False)
        func.prototype = SimTypeFunction([pair], SimTypeInt(signed=True), arg_names=["p"]).with_arch(p.arch)
        func.calling_convention = SimCCSystemVAMD64(p.arch)
        func.prototype_source = PrototypeSource.USER

        dec = p.analyses.Decompiler(func, cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None and "pair_t p" in dec.codegen.text
        combos = [v for v in fm[func.addr]._variables if isinstance(v, SimComboRegisterVariable)]
        assert combos

        # decompiling another function evicts (serializes) authenticate's manager
        p.analyses.Decompiler("main", cfg=cfg.model, fail_fast=True)
        assert func.addr in fm._spilled
        reloaded = fm[func.addr]
        assert sorted(v.key for v in reloaded._variables if isinstance(v, SimComboRegisterVariable)) == sorted(
            v.key for v in combos
        )

    def test_phi_argument_variable_angrdb_roundtrip_and_supersede(self):
        # An argument whose vvar is defined by a phi statement is registered as its own phi variable (engine_ail), so
        # it sits in both _variables and _phi_variables. It must come back from an angrdb as one object, and a
        # replacement argument (e.g. narrower after the prototype changed) must supersede the phi entry too;
        # otherwise the stale argument is unified a second time and assign_unified_variable_names() runs out of names.
        p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        func_addr = 0x400000

        def make_manager(manager: variable_manager_mod.VariableManager) -> variable_manager_mod.VariableManagerInternal:
            vmi = manager.get_function_manager(func_addr)
            arg = SimRegisterVariable(32, 8, ident="arg_1", name="a1", region=func_addr)
            atom = VirtualVariable(1, 1, 64, VirtualVariableCategory.REGISTER, oident=32)
            vmi.record_variable(CodeLocation(func_addr, 0, ins_addr=func_addr), arg, 0, atom=atom)
            vmi._phi_variables[arg] = {arg}
            vmi._variables_to_phivars[arg].add(arg)
            vmi.unify_variables()
            return vmi

        def check_supersede(vmi: variable_manager_mod.VariableManagerInternal) -> None:
            new_arg = SimRegisterVariable(32, 4, ident="arg_1", name="a1", region=func_addr)
            vmi.record_variable(ExternalCodeLocation(), new_arg, 0)
            assert new_arg not in vmi._phi_variables
            vmi.unify_variables()
            unified = [v for v in vmi._unified_variables if v.ident == "arg_1"]
            assert len(unified) == 1
            assert unified[0].size == 4
            vmi.assign_unified_variable_names(arg_names=["a1"])
            assert unified[0].name == "a1"

        vmi = make_manager(p.kb.dec_variables)
        with tempfile.TemporaryDirectory() as td:
            db_file = os.path.join(td, "proj.adb")
            AngrDB(p).dump(db_file)
            p2 = AngrDB().load(db_file)
        vmi2 = p2.kb.dec_variables[func_addr]
        phi = next(iter(vmi2._phi_variables))
        assert phi is vmi2._ident_to_variable["arg_1"]
        assert phi in vmi2._variables
        assert vmi2._phi_variables[phi] == {phi}
        assert next(iter(vmi2._variables_to_unified_variables)) is phi

        check_supersede(vmi)
        check_supersede(vmi2)


if __name__ == "__main__":
    unittest.main()
