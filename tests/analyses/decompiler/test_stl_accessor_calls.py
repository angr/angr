from __future__ import annotations

# pylint: disable=missing-class-docstring,no-self-use
import os.path
import re
import unittest
from collections import OrderedDict
from unittest import TestCase

import archinfo

import angr
from angr.analyses.decompiler.decompilation_options import options as dec_options
from angr.analyses.decompiler.decompiler import Decompiler
from angr.analyses.decompiler.stl_field_accessors import STD_BASIC_STRING, stl_accessor_name
from angr.analyses.decompiler.structured_codegen.c import CVariableField
from angr.analyses.decompiler.structured_codegen.c_serialize import parse_codegen, serialize_codegen
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.procedures.definitions import SIM_TYPE_COLLECTIONS
from angr.sim_type import (
    SimCppClass,
    SimStruct,
    SimTypeChar,
    SimTypeFunction,
    SimTypeInt,
    SimTypeLongLong,
    SimTypePointer,
)
from tests.common import bin_location

STL_BIN = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_stl")
STL2_BIN = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_stl2")

STD_VECTOR_INT = "class std::vector<int, class std::allocator<int>>"

# a call to one of the named STL accessors
_ACCESSOR_CALL = r"std::(?:string|vector<[^()]*?>)::(?:c_str|length|data|end)\("
# ... used as the target of an assignment
_ACCESSOR_ASSIGNED_TO = re.compile(_ACCESSOR_CALL + r"[^;=]*\)\s*=(?!=)")
# a field of an STL class that stayed a field access
_STL_FIELD_ASSIGNED_TO = re.compile(r"->m_(?:data|size|start|finish)\s*=(?!=)")

STL_ACCESSOR_OPTION = next(o for o in dec_options if o.param == "stl_accessor_calls")


def _decompile_with_prototype(bin_path: str, func_name: str, arg_types, ret_type):
    """
    Decompile ``func_name`` after pinning its prototype as user-provided, so that Clinic feeds the argument types to
    Typehoon as ground truth. This is how a container pointer gets its ``cpp::std`` class type in real binaries too
    -- there it comes from an inlined-accessor KnownPattern that fired somewhere in the same function -- but pinning
    it makes the test independent of which patterns happen to match this fixture.
    """

    proj = angr.Project(bin_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True)
    proj.analyses.CompleteCallingConventions(cfg=cfg.model)
    func = cfg.functions.function(name=func_name)
    assert func is not None
    arch = proj.arch
    func.prototype = SimTypeFunction([t.with_arch(arch) for t in arg_types], ret_type.with_arch(arch)).with_arch(arch)
    func.prototype_source = PrototypeSource.USER
    dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model, preset="full")
    assert dec.codegen is not None and dec.codegen.text is not None
    return dec


def _tagged_accessors(codegen) -> set[str]:
    """The accessor names attached to CVariableField nodes reachable from a codegen's position map."""
    return {
        el.obj.stl_accessor
        for elements in codegen.map_pos_to_node.values()
        for el in (elements if isinstance(elements, (list, set, tuple)) else [elements])
        if isinstance(el.obj, CVariableField) and el.obj.stl_accessor is not None
    }


def _cpp_std(unique_name: str):
    return SIM_TYPE_COLLECTIONS["cpp::std"].get(unique_name)


def _ptr_to(unique_name: str):
    return SimTypePointer(_cpp_std(unique_name).with_arch(archinfo.arch_from_id("AMD64")))


class TestStlAccessorNameTable(TestCase):
    """The field -> accessor lookup itself: it must key off the registered cpp::std classes and nothing else."""

    def test_string_fields(self):
        ty = _cpp_std(STD_BASIC_STRING)
        assert stl_accessor_name(ty, "m_data") == "std::string::c_str"
        assert stl_accessor_name(ty, "m_size") == "std::string::length"
        # _M_allocated_capacity is only the active union member for heap-allocated strings, so a raw read of it is
        # not capacity()
        assert stl_accessor_name(ty, "m_capacity") is None

    def test_vector_fields(self):
        ty = _cpp_std(STD_VECTOR_INT)
        assert stl_accessor_name(ty, "m_start") == "std::vector<int>::data"
        assert stl_accessor_name(ty, "m_finish") == "std::vector<int>::end"
        # capacity() is a subtraction, not a field read
        assert stl_accessor_name(ty, "m_end_of_storage") is None

    def test_lookalike_types_do_not_match(self):
        # a user class with the same field names but a different unique name
        lookalike = SimCppClass(
            unique_name="class my::string",
            name="my::string",
            members=OrderedDict([("m_data", SimTypePointer(SimTypeChar())), ("m_size", SimTypeInt())]),
        )
        assert stl_accessor_name(lookalike, "m_data") is None
        # a plain struct is never an STL container
        plain = SimStruct(OrderedDict([("m_data", SimTypePointer(SimTypeChar()))]), name="thing")
        assert stl_accessor_name(plain, "m_data") is None
        # a field of a registered class that has no accessor
        assert stl_accessor_name(_cpp_std(STD_BASIC_STRING), "m_nonexistent") is None


class TestStlAccessorCalls(TestCase):
    """Reads of STL container fields on an already-typed pointer are displayed as the accessor they implement."""

    def test_string_data_read_becomes_c_str_call(self):
        dec = _decompile_with_prototype(
            STL2_BIN, "str_cstr", [_ptr_to(STD_BASIC_STRING)], SimTypePointer(SimTypeChar())
        )
        text = dec.codegen.text
        assert "std::string::c_str(" in text, text
        assert "->m_data" not in text, text

    def test_string_data_read_under_an_index_becomes_c_str_call(self):
        dec = _decompile_with_prototype(
            STL_BIN, "str_index", [_ptr_to(STD_BASIC_STRING), SimTypeLongLong(signed=False)], SimTypeChar()
        )
        text = dec.codegen.text
        assert re.search(r"std::string::c_str\(\w+\)\[", text) is not None, text
        assert "->m_data" not in text, text

    def test_vector_start_read_becomes_data_call(self):
        dec = _decompile_with_prototype(STL2_BIN, "vec_data", [_ptr_to(STD_VECTOR_INT)], SimTypePointer(SimTypeInt()))
        text = dec.codegen.text
        assert "std::vector<int>::data(" in text, text
        assert "->m_start" not in text, text

    def test_accessor_names_are_not_used_for_writes(self):
        # libstdc++'s _Sp_counted_base::_M_release: with the container type pinned, its reads of the refcount word
        # turn into accessor calls while the decrements written back to the same word must stay field stores --
        # "std::string::length(p) = n" would not even be valid C.
        dec = _decompile_with_prototype(
            STL2_BIN,
            "_ZNSt16_Sp_counted_baseILN9__gnu_cxx12_Lock_policyE2EE10_M_releaseEv",
            [_ptr_to(STD_BASIC_STRING)],
            SimTypeLongLong(),
        )
        text = dec.codegen.text
        # c_str() has no libstdc++ KnownPattern, so this call can only come from the typed-field naming
        assert "std::string::c_str(" in text, text
        assert _ACCESSOR_ASSIGNED_TO.search(text) is None, text
        assert _STL_FIELD_ASSIGNED_TO.search(text) is not None, text

    def test_accessor_name_survives_codegen_serialization(self):
        dec = _decompile_with_prototype(
            STL2_BIN, "str_cstr", [_ptr_to(STD_BASIC_STRING)], SimTypePointer(SimTypeChar())
        )
        assert _tagged_accessors(dec.codegen) == {"std::string::c_str"}

        parsed = parse_codegen(serialize_codegen(dec.codegen), project=dec.project, kb=dec.kb, func=dec.func)
        assert _tagged_accessors(parsed) == {"std::string::c_str"}

    def test_option_toggles_the_display(self):
        dec = _decompile_with_prototype(
            STL2_BIN, "str_cstr", [_ptr_to(STD_BASIC_STRING)], SimTypePointer(SimTypeChar())
        )
        assert "std::string::c_str(" in dec.codegen.text

        dec.codegen.reapply_options([(STL_ACCESSOR_OPTION, False)])
        dec.codegen.regenerate_text()
        assert "std::string::c_str(" not in dec.codegen.text, dec.codegen.text
        assert "->m_data" in dec.codegen.text, dec.codegen.text

        dec.codegen.reapply_options([(STL_ACCESSOR_OPTION, True)])
        dec.codegen.regenerate_text()
        assert "std::string::c_str(" in dec.codegen.text, dec.codegen.text


if __name__ == "__main__":
    unittest.main()
