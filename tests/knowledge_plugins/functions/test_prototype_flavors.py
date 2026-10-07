#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.functions"  # pylint:disable=redefined-builtin

import os
import pickle
import unittest

import angr
from angr.knowledge_plugins.functions import DEFAULT_FLAVOR, Function, PrototypeSource
from angr.sim_type import SimStruct, SimTypeFunction, SimTypeInt, SimTypePointer, SimTypeRef
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestPrototypeFlavors(unittest.TestCase):
    """Function.prototypes keeps one prototype (and source) per decompilation flavor."""

    @classmethod
    def setUpClass(cls):
        cls.proj = angr.Project(os.path.join(test_location, "x86_64", "all"), auto_load_libs=False)

    def _func(self) -> Function:
        return Function(self.proj.kb.functions, 0x100000, name="foo", syscall=False, is_simprocedure=False)

    def _c_proto(self) -> SimTypeFunction:
        return SimTypeFunction([SimTypeInt()], SimTypeInt()).with_arch(self.proj.arch)

    def _rust_proto(self) -> SimTypeFunction:
        return SimTypeFunction([SimTypeInt(), SimTypeInt()], None).with_arch(self.proj.arch)

    def test_property_aliases_default_flavor_and_fallback(self):
        assert DEFAULT_FLAVOR == "pseudocode"
        func = self._func()
        assert func.prototype is None
        assert func.prototypes == {"pseudocode": None}
        assert func.get_prototype(None) is None
        assert func.get_prototype("rust") is None
        assert func.get_prototype_source("rust") == PrototypeSource.NONE

        func.prototype = self._c_proto()
        func.prototype_source = PrototypeSource.SIGNATURES
        assert func.prototypes["pseudocode"] is func.prototype
        assert func.get_prototype(None) is func.prototype
        assert func.get_prototype("pseudocode") is func.prototype
        # a flavor without an entry falls back to the C prototype and its source
        assert not func.has_prototype_for_flavor("rust")
        assert func.get_prototype("rust") is func.prototype
        assert func.get_prototype_source("rust") == PrototypeSource.SIGNATURES
        assert func.is_prototype_groundtruth_for("rust")

    def test_set_prototype_isolates_flavors(self):
        func = self._func()
        func.prototype = self._c_proto()
        func.prototype_source = PrototypeSource.CCA_LOW
        func.set_prototype("rust", self._rust_proto(), source=PrototypeSource.SIGNATURES)

        assert func.has_prototype_for_flavor("rust")
        rust_proto = func.get_prototype("rust")
        assert rust_proto is not None and rust_proto.returnty is None
        assert func.get_prototype_source("rust") == PrototypeSource.SIGNATURES
        assert func.is_prototype_groundtruth_for("rust")
        # the default entry is untouched: "pseudocode" never falls back to another flavor
        assert func.prototype is not None and isinstance(func.prototype.returnty, SimTypeInt)
        assert func.prototype_source == PrototypeSource.CCA_LOW
        assert not func.is_prototype_groundtruth
        assert set(func.prototypes) == {"pseudocode", "rust"}
        assert func.prototype_sources == {"pseudocode": PrototypeSource.CCA_LOW, "rust": PrototypeSource.SIGNATURES}
        # argument names are filled in per flavor
        assert rust_proto.arg_names == ("a0", "a1")

        # a flavor's first entry inherits the source it used to fall back to
        func.set_prototype("go", self._rust_proto())
        assert func.get_prototype_source("go") == PrototypeSource.CCA_LOW
        func.set_prototype_source("go", PrototypeSource.USER)
        assert func.get_prototype_source("go") == PrototypeSource.USER
        assert func.prototype_source == PrototypeSource.CCA_LOW

        # clearing a flavor restores the fallback; clearing C sets it to None
        func.clear_prototype("rust")
        assert not func.has_prototype_for_flavor("rust")
        assert func.get_prototype("rust") is func.prototype
        func.clear_prototype("pseudocode")
        assert func.prototype is None and func.prototype_source == PrototypeSource.NONE
        assert func.get_prototype("rust") is None

    def test_copy_pickle_and_cmessage_round_trip(self):
        func = self._func()
        func.prototype = self._c_proto()
        func.prototype_source = PrototypeSource.SIGNATURES
        func.set_prototype("rust", self._rust_proto(), source=PrototypeSource.CCA_DECOMPILER)

        for other in (
            func.copy(),
            pickle.loads(pickle.dumps(func)),
            Function.parse_from_cmessage(
                func.serialize_to_cmessage(), function_manager=self.proj.kb.functions, project=self.proj
            ),
        ):
            assert set(other.prototypes) == {"pseudocode", "rust"}
            assert other.prototype_sources == func.prototype_sources
            assert str(other.prototype) == str(func.prototype)
            assert str(other.get_prototype("rust")) == str(func.get_prototype("rust"))

    def test_old_cmessage_loads_as_default_flavor_prototype(self):
        func = self._func()
        func.prototype = self._c_proto()
        func.prototype_source = PrototypeSource.USER
        func.set_prototype("rust", self._rust_proto(), source=PrototypeSource.CCA_DECOMPILER)
        cmsg = func.serialize_to_cmessage()
        assert len(cmsg.flavored_prototypes) == 1
        # data written before prototypes became per flavor carries only the single prototype
        cmsg.ClearField("flavored_prototypes")
        loaded = Function.parse_from_cmessage(cmsg, function_manager=self.proj.kb.functions, project=self.proj)
        assert loaded.prototypes.keys() == {"pseudocode"}
        assert str(loaded.prototype) == str(func.prototype)
        assert loaded.prototype_source == PrototypeSource.USER
        assert loaded.get_prototype("rust") is loaded.prototype

    def test_lazy_typeref_resolution_per_flavor(self):
        func = self._func()
        unresolved = SimTypeFunction([SimTypePointer(SimTypeRef("no_such_struct", SimStruct))], SimTypeInt()).with_arch(
            self.proj.arch
        )
        func.set_prototype("rust", unresolved, source=PrototypeSource.SIGNATURES)
        # unresolvable references are kept, and every read re-resolves without touching the C entry
        rust_proto = func.get_prototype("rust")
        assert rust_proto is not None
        assert isinstance(rust_proto.args[0], SimTypePointer)
        assert isinstance(rust_proto.args[0].pts_to, SimTypeRef)
        assert func.prototype is None


if __name__ == "__main__":
    unittest.main()
