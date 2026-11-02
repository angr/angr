#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.key_definitions"  # pylint:disable=redefined-builtin

import pickle
from unittest import TestCase, main

import archinfo

from angr import claripy
from angr.claripy.annotation import UninitializedAnnotation
from angr.code_location import CodeLocation, ExternalCodeLocation
from angr.engines.light import SpOffset
from angr.knowledge_plugins.key_definitions import atoms
from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.knowledge_plugins.key_definitions.live_definitions import DefinitionAnnotation, LiveDefinitions
from angr.knowledge_plugins.key_definitions.tag import ParameterTag


def _slots(o):
    # tags have identity equality; pickling copies them
    return {
        k: sorted(map(repr, v)) if k == "tags" else v
        for k, v in ((k, getattr(o, k, "<unset>")) for k in _slot_names(o))
    }


def _slot_names(o):
    return {
        k for klass in type(o).__mro__ for k in getattr(klass, "__slots__", ()) if k not in ("_hash", "__weakref__")
    }


def _old_annotate_with_def(symvar, definition):
    to_remove = [a for a in symvar.annotations if isinstance(a, DefinitionAnnotation)]
    return symvar.annotate(DefinitionAnnotation(definition), remove_annotations=to_remove)


class TestDefinitionAnnotation(TestCase):
    def _definitions(self):
        return [
            Definition(atoms.Register(16, 8), CodeLocation(0x401000, 5, ins_addr=0x401003)),
            Definition(atoms.Tmp(3, 8), CodeLocation(0x401000, 7, ins_addr=0x401005, context=(1, 2))),
            Definition(atoms.MemoryLocation(SpOffset(64, -8), 8, archinfo.Endness.LE), CodeLocation(0x10, 1)),
            Definition(atoms.MemoryLocation(0x601000, 4), ExternalCodeLocation(), dummy=True),
            Definition(atoms.Register(24, 4), CodeLocation(0x20, 0, info={"x": 1}), tags={ParameterTag(function=1)}),
            Definition(atoms.GuardUse(0x30), CodeLocation(0x30, 2)),
        ]

    def test_pickle_rebuilds_equal_objects(self):
        for d in self._definitions():
            anno = DefinitionAnnotation(d)
            copy = pickle.loads(pickle.dumps(anno))
            assert type(copy) is DefinitionAnnotation
            assert copy._hash == anno._hash and copy == anno and hash(copy) == hash(anno)
            for o1, o2 in (
                (anno.definition, copy.definition),
                (anno.definition.atom, copy.definition.atom),
                (anno.definition.codeloc, copy.definition.codeloc),
            ):
                assert type(o1) is type(o2)
                assert _slots(o1) == _slots(o2)
                assert o2._hash is None
                assert o1 is not o2
            assert copy.definition.tags is not anno.definition.tags

    def test_annotate_with_def_matches_remove_and_annotate(self):
        defs = self._definitions()
        values = [claripy.BVV(5, 64), claripy.BVS("x", 64)]
        values.append(LiveDefinitions.annotate_with_def(values[1], defs[0]))
        values.append(values[1].annotate(UninitializedAnnotation()))
        values.append(LiveDefinitions.annotate_with_def(values[3], defs[1]))
        for v in values:
            for d in defs:
                new = LiveDefinitions.annotate_with_def(v, d)
                old = _old_annotate_with_def(v, d)
                assert new.hash() == old.hash()
                assert [type(a) for a in new.annotations] == [type(a) for a in old.annotations]
                assert list(LiveDefinitions.extract_defs(new)) == [d]


if __name__ == "__main__":
    main()
