#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import copy
import pickle
import unittest

from angr.ailment import Block
from angr.ailment.expression import BinaryOp, Const, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, Return
from angr.analyses.s_reaching_definitions.s_rda_model import SRDAModel, populate_model
from angr.code_location import AILCodeLocation
from angr.utils.ssa import get_vvar_deflocs, get_vvar_uselocs


class TestSRDAModelVVarDefs(unittest.TestCase):
    @staticmethod
    def _model() -> SRDAModel:
        return SRDAModel(None, None, None)

    def test_single_def_is_stored_as_int(self):
        model = self._model()
        loc = AILCodeLocation(0x400000, 0, 3)
        model.add_vvar_def(1, loc)
        assert model.all_vvar_definitions == {1: loc}
        assert model.vvar_defs_by_loc == {loc: 1}

    def test_multiple_defs_at_one_location(self):
        model = self._model()
        loc = AILCodeLocation(0x400000, 0, 3)
        model.add_vvar_def(1, loc)
        model.add_vvar_def(2, loc)
        model.add_vvar_def(2, loc)  # re-adding an existing def changes nothing
        assert model.vvar_defs_by_loc == {loc: {1, 2}}

        # removals collapse the set back to an int and finally drop the key
        model.remove_vvar_def(1)
        assert model.vvar_defs_by_loc == {loc: 2}
        model.remove_vvar_def(2)
        assert model.vvar_defs_by_loc == {}
        assert model.all_vvar_definitions == {}

    def test_moving_a_def_unlinks_the_old_location(self):
        model = self._model()
        loc0 = AILCodeLocation(0x400000, 0, 3)
        loc1 = AILCodeLocation(0x400000, 0, 7)
        model.add_vvar_def(1, loc0)
        model.add_vvar_def(2, loc0)
        model.add_vvar_def(2, loc1)
        assert model.all_vvar_definitions == {1: loc0, 2: loc1}
        assert model.vvar_defs_by_loc == {loc0: 1, loc1: 2}

    def test_removing_an_unknown_def_is_a_noop(self):
        model = self._model()
        model.remove_vvar_def(42)
        assert model.vvar_defs_by_loc == {}

    def test_get_defs_by_location(self):
        model = self._model()
        loc = AILCodeLocation(0x400000, 0, 3)
        model.varid_to_vvar = {
            vid: VirtualVariable(None, vid, 64, category=VirtualVariableCategory.REGISTER, oident=16) for vid in (1, 2)
        }
        model.add_vvar_def(1, loc)
        assert {d.atom.varid for d in model.get_defs_by_location(loc)} == {1}
        model.add_vvar_def(2, loc)
        assert {d.atom.varid for d in model.get_defs_by_location(loc)} == {1, 2}
        assert model.get_defs_by_location(AILCodeLocation(0x400000, 0, 9)) == set()


def _vv(idx: int, varid: int) -> VirtualVariable:
    return VirtualVariable(idx, varid, 64, VirtualVariableCategory.REGISTER, oident=8 * varid)


class TestAILCodeLocation(unittest.TestCase):
    def test_compares_and_hashes_without_the_instruction_address(self):
        a, b = AILCodeLocation(0x1000, 0, 2, 0x1004), AILCodeLocation(0x1000, 0, 2)
        assert a == b
        assert hash(a) == hash(b)
        assert a != AILCodeLocation(0x1000, 0, 3)
        assert a != (0x1000, 0, 2)
        assert {a: 1}[b] == 1
        assert a < AILCodeLocation(0x1000, 0, 3)

    def test_copies_and_pickles(self):
        a = AILCodeLocation(0x1000, 1, 2, 0x1004)
        for other in (copy.copy(a), pickle.loads(pickle.dumps(a))):
            assert other == a
            assert other.insn_addr == 0x1004
        assert AILCodeLocation.make_extern(5).is_extern is True


class TestPopulateModel(unittest.TestCase):
    @staticmethod
    def _blocks() -> dict:
        b0 = Block(
            0x1000,
            8,
            statements=[
                Assignment(1, _vv(10, 1), Const(11, 5, 64), ins_addr=0x1000),
                Assignment(2, _vv(12, 2), BinaryOp(13, "Add", [_vv(14, 1), _vv(15, 7)], False), ins_addr=0x1004),
            ],
        )
        b1 = Block(
            0x1010,
            8,
            statements=[
                Assignment(3, _vv(16, 3), BinaryOp(17, "Add", [_vv(18, 2), _vv(19, 1)], False), ins_addr=0x1010),
                Return(4, [_vv(20, 3), _vv(21, 8)], ins_addr=0x1014),
            ],
        )
        return {(b.addr, b.idx): b for b in (b0, b1)}

    def test_matches_adding_every_definition_and_use(self):
        blocks = self._blocks()
        arg = VirtualVariable(
            30, 7, 64, VirtualVariableCategory.PARAMETER, oident=(VirtualVariableCategory.REGISTER, 56)
        )
        late = [(2, AILCodeLocation(0x1010, 0, 1, 0x1014)), (1, AILCodeLocation(0x1000, 0, 1, 0x1004))]

        model = SRDAModel(None, None, None)
        populate_model(model, blocks, {arg})
        for vvar_id, loc in late:
            model.add_vvar_use(vvar_id, None, loc)

        expected = SRDAModel(None, None, None)
        deflocs = get_vvar_deflocs(blocks.values())
        uselocs = get_vvar_uselocs(blocks.values())
        deflocs[7] = arg, AILCodeLocation.make_extern(7)
        deflocs[8] = uselocs[8][0][0], AILCodeLocation.make_extern(8)
        for vvar_id, (vvar, loc) in deflocs.items():
            expected.varid_to_vvar[vvar_id] = vvar
            expected.add_vvar_def(vvar_id, loc)
            for use in uselocs.get(vvar_id, []):
                expected.add_vvar_use(vvar_id, *use)
        for vvar_id, loc in late:
            expected.add_vvar_use(vvar_id, None, loc)

        assert model.varid_to_vvar == expected.varid_to_vvar
        assert list(model.all_vvar_definitions.items()) == list(expected.all_vvar_definitions.items())
        assert list(model.all_vvar_uses.items()) == list(expected.all_vvar_uses.items())
        assert list(model.vvar_uses_by_loc.items()) == list(expected.vvar_uses_by_loc.items())
        assert model.vvar_defs_by_loc == expected.vvar_defs_by_loc
        assert model.varid_to_vvar[7] is arg

    def test_indexes_follow_edits_after_they_are_built(self):
        model = SRDAModel(None, None, None)
        populate_model(model, self._blocks(), None)
        loc = AILCodeLocation(0x1010, 0, 1, 0x1014)
        assert model.vvar_uses_by_loc[loc] == [3, 8]
        model.add_vvar_use(1, None, loc)
        assert model.vvar_uses_by_loc[loc] == [3, 8, 1]
        model.remove_vvar_def(3)
        assert AILCodeLocation(0x1010, 0, 0) not in model.vvar_defs_by_loc


if __name__ == "__main__":
    unittest.main()
