#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import unittest

from angr.ailment.expression import VirtualVariable, VirtualVariableCategory
from angr.analyses.s_reaching_definitions.s_rda_model import SRDAModel
from angr.code_location import AILCodeLocation


class TestSRDAModelVVarDefs(unittest.TestCase):
    @staticmethod
    def _model() -> SRDAModel:
        return SRDAModel(None, None, None)

    def test_single_def_is_stored_as_int(self):
        model = self._model()
        loc = AILCodeLocation(0x400000, None, 3)
        model.add_vvar_def(1, loc)
        assert model.all_vvar_definitions == {1: loc}
        assert model.vvar_defs_by_loc == {loc: 1}

    def test_multiple_defs_at_one_location(self):
        model = self._model()
        loc = AILCodeLocation(0x400000, None, 3)
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
        loc0 = AILCodeLocation(0x400000, None, 3)
        loc1 = AILCodeLocation(0x400000, None, 7)
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
        loc = AILCodeLocation(0x400000, None, 3)
        model.varid_to_vvar = {
            vid: VirtualVariable(None, vid, 64, category=VirtualVariableCategory.REGISTER, oident=16) for vid in (1, 2)
        }
        model.add_vvar_def(1, loc)
        assert {d.atom.varid for d in model.get_defs_by_location(loc)} == {1}
        model.add_vvar_def(2, loc)
        assert {d.atom.varid for d in model.get_defs_by_location(loc)} == {1, 2}
        assert model.get_defs_by_location(AILCodeLocation(0x400000, None, 9)) == set()


if __name__ == "__main__":
    unittest.main()
