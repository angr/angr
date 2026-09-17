# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

import unittest

import pytest

from angr import claripy
from angr.ailment import utils
from angr.ailment.expression import VirtualVariable, VirtualVariableCategory


class TestGetBits(unittest.TestCase):
    """
    get_bits dispatches on an AIL expression or a claripy AST. The AST layer is angr's vendored
    clarirs, so utils.Bits must be angr.claripy.Bits: no clarirs node derives from the legacy
    top-level claripy class, and typing.Never cannot be used with isinstance.

    The claripy calls below are marked for pyright because GetBitsTypeParams names only Expression,
    although the body handles Bits too.
    """

    def test_bits_is_the_vendored_claripy_class(self):
        assert utils.Bits is claripy.Bits

    def test_get_bits_of_claripy_ast(self):
        assert utils.get_bits(claripy.BVS("x", 32)) == 32  # pyright: ignore[reportArgumentType]
        assert utils.get_bits(claripy.BVV(1, 64)) == 64  # pyright: ignore[reportArgumentType]
        assert utils.get_bits(claripy.FPS("f", claripy.FSORT_DOUBLE)) == 64  # pyright: ignore[reportArgumentType]

    def test_get_bits_of_ail_expression(self):
        vvar = VirtualVariable(100, 0, 32, VirtualVariableCategory.REGISTER, 16)
        assert utils.get_bits(vvar) == 32

    def test_get_bits_rejects_other_values(self):
        # get_bits reports the rejected type itself; an isinstance() that cannot run does not.
        with pytest.raises(TypeError) as excinfo:
            utils.get_bits(32)  # pyright: ignore[reportArgumentType]
        assert excinfo.value.args == (int,)


if __name__ == "__main__":
    unittest.main()
