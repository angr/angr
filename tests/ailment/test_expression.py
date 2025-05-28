# pylint: disable=missing-class-docstring,no-self-use
import unittest

import ailment


class TestExpression(unittest.TestCase):

    def test_phi_hashing(self):
        vvar_0 = ailment.expression.VirtualVariable(100, 0, 32, ailment.expression.VirtualVariableCategory.REGISTER, 16)
        vvar_1 = ailment.expression.VirtualVariable(101, 1, 32, ailment.expression.VirtualVariableCategory.REGISTER, 16)
        vvar_2 = ailment.expression.VirtualVariable(102, 2, 32, ailment.expression.VirtualVariableCategory.REGISTER, 16)
        phi_expr = ailment.expression.Phi(
            0, 32, [((0, None), vvar_0), ((0, 0), vvar_2), ((1, None), vvar_1), ((4, None), None)]
        )
        h = hash(phi_expr)  # should not crash
        assert h is not None


if __name__ == "__main__":
    unittest.main()
