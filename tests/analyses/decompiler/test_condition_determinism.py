# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

import subprocess
import sys
import unittest
from unittest import TestCase

from angr import claripy
from angr.analyses.decompiler.condition_processor import ConditionProcessor

# builds one condition through ConditionProcessor and prints everything that must not vary between processes
_PROBE = """
import archinfo
from angr import ailment, claripy
from angr.ailment.expression import BinaryOp, Call, Const, Convert, VirtualVariable, VirtualVariableCategory
from angr.analyses.decompiler.condition_processor import ConditionProcessor

arch = archinfo.ArchAMD64()
cp = ConditionProcessor(arch, ailment.Manager())
vvar = VirtualVariable(1, 315, 64, VirtualVariableCategory.REGISTER, oident=56)
call = Call(2, Const(3, 0x401000, 64), args=[vvar], bits=64, ins_addr=0x404309)
cond = BinaryOp(4, "CmpEQ", [Convert(5, 64, 32, False, call), Const(6, 0, 32)], False, bits=1)
ast = cp.claripy_ast_from_ail_condition(cond)
terms = [claripy.BoolS(f"ailexpr_t{i}", explicit_name=True) for i in range(6)]
print(ast)
print(ast.hash())
print(ConditionProcessor.simplify_condition(claripy.Or(*terms)))
"""


class TestConditionDeterminism(TestCase):
    def test_simplify_condition_preserves_operand_order(self):
        # sympy orders And/Or operands by symbol name, so the names handed to it decide the order of the operands
        # that come back. they must follow the input, not the hash of the leaves.
        terms = [claripy.BoolS(f"ailexpr_t{i}", explicit_name=True) for i in range(6)]
        for op in (claripy.Or, claripy.And):
            simplified = ConditionProcessor.simplify_condition(op(*terms))
            assert simplified.op == op(*terms).op
            assert list(simplified.args) == terms

    def test_condition_names_do_not_depend_on_the_process(self):
        args = [sys.executable, "-c", _PROBE]
        with (
            subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as p0,
            subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as p1,
        ):
            outputs = [p.communicate(timeout=120) for p in (p0, p1)]
        for out, err in outputs:
            assert out.strip(), err
        assert outputs[0][0] == outputs[1][0], f"process-dependent output:\n{outputs[0][0]}---\n{outputs[1][0]}"


if __name__ == "__main__":
    unittest.main()
