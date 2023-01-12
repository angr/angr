import logging
import unittest
import os
from itertools import count

import archinfo
import angr

import ailment


def block_simplify(block):
    p = angr.Project(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "binaries", "tests", "x86_64", "fauxware"),
        auto_load_libs=False,
    )
    bsimp = p.analyses.AILBlockSimplifier(block, 0x1337)
    return bsimp.result_block


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestBlockSimplifier(unittest.TestCase):
    def test_simplify_pointless_assign(self):
        arch = archinfo.arch_from_id("AMD64")
        block = ailment.Block(0x1337, 10)
        block.statements.append(
            ailment.Assignment(
                0,
                ailment.Register(1, None, arch.registers["rax"][0], 64),
                ailment.Register(2, None, arch.registers["rax"][0], 64),
                ins_addr=0x1337,
            )
        )
        block.statements.append(
            ailment.Assignment(
                3,
                ailment.Register(4, None, arch.registers["rbx"][0], 64),
                ailment.Register(5, None, arch.registers["rcx"][0], 64),
                ins_addr=0x1338,
            )
        )

        b = block_simplify(block)
        assert len(b.statements) == 1
        assert b.statements[0].idx == 3

    def test_simplify_dead_assign_0(self):
        block = ailment.Block(0x1337, 10)
        n = count()
        important = 0x999
        block.statements.extend(
            [
                ailment.Assignment(
                    next(n),
                    ailment.Register(next(n), None, 1, 64),
                    ailment.Const(next(n), None, 100, 64),
                    ins_addr=0x1337,
                ),
                ailment.Assignment(
                    important,
                    ailment.Register(next(n), None, 1, 64),
                    ailment.Const(next(n), None, 101, 64),
                    ins_addr=0x1338,
                ),
                ailment.Stmt.Jump(next(n), ailment.Expr.Const(None, None, 0x3333, 64), ins_addr=0x1338),
            ]
        )

        b = block_simplify(block)
        assert len(b.statements) == 2
        assert b.statements[0].idx == important

    def test_simplify_dead_assign_1(self):
        # if a register is used ever, it should not be simplified away
        arch = archinfo.arch_from_id("AMD64")
        block = ailment.Block(0x1337, 10)
        n = count(start=1)
        important = 0x999
        block.statements.extend(
            [
                ailment.Assignment(
                    next(n),
                    ailment.Register(next(n), None, arch.registers["rdi"][0], 64),
                    ailment.Const(next(n), None, 0x13371337, 64),
                    ins_addr=0x1337,
                ),  # rdi = 0x13371337
                ailment.Stmt.Call(
                    important,
                    ailment.Const(next(n), None, 0x400080, 64),
                    ins_addr=0x1338,
                ),  # Call(0x400080), which uses rdi but also overwrites rdi (since it is a caller-saved argument)
            ]
        )

        b = block_simplify(block)
        assert len(b.statements) == 2
        assert b.statements[0].idx == 1
        assert b.statements[1].idx == important


if __name__ == "__main__":
    logging.getLogger("angr.analyses.decompiler.block_simplifier").setLevel(logging.DEBUG)
    unittest.main()
