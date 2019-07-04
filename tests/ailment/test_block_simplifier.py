
import logging
import os
import nose
from itertools import count

import archinfo
import angr

import ailment
import ailment.analyses

def block_simplify(block):
    p = angr.Project(os.path.join(os.path.dirname(os.path.abspath(__file__)),
        '..', '..', 'binaries', 'tests', 'x86_64', 'fauxware'), auto_load_libs=False)
    bsimp = p.analyses.AILBlockSimplifier(block)
    return bsimp.result_block

def test_simplify_pointless_assign():
    arch = archinfo.arch_from_id('AMD64')
    block = ailment.Block(0x1337, 10)
    block.statements.append(
        ailment.Assignment(
            0,
            ailment.Register(1, None, arch.registers['rax'][0], 64),
            ailment.Register(2, None, arch.registers['rax'][0], 64),
            ins_addr=0x1337,
        )
    )
    block.statements.append(
        ailment.Assignment(
            3,
            ailment.Register(4, None, arch.registers['rbx'][0], 64),
            ailment.Register(5, None, arch.registers['rcx'][0], 64),
            ins_addr=0x1338,
        )
    )


    b = block_simplify(block)
    nose.tools.assert_equal(len(b.statements), 1)
    nose.tools.assert_equal(b.statements[0].idx, 3)

def test_simplify_dead_assign():
    arch = archinfo.arch_from_id('AMD64')
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
            ailment.Stmt.Jump(
                next(n),
                0x3333,
                ins_addr=0x1338
            ),
        ]
    )

    b = block_simplify(block)
    nose.tools.assert_equal(len(b.statements), 2)
    nose.tools.assert_equal(b.statements[0].idx, important)


if __name__ == '__main__':
    logging.getLogger('ailment.analyses.block_simplifier').setLevel(logging.DEBUG)
    test_simplify_pointless_assign()
    test_simplify_dead_assign()
