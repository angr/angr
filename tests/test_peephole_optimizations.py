import os

import angr
import archinfo
import ailment

from angr.analyses.decompiler.peephole_optimizations import ConstantDereferences

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')


def test_constant_dereference():

    # a = *(A) :=> a = the variable at at A iff
    # - A is a pointer that points to a read-only section.

    proj = angr.Project(os.path.join(test_location, "armel", "decompiler", "rm"))

    stmt = ailment.Assignment(None,
                              ailment.Register(None, None, proj.arch.registers['r0'][0],
                                               proj.arch.registers['r0'][1] * proj.arch.byte_width,
                                               ins_addr=0x400100
                                               ),
                              ailment.Expr.Load(None, ailment.Expr.Const(None, None, 0xa000, proj.arch.bits),
                                                proj.arch.bytes, archinfo.Endness.LE
                                                ),
                              ins_addr=0x400100,
                              )
    opt = ConstantDereferences(proj)
    optimized = opt.optimize(stmt)
    assert isinstance(optimized, ailment.Assignment)
    assert optimized.dst is stmt.dst
    assert isinstance(optimized.src, ailment.Const)
    assert optimized.src.value == 0x183f8
    assert optimized.tags.get('ins_addr', None) == 0x400100, "Peephole optimizer lost tags."

    # multiple cases that no optimization should happen
    # a. Loading a pointer from a writable location
    stmt = ailment.Assignment(None,
                              ailment.Register(None, None, proj.arch.registers['r0'][0],
                                               1,
                                               ins_addr=0x400100
                                               ),
                              ailment.Expr.Load(None, ailment.Expr.Const(None, None, 0x21df4, proj.arch.bits),
                                                1, archinfo.Endness.LE
                                                ),
                              ins_addr=0x400100,
                              )
    opt = ConstantDereferences(proj)
    optimized = opt.optimize(stmt)
    assert optimized is None


if __name__ == "__main__":
    test_constant_dereference()
