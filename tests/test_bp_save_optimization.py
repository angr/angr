import os
import nose

import angr
import ailment

test_location = str(
    os.path.join(
        os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))


def check_bp_save_fauxware(arch):
    p = angr.Project(os.path.join(test_location, arch, 'fauxware'), auto_load_libs=False)
    p.analyses.CFGFast()
    main = p.kb.functions['main']
    dra = p.analyses.Decompiler(main)
    first_block_stmts = dra.codegen._sequence.nodes[0].nodes[0].statements
    for stmt in first_block_stmts:
        if isinstance(stmt, ailment.Stmt.Store):
            nose.tools.assert_false(
                (isinstance(stmt.data, ailment.Expr.Register)
                 and stmt.data.reg_offset == p.arch.bp_offset)
                or (isinstance(stmt.data, ailment.Expr.StackBaseOffset)
                    and stmt.data.offset == 0))


def test_bp_save_amd64_fauxware():
    check_bp_save_fauxware('x86_64')


def test_bp_save_armel_fauxware():
    check_bp_save_fauxware('armel')


if __name__ == '__main__':
    test_bp_save_armel_fauxware()
    test_bp_save_amd64_fauxware()
