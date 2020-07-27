import os

import pyvex
import angr
from angr.analyses.decompiler.structured_codegen import CBinaryOp, CFunctionCall
from angr.analyses.viscosity.edits import BytesEdit, MaskedBytesEdit


test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')


def t():
    from angr.analyses.viscosity.encoding.base import VEXStatementsSkeleton
    proj = angr.load_shellcode(b"\x48\x83\xf8\x14\x76\x13", "amd64")
    proj.factory.block(0, cross_insn_opt=False).vex.pp()
    s = VEXStatementsSkeleton.from_block(proj.factory.block(0, cross_insn_opt=False).vex)
    print(s.skeleton)


def test_patch_amd64_instruction_cmp_jbe_by_vex_changes():
    binpath = os.path.join(test_location, "x86_64", "vulns", "vulnerable_fauxware")
    proj = angr.Project(binpath, auto_load_libs=False)

    block0 = proj.factory.block(0x400949, cross_insn_opt=False)
    block1 = block0.vex.copy()

    # block1.pp()
    block1.statements[7].data.args[1] = pyvex.expr.Const(pyvex.const.U64(10))

    v = proj.analyses.Viscosity(block0, block1)
    assert len(v.result) == 1
    assert v.result[0] == BytesEdit(0x40094c, b"\x0a", orig=b"\x14")

    block1.statements[7].data._op = "Iop_CmpLT64U"  # FIXME: This is really bad - we should modify .op_int
    v = proj.analyses.Viscosity(block0, block1)
    assert len(v.result) == 1
    assert v.result[0] == MaskedBytesEdit(0x40094d, b"\x72\x00", b"\xff\x00")


def test_patch_amd64_instruction_by_ail_changes():
    binpath = os.path.join(test_location, "x86_64", "vulns", "vulnerable_fauxware")
    proj = angr.Project(binpath, auto_load_libs=False)

    cfg = proj.analyses.CFG(normalize=True)
    func = cfg.kb.functions['authenticate']
    dec = proj.analyses.Decompiler(func)

    # find the binary operation
    binops = list(v.obj for k, v in dec.codegen.posmap.items() if isinstance(v.obj, CBinaryOp))
    assert len(binops) == 2

    le_binop = next(iter(binop for binop in binops if binop.op == "CmpLE"))
    assert le_binop.tags
    assert "vex_block_addr" in le_binop.tags
    assert "vex_stmt_idx" in le_binop.tags

    # get the block
    block = proj.factory.block(le_binop.tags['vex_block_addr'], cross_insn_opt=False)
    vex_block_copy = block.vex.copy()
    le_vex_stmt = vex_block_copy.statements[le_binop.tags['vex_stmt_idx']]
    assert isinstance(le_vex_stmt, pyvex.stmt.WrTmp)
    assert isinstance(le_vex_stmt.data, pyvex.expr.Binop)
    le_vex_stmt.data._op = "Iop_CmpLT64U"

    v = proj.analyses.Viscosity(block, vex_block_copy)

    import ipdb; ipdb.set_trace()


def test_patch_amd64_remove_calls():
    binpath = os.path.join(test_location, "x86_64", "vulns", "vulnerable_fauxware")
    proj = angr.Project(binpath, auto_load_libs=False)

    cfg = proj.analyses.CFG(normalize=True)
    func = cfg.kb.functions['main']
    dec = proj.analyses.Decompiler(func)

    # find the call statement
    calls = list(v.obj for k, v in dec.codegen.posmap.items() if isinstance(v.obj, CFunctionCall))
    auth_call = next(iter(call for call in calls if call.callee_func.name == "authenticate"))

    assert auth_call.tags
    assert "ins_addr" in auth_call.tags
    assert "vex_block_addr" in auth_call.tags
    assert "vex_stmt_idx" in auth_call.tags

    # remove the call to authenticate
    # get the block
    block = proj.factory.block(auth_call.tags['vex_block_addr'], cross_insn_opt=False)
    vex_block_copy = block.vex.copy()

    # remove all statements that correspond to the ins_addr
    idx = [ i for i, stmt in enumerate(vex_block_copy.statements)
            if isinstance(stmt, pyvex.stmt.IMark) and stmt.addr == auth_call.tags['ins_addr'] ][0]
    vex_block_copy.statements = vex_block_copy.statements[:idx]

    v = proj.analyses.Viscosity(block, vex_block_copy)

    assert len(v.result) == 1
    assert v.result[0] == BytesEdit(0x400ab9, b"\x90\x90\x90\x90\x90")


if __name__ == "__main__":
    test_patch_amd64_remove_calls()
