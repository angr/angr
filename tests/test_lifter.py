import binascii

import pyvex
import archinfo
import angr


def test_strict_block_ends_cbz():
    # ldr     r3, [sp, #4]
    # cbz     r3, #0x8149
    # mov.w   r2, #0x10000000
    # ldr     r3, [pc, #0x38]
    # str     r2, [r3]
    # add     sp, #8
    # pop     {r4, r5, r6, pc}

    p = angr.load_shellcode(b"\x01\x9b\x1b\xb1O\xf0\x80R\x0eK\x1a`\x02\xb0p\xbd", "arm")
    assert p.factory.block(1, strict_block_end=False).instructions == 7
    assert p.factory.block(1, strict_block_end=True).instructions == 2
    p.factory.default_engine.default_strict_block_end = False
    assert p.factory.block(1).instructions == 7
    p.factory.default_engine.default_strict_block_end = True
    assert p.factory.block(1).instructions == 2


def test_strict_block_ends_with_size_x86():
    # cmovnz  cx, dx
    # pop     eax
    # jecxz   short loc_4010D7  ; the first block should end here
    # sub     edi, 2
    # loop    loc_4010c9
    # nop
    # nop

    b = b"\x66\x0f\x45\xca\x58\xe3\x07\x83\xef\x02\xe2\xf4\x90\x90"
    p = angr.load_shellcode(b, "x86", load_address=0x4010C9)

    # jecxz
    assert p.factory.block(0x4010C9, size=len(b), strict_block_end=False).instructions == 7
    assert p.factory.block(0x4010C9, strict_block_end=True).instructions == 3
    assert p.factory.block(0x4010C9, size=len(b), strict_block_end=True).instructions == 3

    # loop
    assert p.factory.block(0x4010D0, strict_block_end=False).instructions == 4
    assert p.factory.block(0x4010D0, strict_block_end=True).instructions == 2
    assert p.factory.block(0x4010D0, size=7, strict_block_end=True).instructions == 2


def test_strict_block_ends_with_size_amd64():
    # cmovnz  cx, dx
    # pop     rax
    # jrcxz   short loc_4010D7  ; the first block should end here
    # sub     edi, 2
    # loop    loc_4010c9
    # nop
    # nop

    b = b"\x66\x0f\x45\xca\x58\xe3\x07\x83\xef\x02\xe2\xf4\x90\x90"
    p = angr.load_shellcode(b, "amd64", load_address=0x4010C9)

    # jrcxz
    assert p.factory.block(0x4010C9, size=len(b), strict_block_end=False).instructions == 7
    assert p.factory.block(0x4010C9, strict_block_end=True).instructions == 3
    assert p.factory.block(0x4010C9, size=len(b), strict_block_end=True).instructions == 3

    # loop
    assert p.factory.block(0x4010D0, strict_block_end=False).instructions == 4
    assert p.factory.block(0x4010D0, strict_block_end=True).instructions == 2
    assert p.factory.block(0x4010D0, size=7, strict_block_end=True).instructions == 2


def test_no_cross_insn_boundary_opt_amd64():
    # 0x4020f8:       sub     rsp, 8
    # 0x4020fc:       mov     rax, qword ptr [rip + 0x221ef5]
    # 0x402103:       test    rax, rax
    # 0x402106:       je      0x40210d

    b = binascii.unhexlify("4883ec08488b05f51e22004885c07405")
    p = angr.load_shellcode(b, "amd64", load_address=0x4020F8)

    # No optimization
    block = p.factory.block(0x4020F8, size=len(b), opt_level=0)
    assert len(block.vex.statements) == 32
    # Full level-1 optimization
    block = p.factory.block(0x4020F8, size=len(b), opt_level=1, cross_insn_opt=True)
    assert len(block.vex.statements) == 20
    # Level-1 optimization within each instruction
    block = p.factory.block(0x4020F8, size=len(b), opt_level=1, cross_insn_opt=False)
    stmts = block.vex.statements
    assert len(stmts) == 22
    # 09 | ------ IMark(0x402103, 3, 0) ------
    assert isinstance(stmts[9], pyvex.IRStmt.IMark)
    assert stmts[9].addr == 0x402103
    # 10 | t6 = GET:I64(rax)
    assert isinstance(stmts[10], pyvex.IRStmt.WrTmp)
    assert isinstance(stmts[10].data, pyvex.IRExpr.Get)
    assert stmts[10].data.offset == archinfo.arch_from_id("amd64").registers["rax"][0]
    # 11 | PUT(cc_op) = 0x0000000000000014
    assert isinstance(stmts[11], pyvex.IRStmt.Put)
    assert stmts[11].offset == archinfo.arch_from_id("amd64").registers["cc_op"][0]
    assert isinstance(stmts[11].data, pyvex.IRExpr.Const)
    assert stmts[11].data.con.value == 0x14
    # 12 | PUT(cc_dep1) = t6
    assert isinstance(stmts[12], pyvex.IRStmt.Put)
    assert stmts[12].offset == archinfo.arch_from_id("amd64").registers["cc_dep1"][0]
    # 13 | PUT(cc_dep2) = 0x0000000000000000
    assert isinstance(stmts[13], pyvex.IRStmt.Put)
    assert stmts[13].offset == archinfo.arch_from_id("amd64").registers["cc_dep2"][0]
    assert isinstance(stmts[13].data, pyvex.IRExpr.Const)
    assert stmts[13].data.con.value == 0
    # 14 | PUT(rip) = 0x0000000000402106
    assert isinstance(stmts[14], pyvex.IRStmt.Put)
    assert stmts[14].offset == archinfo.arch_from_id("amd64").registers["rip"][0]
    assert isinstance(stmts[14].data, pyvex.IRExpr.Const)
    assert stmts[14].data.con.value == 0x402106
    # 15 | ------ IMark(0x402106, 2, 0) ------
    assert isinstance(stmts[15], pyvex.IRStmt.IMark)
    assert stmts[15].addr == 0x402106


if __name__ == "__main__":
    test_strict_block_ends_cbz()
    test_strict_block_ends_with_size_x86()
    test_strict_block_ends_with_size_amd64()
    test_no_cross_insn_boundary_opt_amd64()
