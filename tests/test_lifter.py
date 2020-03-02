import binascii

import angr


def test_strict_block_ends_cbz():
    # ldr     r3, [sp, #4]
    # cbz     r3, #0x8149
    # mov.w   r2, #0x10000000
    # ldr     r3, [pc, #0x38]
    # str     r2, [r3]
    # add     sp, #8
    # pop     {r4, r5, r6, pc}

    p = angr.load_shellcode(b'\x01\x9b\x1b\xb1O\xf0\x80R\x0eK\x1a`\x02\xb0p\xbd', 'arm')
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
    p = angr.load_shellcode(b, 'x86', load_address=0x4010c9)

    # jecxz
    assert p.factory.block(0x4010c9, size=len(b), strict_block_end=False).instructions == 7
    assert p.factory.block(0x4010c9, strict_block_end=True).instructions == 3
    assert p.factory.block(0x4010c9, size=len(b), strict_block_end=True).instructions == 3

    # loop
    assert p.factory.block(0x4010d0, strict_block_end=False).instructions == 4
    assert p.factory.block(0x4010d0, strict_block_end=True).instructions == 2
    assert p.factory.block(0x4010d0, size=7, strict_block_end=True).instructions == 2


def test_strict_block_ends_with_size_amd64():
    # cmovnz  cx, dx
    # pop     rax
    # jrcxz   short loc_4010D7  ; the first block should end here
    # sub     edi, 2
    # loop    loc_4010c9
    # nop
    # nop


    b = b"\x66\x0f\x45\xca\x58\xe3\x07\x83\xef\x02\xe2\xf4\x90\x90"
    p = angr.load_shellcode(b, 'amd64', load_address=0x4010c9)

    # jrcxz
    assert p.factory.block(0x4010c9, size=len(b), strict_block_end=False).instructions == 7
    assert p.factory.block(0x4010c9, strict_block_end=True).instructions == 3
    assert p.factory.block(0x4010c9, size=len(b), strict_block_end=True).instructions == 3

    # loop
    assert p.factory.block(0x4010d0, strict_block_end=False).instructions == 4
    assert p.factory.block(0x4010d0, strict_block_end=True).instructions == 2
    assert p.factory.block(0x4010d0, size=7, strict_block_end=True).instructions == 2


def test_no_cross_insn_boundary_opt_amd64():
    b = binascii.unhexlify("4883ec08488b05f51e22004885c07405")
    p = angr.load_shellcode(b, 'amd64', load_address=0x4020f8)

    block = p.factory.block(0x4020f8, size=len(b), opt_level=0, cross_insn_opt=False)
    print(block.vex.pp())
    block = p.factory.block(0x4020f8, size=len(b), opt_level=1, cross_insn_opt=False)
    print(block.vex.pp())
    block = p.factory.block(0x4020f8, size=len(b), opt_level=1, cross_insn_opt=True)
    print(block.vex.pp())


if __name__ == '__main__':
    test_strict_block_ends_cbz()
    test_strict_block_ends_with_size_x86()
    test_strict_block_ends_with_size_amd64()
