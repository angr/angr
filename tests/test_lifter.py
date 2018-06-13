import angr

def test_strict_block_ends_cbz():
    # ldr     r3, [sp, #4]
    # cbz     r3, #0x8149
    # mov.w   r2, #0x10000000
    # ldr     r3, [pc, #0x38]
    # str     r2, [r3]
    # add     sp, #8
    # pop     {r4, r5, r6, pc}

    p = angr.load_shellcode('\x01\x9b\x1b\xb1O\xf0\x80R\x0eK\x1a`\x02\xb0p\xbd', 'arm')
    assert p.factory.block(1, strict_block_end=False).instructions == 7
    assert p.factory.block(1, strict_block_end=True).instructions == 2
    p.engines.vex.default_strict_block_end = False
    assert p.factory.block(1).instructions == 7
    p.engines.vex.default_strict_block_end = True
    assert p.factory.block(1).instructions == 2

if __name__ == '__main__':
    test_strict_block_ends_cbz()
