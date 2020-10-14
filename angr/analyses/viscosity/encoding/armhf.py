from .base import VEXStatementsSkeleton as S, InstructionEncoding as I

encodings = [
    # comparing between registers
    # TODO: Implement tmp normalization to differentiate Cmp(t0,t1) and Cmp(t1,t0)
    # I(b"\x00\x00\x00\x8a", b"\x00\x00\x00\xff", "bhi ?", S(['t = CmpLT32U(t,t)', 't = 1Uto32(t)', 't = 32to1(t)', 'exit-elsewhere'])),
    # I(b"\x00\x00\x00\x2a", b"\x00\x00\x00\xff", "bhs ?", S(['t = CmpLE32U(t,t)', 't = 1Uto32(t)', 't = 32to1(t)', 'exit-elsewhere'])),
    # I(b"\x00\x00\x00\x3a", b"\x00\x00\x00\xff", "blo ?", S(['t = CmpLT32U(t,t)', 't = 1Uto32(t)', 't = 32to1(t)', 'exit-elsewhere'])),
    # I(b"\x00\x00\x00\x9a", b"\x00\x00\x00\xff", "bls ?", S(['t = CmpLE32U(t,t)', 't = 1Uto32(t)', 't = 32to1(t)', 'exit-elsewhere'])),
    # I(b"\x00\x00\x00\x0a", b"\x00\x00\x00\xff", "beq ?", S(['t = CmpEQ32(t,t)', 't = 1Uto32(t)', 't = 32to1(t)', 'exit-elsewhere'])),
    # I(b"\x00\x00\x00\x1a", b"\x00\x00\x00\xff", "bne ?", S(['t = CmpNE32(t,t)', 't = 1Uto32(t)', 't = 32to1(t)', 'exit-elsewhere'])),
    # I(b"\x00\x00\x00\xba", b"\x00\x00\x00\xff", "blt ?", S(['t = CmpLT32S(t,t)', 't = 1Uto32(t)', 't = 32to1(t)', 'exit-elsewhere'])),
    # I(b"\x00\x00\x00\xda", b"\x00\x00\x00\xff", "ble ?", S(['t = CmpLE32S(t,t)', 't = 1Uto32(t)', 't = 32to1(t)', 'exit-elsewhere'])),
    # I(b"\x00\x00\x00\xca", b"\x00\x00\x00\xff", "bgt ?", S(['t = CmpLT32S(t,t0)', 't = 1Uto32(t)', 't = 32to1(t)', 'exit-elsewhere'])),
    # I(b"\x00\x00\x00\xaa", b"\x00\x00\x00\xff", "bge ?", S(['t = CmpLT32S(t,t0)', 't = 1Uto32(t)', 't = 32to1(t)', 'exit-elsewhere'])),

    # comparing a register to a constant
    I(b"\x00\x00\x00\x8a", b"\x00\x00\x00\xff", "bhi ?", S(['t = CmpLT32U(con,t)', 't = 1Uto32(t)', 't = 32to1(t)', 'exit-elsewhere'])),
    I(b"\x00\x00\x00\x2a", b"\x00\x00\x00\xff", "bhs ?", S(['t = CmpLE32U(con,t)', 't = 1Uto32(t)', 't = 32to1(t)', 'exit-elsewhere'])),
    I(b"\x00\x00\x00\x3a", b"\x00\x00\x00\xff", "blo ?", S(['t = CmpLT32U(t,con)', 't = 1Uto32(t)', 't = 32to1(t)', 'exit-elsewhere'])),
    I(b"\x00\x00\x00\x9a", b"\x00\x00\x00\xff", "bls ?", S(['t = CmpLE32U(t,con)', 't = 1Uto32(t)', 't = 32to1(t)', 'exit-elsewhere'])),
    I(b"\x00\x00\x00\x0a", b"\x00\x00\x00\xff", "beq ?", S(['t = CmpEQ32(t,con)', 't = 1Uto32(t)', 't = 32to1(t)', 'exit-elsewhere'])),
    I(b"\x00\x00\x00\x1a", b"\x00\x00\x00\xff", "bne ?", S(['t = CmpNE32(t,con)', 't = 1Uto32(t)', 't = 32to1(t)', 'exit-elsewhere'])),
    I(b"\x00\x00\x00\xba", b"\x00\x00\x00\xff", "blt ?", S(['t = CmpLT32S(t,con)', 't = 1Uto32(t)', 't = 32to1(t)', 'exit-elsewhere'])),
    I(b"\x00\x00\x00\xda", b"\x00\x00\x00\xff", "ble ?", S(['t = CmpLE32S(t,con)', 't = 1Uto32(t)', 't = 32to1(t)', 'exit-elsewhere'])),
    I(b"\x00\x00\x00\xca", b"\x00\x00\x00\xff", "bgt ?", S(['t = CmpLT32S(con,t0)', 't = 1Uto32(t)', 't = 32to1(t)', 'exit-elsewhere'])),
    I(b"\x00\x00\x00\xaa", b"\x00\x00\x00\xff", "bge ?", S(['t = CmpLT32S(con,t0)', 't = 1Uto32(t)', 't = 32to1(t)', 'exit-elsewhere'])),
]
