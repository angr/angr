from .base import VEXStatementsSkeleton as S, InstructionEncoding as I

encodings = [
    # comparing between registers
    I(b"\x76\x00", b"\xff\x00", "ja ?", S(['t = CmpLE64U(t,t)', 't = 1Uto64(t)', 't = t', 't = 64to1(t)', 't = t', 'exit-elsewhere'])),
    I(b"\x77\x00", b"\xff\x00", "ja ?", S(['t = CmpLE64U(t,t)', 't = 1Uto64(t)', 't = t', 't = 64to1(t)', 't = t', 'exit-fallthrough'])),
    I(b"\x72\x00", b"\xff\x00", "jb ?", S(['t = CmpLT64U(t,t)', 't = 1Uto64(t)', 't = t', 't = 64to1(t)', 't = t', 'exit-elsewhere'])),
    I(b"\x74\x00", b"\xff\x00", "je ?", S(['t = CmpEQ64(t,t)', 't = 1Uto64(t)', 't = t', 't = 64to1(t)', 't = t', 'exit-elsewhere'])),
    I(b"\x7c\x00", b"\xff\x00", "jl ?", S(['t = CmpLT64S(t,t)', 't = 1Uto64(t)', 't = t', 't = 64to1(t)', 't = t', 'exit-elsewhere'])),
    I(b"\x7d\x00", b"\xff\x00", "jge ?", S(['t = CmpLT64S(t,t)', 't = 1Uto64(t)', 't = t', 't = 64to1(t)', 't = t', 'exit-fallthrough'])),
    I(b"\x7e\x00", b"\xff\x00", "jle ?", S(['t = CmpLE64S(t,t)', 't = 1Uto64(t)', 't = t', 't = 64to1(t)', 't = t', 'exit-elsewhere'])),
    I(b"\x7f\x00", b"\xff\x00", "jg ?", S(['t = CmpLE64S(t,t)', 't = 1Uto64(t)', 't = t', 't = 64to1(t)', 't = t', 'exit-fallthrough'])),

    # comparing a register to a constant
    I(b"\x76\x00", b"\xff\x00", "ja ?", S(['t = CmpLE64U(t,con)', 't = 1Uto64(t)', 't = t', 't = 64to1(t)', 't = t', 'exit-elsewhere'])),
    I(b"\x77\x00", b"\xff\x00", "ja ?", S(['t = CmpLE64U(t,con)', 't = 1Uto64(t)', 't = t', 't = 64to1(t)', 't = t', 'exit-fallthrough'])),
    I(b"\x72\x00", b"\xff\x00", "jb ?", S(['t = CmpLT64U(t,con)', 't = 1Uto64(t)', 't = t', 't = 64to1(t)', 't = t', 'exit-elsewhere'])),
    I(b"\x74\x00", b"\xff\x00", "je ?", S(['t = CmpEQ64(t,con)', 't = 1Uto64(t)', 't = t', 't = 64to1(t)', 't = t', 'exit-elsewhere'])),
    I(b"\x7c\x00", b"\xff\x00", "jl ?", S(['t = CmpLT64S(t,con)', 't = 1Uto64(t)', 't = t', 't = 64to1(t)', 't = t', 'exit-elsewhere'])),
    I(b"\x7d\x00", b"\xff\x00", "jge ?", S(['t = CmpLT64S(t,con)', 't = 1Uto64(t)', 't = t', 't = 64to1(t)', 't = t', 'exit-fallthrough'])),
    I(b"\x7e\x00", b"\xff\x00", "jle ?", S(['t = CmpLE64S(t,con)', 't = 1Uto64(t)', 't = t', 't = 64to1(t)', 't = t', 'exit-elsewhere'])),
    I(b"\x7f\x00", b"\xff\x00", "jg ?", S(['t = CmpLE64S(t,con)', 't = 1Uto64(t)', 't = t', 't = 64to1(t)', 't = t', 'exit-fallthrough'])),
]
