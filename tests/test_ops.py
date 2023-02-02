import angr
import claripy

# all the input values were generated via
# [random.randrange(256) for _ in range(16)]
# then set into the input registers via gdb
# set $xmm0.v16_int8 = {...}
# then read out as uint128s
# p/x $xmm0.uint128
# then single stepped and the result read out


def test_irop_perm():
    p = angr.load_shellcode("vpshufb xmm0,xmm1,xmm2", "amd64")

    # concrete test
    s1 = p.factory.blank_state()
    s1.regs.xmm1 = 0x3C899A56814EE9B84C7B5D8394C85881
    s1.regs.xmm2 = 0xA55C66A2CDEF1CBCD72B42078D1B7F8B
    s2 = s1.step(num_inst=1).successors[0]
    assert (s2.regs.xmm0 == 0x00567B00000056000081C84C00813C00).is_true()

    # symbolic test
    s3 = p.factory.blank_state()
    s3.regs.xmm1 = claripy.BVS("xmm1", 128)
    s3.regs.xmm2 = claripy.BVS("xmm2", 128)
    s4 = s3.step(num_inst=1).successors[0]
    s4.solver.add(s4.regs.xmm2 == 0xA55C66A2CDEF1CBCD72B42078D1B7F8B)
    s4.solver.add(s4.regs.xmm0 == 0x00567B00000056000081C84C00813C00)
    assert s4.solver.solution(s4.regs.xmm1, 0x3C899A56814EE9B84C7B5D8394C85881)


def test_irop_mulhi():
    p = angr.load_shellcode("vpmulhw xmm0,xmm1,xmm2", "amd64")

    # concrete test
    s1 = p.factory.blank_state()
    s1.regs.xmm1 = 0x3ACA92553C2526D4F20987AEAB250255
    s1.regs.xmm2 = 0x1AEBCB281463274EC3CE6473619A8541
    s2 = s1.step(num_inst=1).successors[0]
    assert (s2.regs.xmm0 == 0x62E16A304CA05F60348D0C9DFA5FEE1).is_true()


def test_irop_catevenlanes():
    p = angr.load_shellcode("pmulhrsw xmm0, xmm1", "amd64")

    # concrete test
    s1 = p.factory.blank_state()
    s1.regs.xmm0 = 0x4713E06BF3235E97CA8CFDE0647D65FD
    s1.regs.xmm1 = 0x31F1F86DA1DCE7DE252ADC78160E1016
    s2 = s1.step(num_inst=1).successors[0]
    assert (s2.regs.xmm0 == 0x1BBB01DE0976EE2BF07B009711500CD1).is_true()


def test_saturating_packing():
    # SaturateSignedWordToUnsignedByte
    p = angr.load_shellcode("vpackuswb xmm1, xmm0, xmm0", arch="amd64")
    s = p.factory.blank_state()
    s.regs.xmm0 = 0x0000_0001_7FFE_7FFF_8000_8001_FFFE_FFFF
    s = s.step(num_inst=1).successors[0]
    assert (s.regs.xmm1 == 0x00_01_FF_FF_00_00_00_00_0001FFFF00000000).is_true()

    # "Pack with unsigned saturation"
    p = angr.load_shellcode("vpackusdw xmm1, xmm0, xmm0", arch="amd64")
    s = p.factory.blank_state()
    s.regs.xmm0 = 0x00000001_7FFFFFFE_80000001_FFFFFFFE
    s = s.step(num_inst=1).successors[0]
    assert (s.regs.xmm1 == 0x0001_FFFF_0000_0000_0001FFFF00000000).is_true()

    # SaturateSignedWordToSignedByte
    p = angr.load_shellcode("vpacksswb xmm1, xmm0, xmm0", arch="amd64")
    s = p.factory.blank_state()
    s.regs.xmm0 = 0x0000_0001_7FFE_7FFF_8000_8001_FFFE_FFFF
    s = s.step(num_inst=1).successors[0]
    assert (s.regs.xmm1 == 0x00_01_7F_7F_80_80_FE_FF_00017F7F8080FEFF).is_true()


if __name__ == "__main__":
    test_irop_perm()
    test_irop_mulhi()
    test_irop_catevenlanes()
    test_saturating_packing()
