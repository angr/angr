import angr
import claripy
import archinfo

# all the input values were generated via
# [random.randrange(256) for _ in range(16)]
# then set into the input registers via gdb
# set $xmm0.v16_int8 = {...}
# then read out as uint128s
# p/x $xmm0.uint128
# then single stepped and the result read out

def test_irop_perm():
    p = angr.load_shellcode('vpshufb xmm0,xmm1,xmm2', 'amd64')

    # concrete test
    s1 = p.factory.blank_state()
    s1.regs.xmm1 = 0x3c899a56814ee9b84c7b5d8394c85881
    s1.regs.xmm2 = 0xa55c66a2cdef1cbcd72b42078d1b7f8b
    s2 = s1.step(num_inst=1).successors[0]
    assert (s2.regs.xmm0 == 0x00567b00000056000081c84c00813c00).is_true()

    # symbolic test
    s3 = p.factory.blank_state()
    s3.regs.xmm1 = claripy.BVS('xmm1', 128)
    s3.regs.xmm2 = claripy.BVS('xmm2', 128)
    s4 = s3.step(num_inst=1).successors[0]
    s4.solver.add(s4.regs.xmm2 == 0xa55c66a2cdef1cbcd72b42078d1b7f8b)
    s4.solver.add(s4.regs.xmm0 == 0x00567b00000056000081c84c00813c00)
    assert s4.solver.solution(s4.regs.xmm1, 0x3c899a56814ee9b84c7b5d8394c85881)

def test_irop_mulhi():
    p = angr.load_shellcode('vpmulhw xmm0,xmm1,xmm2', 'amd64')

    # concrete test
    s1 = p.factory.blank_state()
    s1.regs.xmm1 = 0x3aca92553c2526d4f20987aeab250255
    s1.regs.xmm2 = 0x1aebcb281463274ec3ce6473619a8541
    s2 = s1.step(num_inst=1).successors[0]
    assert (s2.regs.xmm0 == 0x62e16a304ca05f60348d0c9dfa5fee1).is_true()

def test_irop_catevenlanes():
    p = angr.load_shellcode('pmulhrsw xmm0, xmm1', 'amd64')

    # concrete test
    s1 = p.factory.blank_state()
    s1.regs.xmm0 = 0x4713e06bf3235e97ca8cfde0647d65fd
    s1.regs.xmm1 = 0x31f1f86da1dce7de252adc78160e1016
    s2 = s1.step(num_inst=1).successors[0]
    assert (s2.regs.xmm0 == 0x1bbb01de0976ee2bf07b009711500cd1).is_true()

def test_saturating_packing():
    # SaturateSignedWordToUnsignedByte
    p = angr.load_shellcode("vpackuswb xmm1, xmm0, xmm0", arch='amd64')
    s = p.factory.blank_state()
    s.regs.xmm0 = 0x0000_0001_7ffe_7fff_8000_8001_fffe_ffff
    s = s.step(num_inst=1).successors[0]
    assert (s.regs.xmm1 == 0x00_01_ff_ff_00_00_00_00_0001ffff00000000).is_true()

    # "Pack with unsigned saturation"
    p = angr.load_shellcode("vpackusdw xmm1, xmm0, xmm0", arch='amd64')
    s = p.factory.blank_state()
    s.regs.xmm0 = 0x00000001_7ffffffe_80000001_fffffffe
    s = s.step(num_inst=1).successors[0]
    assert (s.regs.xmm1 == 0x0001_ffff_0000_0000_0001ffff00000000).is_true()

    # SaturateSignedWordToSignedByte
    p = angr.load_shellcode("vpacksswb xmm1, xmm0, xmm0", arch='amd64')
    s = p.factory.blank_state()
    s.regs.xmm0 = 0x0000_0001_7ffe_7fff_8000_8001_fffe_ffff
    s = s.step(num_inst=1).successors[0]
    assert (s.regs.xmm1 == 0x00_01_7f_7f_80_80_fe_ff_00017f7f8080feff).is_true()


if __name__ == '__main__':
    test_irop_perm()
    test_irop_mulhi()
    test_irop_catevenlanes()
    test_saturating_packing()
