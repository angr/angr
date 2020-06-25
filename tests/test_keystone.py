import os
import logging
import sys

import nose

import angr

l = logging.getLogger("angr.tests")
test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')

insn_texts = {
    'i386': b"add eax, 0xf",
    'x86_64': b"add rax, 0xf",
    'ppc': b"addi %r1, %r1, 0xf",
    'armel': b"add r1, r1, 0xf",
    'armel_thumb': b"add.w r1, r1, #0xf",
    'mips': b"addi $1, $1, 0xf"
}

def run_keystone(arch):
    proj_arch = arch
    is_thumb = False
    if arch == "armel_thumb":
        is_thumb = True
        proj_arch = "armel"
    p = angr.Project(os.path.join(test_location, proj_arch, "fauxware"))
    addr = p.loader.main_object.get_symbol('authenticate').rebased_addr

    sm = p.factory.simulation_manager()
    if arch in ['i386', 'x86_64']:
        sm.one_active.regs.eax = 3
    else:
        sm.one_active.regs.r1 = 3

    if is_thumb:
        addr |= 1
    block = p.factory.block(addr, insn_text=insn_texts[arch], thumb=is_thumb).vex

    nose.tools.assert_equal(block.instructions, 1)

    sm.step(force_addr=addr, insn_text=insn_texts[arch], thumb=is_thumb)

    if arch in ['i386', 'x86_64']:
        nose.tools.assert_equal(sm.one_active.solver.eval(sm.one_active.regs.eax), 0x12)
    else:
        nose.tools.assert_equal(sm.one_active.solver.eval(sm.one_active.regs.r1), 0x12)

def test_keystone():

    # Installing keystone on Windows is currently a pain. Fix the installation first (may it pip installable) before
    # re-enabling this test on Windows.
    if not sys.platform.startswith('linux'):
        raise nose.SkipTest()

    for arch_name in insn_texts:
        yield run_keystone, arch_name

if __name__ == "__main__":
    for arch_name in insn_texts:
        print(arch_name)
        run_keystone(arch_name)
