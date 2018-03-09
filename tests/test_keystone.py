import os
import logging
import nose
import angr

l = logging.getLogger("angr.tests")
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

target_addrs = {
    'i386': [ 0x080485C9 ],
    'x86_64': [ 0x4006ed ],
    'armel': [ 0x85F0 ],
}

def run_keystone(arch):
    p = angr.Project(os.path.join(test_location, arch, "fauxware"))

    block = p.factory.block(target_addrs[arch][0])
    sm = p.factory.simgr()

    insn_text = ''
    for i in block.capstone.insns:
        insn_text += i.mnemonic + ' ' + i.op_str + ';'

    new_block = p.factory.block(block.addr, insn_text=insn_text[:-1], size=block.size)

    nose.tools.assert_equal(block.bytes, new_block.bytes)

    sm.step(addr=block.addr, insn_text=insn_text)

    nose.tools.assert_true('active' in sm.stashes)

if __name__ == "__main__":
    for arch in target_addrs:
        run_keystone(arch)
