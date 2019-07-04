
import logging
import os

import angr
import pyvex
import archinfo

import ailment
import ailment.analyses


def test_block_simplifier():

    arch = archinfo.arch_from_id('AMD64')

    manager = ailment.Manager(arch=arch)

    block_bytes = bytes.fromhex("554889E54883EC40897DCC488975C048C745F89508400048C745F0B6064000488B45C04883C008488B00BEA70840004889C7E883FEFFFF")

    irsb = pyvex.IRSB(block_bytes, 0x4006c6, arch, opt_level=0)

    ablock = ailment.IRSBConverter.convert(irsb, manager)

    # we need a project...
    project = angr.Project(os.path.join(os.path.dirname(os.path.abspath(__file__)),
        '..', '..', 'binaries', 'tests', 'x86_64', 'all'), auto_load_libs=False)

    simp = project.analyses.AILBlockSimplifier(ablock)


if __name__ == "__main__":
    test_block_simplifier()
