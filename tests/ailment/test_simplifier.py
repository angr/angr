
import logging
import os

import angr
import pyvex
import archinfo

import ailment
import ailment.analyses


def test_simplifier():

    arch = archinfo.arch_from_id('AMD64')

    manager = ailment.Manager(arch=arch)

    block_bytes = "55 48 89 E5 48 83 EC 40 89 7D CC 48 89 75 C0 48 C7 45 F8 95 08 40 00 48 C7 45 F0" \
                  "B6 06 40 00 48 8B 45 C0 48 83 C0 08 48 8B 00 BE A7 08 40 00 48 89 C7 E8 83 FE FF" \
                  "FF".replace(" ", "").decode("hex")

    irsb = pyvex.IRSB(block_bytes, 0x400680, arch, opt_level=0)

    ablock = ailment.IRSBConverter.convert(irsb, manager)

    # we need a project...
    project = angr.Project(os.path.join('..', '..', 'binaries', 'tests', 'x86_64', 'all'), auto_load_libs=False)

    simp = project.analyses.AILSimplifier(ablock)


if __name__ == "__main__":
    test_simplifier()
