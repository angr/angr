import logging
import os
import unittest

import angr

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')
l = logging.getLogger('angr.test_boyscout')

entries = [
    ("i386/all", "X86", "Iend_LE"),
    ("i386/fauxware", "X86", "Iend_LE"),
    ("x86_64/all", "AMD64", "Iend_LE"),
    ("x86_64/basic_buffer_overflows", "AMD64", "Iend_LE"),
    ("x86_64/cfg_0", "AMD64", "Iend_LE"),
    ("x86_64/cfg_1", "AMD64", "Iend_LE"),
    ("armel/fauxware", "ARM", "Iend_LE"),
    ("armel/test_division", "ARM", "Iend_LE"),
    ("armhf/fauxware", "ARM", "Iend_LE"),
    ("mips/allcmps", "MIPS32", "Iend_BE"),
    ("mips/manysum", "MIPS32", "Iend_BE"),
    ("mipsel/busybox", "MIPS32", "Iend_LE"),
    ("mipsel/fauxware", "MIPS32", "Iend_LE"),
    # TODO: PPC tests are commented out for now. They will be uncommented when Amat's branch is
    # TODO: merged back in
    # ("ppc/fauxware", "PPC", "Iend_BE"),
    # ("ppc64/fauxware", "PPC64", "Iend_BE"),
]


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestBoyScout(unittest.TestCase):
    def test_boyscout(self):
        for a, b, c in entries:
            yield self.main, a, b, c

    def main(self, file_path, arch, endianness):
        f = os.path.join(test_location, file_path)
        l.debug("Processing %s", f)

        p = angr.Project(f,
                         load_options={
                             'main_opts': {
                                 'backend': 'blob',
                                 'base_addr': 0x10000,
                                 'entry_point': 0x10000,
                                 'arch': 'ARM',
                                 'offset': 0,
                             }
                         },
                         auto_load_libs=False
                         )
        # Call Scout
        # p.analyses.Scout(start=0x16353c)
        bs = p.analyses.BoyScout()

        assert arch in bs.arch
        assert bs.endianness == endianness


if __name__ == "__main__":
    unittest.main()
