import os
import logging

import nose

import angr
test_location = str(os.path.dirname(os.path.realpath(__file__)))

l = logging.getLogger('angr.test_boyscout')

def test_boyscout():
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
        #("ppc/fauxware", "PPC", "Iend_BE"),
        #("ppc64/fauxware", "PPC64", "Iend_BE"),
    ]

    for file_path, arch, endianness in entries:
        f = os.path.join(test_location, "blob/" + file_path)
        l.debug("Processing %s", f)

        p = angr.Project(f,
            load_options={
                'backend': 'blob',
                'custom_base_addr': 0x10000,
                #'custom_entry_point': 0x10000,
                'custom_entry_point': 0x10000,
                'custom_arch': 'ARM',
                'custom_offset': 0,
                }
            )
        # Call Scout
        #p.analyses.Scout(start=0x16353c)
        bs = p.analyses.BoyScout()

        nose.tools.assert_equal(bs.arch, arch)
        nose.tools.assert_equal(bs.endianness, endianness)

if __name__ == "__main__":
    _debugging_modules = {
        #'angr.analyses.boyscout'
        }
    _info_modules = {
        'angr.analyses.boyscout'
    }
    for m in _debugging_modules:
        logging.getLogger(m).setLevel(logging.DEBUG)
    for m in _info_modules:
        logging.getLogger(m).setLevel(logging.INFO)
    test_boyscout()
