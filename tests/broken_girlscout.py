import sys
import logging

import nose

import angr

def main():
    if len(sys.argv) == 2:
        f = sys.argv[1]
    else:
        f = "/home/angr/angr/rearentry/tests/dell-2e0048/dell-2e0048.out"
    # TODO: Determine the architecture and endness
    p = angr.Project(f, arch=angr.SimARM(endness="Iend_BE"),
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
    gs = p.analyses.GirlScout(pickle_intermediate_results=True)
    nose.tools.assert_equal(gs.base_address, 0x40580000)

if __name__ == "__main__":
    _debugging_modules = {
        #'angr.analyses.girlscout'
        }
    _info_modules = {
        'angr.analyses.girlscout'
    }
    _error_modules = {
        'angr.states'
    }
    for m in _debugging_modules:
        logging.getLogger(m).setLevel(logging.DEBUG)
    for m in _info_modules:
        logging.getLogger(m).setLevel(logging.INFO)
    for m in _error_modules:
        logging.getLogger(m).setLevel(logging.ERROR)
    main()
