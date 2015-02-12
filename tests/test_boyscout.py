import sys
import os
import logging

import angr
import simuvex

test_location = str(os.path.dirname(os.path.realpath(__file__)))

def main():
    for root, dirs, files in os.walk(test_location + "/blob"):
        for filename in files:
            f = os.path.join(root, filename)

            print "Processing %s" % f

            # TODO: Determine the architecture and endness
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

            print bs.arch,
            print bs.endianness

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
    main()
