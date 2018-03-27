# coding: utf-8
from __future__ import print_function
import xml.etree.ElementTree
import glob
import os

def parse_file(fname):
    assert fname.endswith('-linux.xml')
    abi = os.path.basename(fname)[:-len('-linux.xml')]
    tree = xml.etree.ElementTree.parse(fname)
    syscalls = tree.findall('syscall')
    return abi, {int(e.attrib['number']): e.attrib['name'] for e in syscalls}

def dump_mapping(abi, mapping):
    print('\nlib.add_number_mapping_from_dict("%s", {' % abi)
    for num in sorted(mapping):
        print('    %d: "%s",' % (num, mapping[num]))
    print('})')

def main():
    for fname in sorted(glob.glob('/usr/share/gdb/syscalls/*-linux.xml')):
        abi, mapping = parse_file(fname)
        if abi == 'arm':
            for key in list(mapping):
                if mapping[key].startswith('ARM_'):
                    mapping.pop(key)
        elif abi == 'i386':
            mapping[90] = 'old_mmap' # name the old mmap differently

        dump_mapping(abi, mapping)
        if abi == 'arm':
            # https://github.com/gumstix/linux/blob/yocto-v3.18.y/arch/arm/include/uapi/asm/unistd.h
            dump_mapping('armhf', {num+0x900000: name for num, name in mapping.items()})

if __name__ == '__main__':
    main()
