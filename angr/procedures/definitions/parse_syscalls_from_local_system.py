# coding: utf-8
import xml.etree.ElementTree
import glob
import os

def parse_gdb_xml_file(fname):
    assert fname.endswith('-linux.xml')
    tree = xml.etree.ElementTree.parse(fname)
    syscalls = tree.findall('syscall')
    return {int(e.attrib['number']): e.attrib['name'] for e in syscalls}

def parse_unistd_include_header(header_path):
    with open(header_path, 'r') as f:
        lines = [l.strip() for l in f.read().strip().split('\n') if '__NR_' in l]
        syscalls = {}
        for l in lines:
            spl = l.split()
            assert spl[0] == '#define'
            assert spl[1].startswith('__NR_')
            name = spl[1][len('__NR_'):]
            nr = int(spl[2])
            syscalls[nr] = name
        return syscalls


def dump_mapping(abi, mapping):
    print('\nlib.add_number_mapping_from_dict("%s", {' % abi)
    for num in sorted(mapping):
        print('    %d: "%s",' % (num, mapping[num]))
    print('})')

def main():
    syscalls_by_abi = {}
    for fname in glob.glob('/usr/share/gdb/syscalls/*-linux.xml'):
        abi = os.path.basename(fname)[:-len('-linux.xml')]
        syscalls_by_abi[abi] = parse_gdb_xml_file(fname)

    syscalls_by_abi['amd64'] = parse_unistd_include_header('/usr/include/x86_64-linux-gnu/asm/unistd_64.h')
    syscalls_by_abi['i386'] = parse_unistd_include_header('/usr/include/x86_64-linux-gnu/asm/unistd_32.h')

    syscalls_by_abi['i386'][90] = 'old_mmap' # name the old mmap differently
    syscalls_by_abi['arm'] = {num: name for num, name in syscalls_by_abi['arm'].items() if not name.startswith('ARM_')}

    syscalls_by_abi['armhf'] = {num + 0x900000: name for num, name in syscalls_by_abi['arm'].items()}

    for abi, mapping in sorted(syscalls_by_abi.items()):
        dump_mapping(abi, mapping)

if __name__ == '__main__':
    main()
