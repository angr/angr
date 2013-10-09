#!/usr/bin/env python

import pysex
import idalink
import z3
import subprocess
import sys
import logging
from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection, DynamicSegment
from elftools.common.py3compat import bytes2str

logging.basicConfig()
l = logging.getLogger("loader")
l.setLevel(logging.DEBUG)

def load_binary(ida):
    mem = pysex.s_memory.Memory()
    dst = z3.BitVec('dst', mem.get_bit_address())

    # dynamic stuff
    paths = get_path_shared_libraries(ida.get_filename())

    # static stuff
    for k in ida.mem.keys():
        bit_len = 8 #idalink handles bytes
        mem.store(dst, z3.BitVecVal(ida.mem[k], bit_len), [dst == k], 5)


    return mem

def get_path_shared_libraries(filename):
	paths = [] 
        p = subprocess.Popen(["ldd", filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result = p.stdout.readlines()

        for x in result:
            s = x.split()
            if "=>" in x:
                if len(s) == 3: # virtual library
                    pass
                else: 
                    paths.append(s[2])
            else: 
                if len(s) == 2:
                    paths.append(s[0])
        return paths 

def load_ELF(mem, filename):
    elf_file = ELFFile(open(filename, "rb"))

    for section in elf_file.iter_sections():
        if not isinstance(section, DynamicSection):
            continue

        for tag in section.iter_tags():
            if tag.entry.d_tag == 'DT_NEEDED':
                l.info("Shared library: [%s]" % bytes2str(tag.needed))
