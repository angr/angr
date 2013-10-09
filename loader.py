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
import pdb

logging.basicConfig()
l = logging.getLogger("loader")
l.setLevel(logging.DEBUG)

def load_binary(ida):
    mem = pysex.s_memory.Memory()
    dst = z3.BitVec('dst', mem.get_bit_address())

    # dynamic stuff
    dobj = get_dynamicOBJ(ida.get_filename())
    print dobj
    # static stuff
    for k in ida.mem.keys():
        bit_len = 8 #idalink handles bytes
        mem.store(dst, z3.BitVecVal(ida.mem[k], bit_len), [dst == k], 5)


    return mem

def load_ELF(mem, filename):
    elf_file = ELFFile(open(filename, "rb"))

    for section in elf_file.iter_sections():
        if not isinstance(section, DynamicSection):
            continue

        for tag in section.iter_tags():
            if tag.entry.d_tag == 'DT_NEEDED':
                l.info("Shared library: [%s]" % bytes2str(tag.needed))

def get_dynamicOBJ(filename):
    p_nm = subprocess.Popen(["nm", "-D", filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result_nm = p_nm.stdout.readlines()
    p_ldd = subprocess.Popen(["ldd", filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result_ldd = p_ldd.stdout.readlines()

    dyn = {}

    for nm_out in result_nm:
        sym_entry = nm_out.split()
        if len(sym_entry) >= 2 and sym_entry[0 if len(sym_entry) == 2 else 1] == "U":
            sym = sym_entry[1 if len(sym_entry) == 2 else 2]
            for lld_out in result_ldd:
                lib_entry = lld_out.split()
                if "=>" in lld_out and len(lib_entry) > 3: # virtual library
                    lib = lib_entry[2]
                    ls_nm = subprocess.Popen(["nm", "-D", lib], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    result_lsnm = ls_nm.stdout.readlines()
                    for ls_nm_out in result_lsnm:
                        lib_symbol = ls_nm_out.split()
                        if len(lib_symbol) >= 2 and lib_symbol[0 if len(lib_symbol) == 2 else 1] == "T":
                            if sym == lib_symbol[1 if len(lib_symbol) == 2 else 2]:
                                dyn[sym] = lib

    return dyn
