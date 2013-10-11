#!/usr/bin/env python

import pysex
import idalink
import z3
import subprocess
import sys
import logging
import binary
import shutil
from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection, DynamicSegment
from elftools.common.py3compat import bytes2str
import pdb

logging.basicConfig()
l = logging.getLogger("loader")
l.setLevel(logging.DEBUG)

loaded_libs = {}
default_offset = 1024

def get_tmp_fs_copy(src_filename):
    dst_filename = "/tmp/" + src_filename.split("/")[-1]
    shutil.copyfile(src_filename, dst_filename)

    return dst_filename

# for the moment binaries are relocated handly
def load_binary(ida):
    mem = pysex.s_memory.Memory()
    loaded_libs[ida.get_filename()] = {}
    link_and_load(ida, mem, 0)
    l.debug("MEM: Lower addr: %d, Higher addr: %d" %(min(mem.get_addresses()), max(mem.get_addresses())))

    return mem


def link_and_load(ida, mem, start=0):
    dst = z3.BitVec('dst', mem.get_bit_address())
    filename = ida.get_filename()
    rel_addr = start

    l.debug("Loading Binary: %s, size: %d" %(filename, len(ida.mem.keys())))

    # dynamic stuff
    names = get_local_defined_symbols(filename)
    d_obj = match_externOBJ(ida.get_filename())
    addr_d_obj = get_addresses(d_obj, ida)

    # static stuff
    for addr in ida.mem.keys():
        if addr in addr_d_obj.keys():
            ida_bin = binary.Binary(get_tmp_fs_copy(d_obj[addr_d_obj[addr]])).ida

            ## REMOVE WHEN READY ###
            if "libc" in ida_bin.get_filename():
                l.debug("Skipping LibC")
                # add fake pointer to libc!!!!
                continue
            #########################
            link_and_load(ida_bin, mem, start + len(ida.mem.keys()) + default_offset)
        #        loaded_ilibs[filename][]
        mem.store(dst, z3.BitVecVal(ida.mem[addr], 8), [dst == rel_addr], 5)
        rel_addr += 1


    l.debug("Loaded into memory binary: %s" % ida.get_filename())
    l.debug("File: %s" %filename)
    l.debug("Lower addr: %d, Higher addr: %d" %(start, rel_addr))
    return


def load_ELF(mem, filename):
    elf_file = ELFFile(open(filename, "rb"))

    for section in elf_file.iter_sections():
        if not isinstance(section, DynamicSection):
            continue

        for tag in section.iter_tags():
            if tag.entry.d_tag == 'DT_NEEDED':
                l.info("Shared library: [%s]" % bytes2str(tag.needed))

def get_addresses(d_obj, ida):
    addr_d_obj = {}
    for sym in d_obj.keys():
        # store the symbols according their address
        addr_d_obj[ida.mem.get_name_addr(sym)[0]] = sym
    return addr_d_obj

# o.s. has to provide "nm" and "ldd" commands
def match_externOBJ(filename):
    p_nm = subprocess.Popen(["nm", "-D", filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result_nm = p_nm.stdout.readlines()
    p_ldd = subprocess.Popen(["ldd", filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result_ldd = p_ldd.stdout.readlines()
    dyn = {}

    l.debug("Resolving external functions of %s" %filename)

    for nm_out in result_nm:
        sym_entry = nm_out.split()
        if len(sym_entry) >= 2 and sym_entry[0 if len(sym_entry) == 2 else 1] == "U":
            sym = sym_entry[1 if len(sym_entry) == 2 else 2]
            found = False
            for lld_out in result_ldd:
                lib_entry = lld_out.split()
                if ("=>" in lld_out and len(lib_entry) != 3) or len(lib_entry) == 2: # skipping virtual libraries
                    lib = lib_entry[2 if "=>" in lld_out else 0]
                    ls_nm = subprocess.Popen(["nm", "-D", lib], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    result_lsnm = ls_nm.stdout.readlines()
                    for ls_nm_out in result_lsnm:
                        lib_symbol = ls_nm_out.split()
                        if len(lib_symbol) >= 2 and lib_symbol[0 if len(lib_symbol) == 2 else 1] not in "UN?":
                            if sym == lib_symbol[1 if len(lib_symbol) == 2 else 2]:
                                dyn[sym] = lib
                                found = True
            if found == False:
                l.error("Extern function has not been matched with a valid shared libraries. Symbol:")
                pdb.set_trace()

    return dyn

def get_local_defined_symbols(filename):
    p_ls = subprocess.Popen(["nm", "-D", filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result_ls = p_ls.stdout.readlines()
    sym = []
    for ls_out in result_ls:
        lib_symbol = ls_out.split()
        if len(lib_symbol) >= 2 and lib_symbol[0 if len(lib_symbol) == 2 else 1] not in "UN?":
            sym.append(lib_symbol[1 if len(lib_symbol) == 2 else 2])

    return sym
