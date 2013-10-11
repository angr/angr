#!/usr/bin/env python

import os
import pysex
import idalink
import z3
import subprocess
import sys
import logging
import binary
import shutil
import names
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
    l.debug("MEM: Lowest addr: %d, Highest addr: %d" %(min(mem.get_addresses()), max(mem.get_addresses())))
    return mem

# TODO relocating everything, start variable has this purpose!
def link_and_load(ida, mem, start=0):
    dst = z3.BitVec('dst', mem.get_bit_address())
    lib_name = os.path.realpath(os.path.expanduser(ida.get_filename())).split("/")[-1]
    l.debug("Loading Binary: %s, instructions: #%d" %(lib_name, len(ida.mem.keys())))

    # dynamic stuff
    bin_names = names.Names(ida)

    #load everything
    for addr in ida.mem.keys():
        sym_name = bin_names.get_name_by_addr(addr)
        cnt = ida.mem[addr]
        if sym_name and bin_names.get_type(sym_name) == 'E':
            extrnlib_name = bin_names.get_extrn_lib_name(sym_name)
            if extrnlib_name not in loaded_libs.keys():
                ## REMOVE WHEN READY ###
                if "libc" in extrnlib_name:
                    l.debug("Skipping LibC")
                    # add fake pointer to libc!!!!
                    continue
                #########################
                ida_bin = binary.Binary(get_tmp_fs_copy(bin_names.get_extrn_fs_path(sym_name))).ida
                link_and_load(ida_bin, mem)
            ##change address!
            cnt = loaded_libs[bin_names.get_extrn_lib_name(sym_name)].get_addr(sym_name)

        mem.store(dst, z3.BitVecVal(cnt, 8), [dst == addr], 5)

    loaded_libs[lib_name] = bin_names
    l.debug("Loaded into memory binary: %s" % lib_name)

    return
