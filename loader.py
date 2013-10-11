#!/usr/bin/env python

import pysex
import idalink
import z3
import subprocess
import sys
import logging
import binary
import shutil
import names

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
    filename = ida.get_filename()

    l.debug("Loading Binary: %s, instructions: #%d" %(filename, len(ida.mem.keys())))

    # dynamic stuff
    syms = names.Names(ida)

    #load everything
    for addr in ida.mem.keys():
        sym = syms.get_name_by_addr(addr)
        if sym and syms.get_type(sym) == 'E':
            ida_bin = binary.Binary(get_tmp_fs_copy(syms.get_fs_path(sym))).ida

            ## REMOVE WHEN READY ###
            if "libc" in ida_bin.get_filename():
                l.debug("Skipping LibC")
                # add fake pointer to libc!!!!
                continue
            #########################
            link_and_load(ida_bin, mem)
        mem.store(dst, z3.BitVecVal(ida.mem[addr], 8), [dst == addr], 5)

    loaded_libs[filename][]
    l.debug("Loaded into memory binary: %s" % filename)

    return
