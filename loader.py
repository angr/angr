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

logging.basicConfig()
l = logging.getLogger("loader")
l.setLevel(logging.DEBUG)

loaded_libs = {}
default_offset = 10240 #10k


def get_tmp_fs_copy(src_filename):
    dst_filename = "/tmp/" + src_filename.split("/")[-1]
    shutil.copyfile(src_filename, dst_filename)

    return dst_filename


# for the moment binaries are relocated handly
def load_binary(ida):
    mem = pysex.s_memory.Memory()
    loaded_libs[ida.get_filename()] = {}
    link_and_load(ida, mem)
    l.debug("MEM: Lowest addr: %d, Highest addr: %d" %(min(mem.get_addresses()), max(mem.get_addresses())))
    return mem

# TODO relocating everything, start variable serves this purpose!
def link_and_load(ida, mem, rebase=0, start=0):
    dst = z3.BitVec('dst', mem.get_bit_address())
    lib_name = os.path.realpath(os.path.expanduser(ida.get_filename())).split("/")[-1]
    l.debug("Loading Binary: %s, instructions: #%d" %(lib_name, len(ida.mem.keys())))

    if rebase:
        real_start = min(ida.mem.keys()) + start
        ida.idaapi.rebase_program(real_start, ida.idaapi.MSF_FIXONCE | ida.idaapi.MSF_LDKEEP)

    # dynamic stuff
    bin_names = names.Names(ida)

    #load everything
    for addr in ida.mem.keys():
        sym_name = bin_names.get_name_by_addr(addr)
        cnt = ida.mem[addr]
        size = 8
        if sym_name and bin_names[sym_name].ntype == 'E':
            extrnlib_name = bin_names[sym_name].extrn_lib_name
            REMOVE WHEN READY ###
            if "libc" in extrnlib_name:
                l.debug("Skipping LibC")
                continue
             
            if extrnlib_name not in loaded_libs.keys():
                ida_bin = binary.Binary(get_tmp_fs_copy(bin_names[sym_name].extrn_fs_path)).ida
                start_current = min(ida.mem.keys())
                size_bin = len(ida_bin.mem)
                link_and_load(ida_bin, mem, 1, (((start_current - (default_offset + size_bin)) % mem.get_max()) & 0x1000)
            ## got EXTRN change address!
            cnt = loaded_libs[bin_names[sym_name].extrn_lib_name][sym_name].addr
            size = ida.idautils.DecodeInstruction(addr).size * 8
            assert  size >= cnt.bit_length(), "Address inexpectedly too long"

        mem.store(dst, z3.BitVecVal(cnt, size), [dst == addr], 5)

    loaded_libs[lib_name] = bin_names
    l.debug("Loaded into memory binary: %s" % lib_name)

    return

def get_addr_jmp(ida, addr):
    jmp_addr = addr
    while True:
        addr = [x for x in ida.idautils.DataRefsTo(addr)]
        if not addr:
            break
        jmp_addr = addr[0]
        addr = jmp_addr
    return jmp_addr
