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
import ipdb

logging.basicConfig()
l = logging.getLogger("loader")
l.setLevel(logging.DEBUG)

loaded_libs = {}
default_offset = 10240 #10k
bit_sys = 64
sc_addr  = 0
ec_addr = 0

def get_tmp_fs_copy(src_filename):
    dst_filename = "/tmp/" + src_filename.split("/")[-1]
    shutil.copyfile(src_filename, dst_filename)

    return dst_filename


# for the moment binaries are relocated handly
def load_binary(ida):
    global sc_addr
    global ec_addr

    text_mem = {}
    loaded_libs[ida.get_filename()] = {}
    sc_addr = min(ida.mem.keys())
    ec_addr = max(ida.mem.keys())
    link_and_load(ida, text_mem)
    return pysex.s_memory.Memory(initial=[text_mem, 5], sys=bit_sys)

# TODO relocating everything, start variable serves this purpose!
# FIXME: think about cases when binary has really low addressing space (even though it should not ever happen)
def link_and_load(ida, mem, rebase=0, start=0, bit_addr=bit_sys, max_cnt=2**bit_sys):
    global sc_addr
    global ec_addr

    dst = z3.BitVec('dst', bit_addr)

    lib_name = os.path.realpath(os.path.expanduser(ida.get_filename())).split("/")[-1]

    if rebase:
        #FIXME
        seg = list(ida.idautils.Segments())
        real_delta = start - ida.idc.SegStart(seg[0])
        real_delta += (real_delta % 2)
        res = ida.idaapi.rebase_program(real_delta, ida.idaapi.MSF_FIXONCE | ida.idaapi.MSF_LDKEEP)
        # ida.mem.clear_cache() # we have relocated everything, the cache is no longer valid

    l.debug("Loading Binary: %s" %(lib_name))

    # dynamic stuff    
    bin_names = names.Names(ida)
    l.info("Names loaded")

    #load everything
    for addr in ida.idautils.Heads():
        cnt = ida.idaapi.get_byte(addr)
        sym_name = bin_names.get_name_by_addr(addr)
        size = 8
        if sym_name and bin_names[sym_name].ntype == 'E':
            extrnlib_name = bin_names[sym_name].extrn_lib_name

            if extrnlib_name not in loaded_libs.keys():
                l.info("got external lib %s" %extrnlib_name)
                ida_bin = binary.Binary(get_tmp_fs_copy(bin_names[sym_name].extrn_fs_path)).ida
                seg = list(ida_bin.idautils.Segments())
                min_addr_bin = ida_bin.idc.SegStart(seg[0])
                max_addr_bin = ida_bin.idc.SegEnd(seg[-1])
                start_bin_addr = (min_addr_bin - (max_addr_bin + default_offset - sc_addr)) #& 0x1000
                l.info("Calculating reallocation addresses")
                # FIXE ME: calculate here real_delta and check if negative! In this case the rebase thing
                # does not work
                # updating global addresses and get the relocated address
                if start_bin_addr >= 0:
                    sc_addr = start_bin_addr
                    l.info("Binary %s will be allocated above the other libraries" %ida_bin.get_filename())
                else:
                    start_bin_addr = (ec_addr + default_offset) #& 0x1000
                    ec_addr = (max_addr_bin - min_addr_bin) + start_bin_addr
                    l.info("Binary %s will be allocated below the other libraries" %ida_bin.get_filename())
                    assert ec_addr <= max_cnt, "Memory is full!"

                link_and_load(ida_bin, mem, 1, start_bin_addr)

            ## got EXTRN change address!
            cnt = loaded_libs[bin_names[sym_name].extrn_lib_name][sym_name].addr
            size = ida.idautils.DecodeInstruction(addr).size * 8
            assert  size >= cnt.bit_length(), "Address inexpectedly too long"

        store_text(mem, addr, z3.BitVecVal(cnt, size))
        

    loaded_libs[lib_name] = bin_names
    l.debug("Loaded into memory binary: %s" % lib_name)
    return

def store_text(mem, addr, cnt):
    for off in range(0, cnt.size() / 8):
        cell = pysex.s_memory.Cell(5, z3.Extract((off << 3) + 7, (off << 3), cnt))
        mem[(addr + off)] = cell
