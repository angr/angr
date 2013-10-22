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
import collections

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

def link_and_load(ida, mem, delta=0, bit_addr=bit_sys, max_cnt=2**bit_sys):
    global sc_addr
    global ec_addr

    lib_name = os.path.realpath(os.path.expanduser(ida.get_filename())).split("/")[-1]

    if delta:
        res = ida.idaapi.rebase_program(delta, ida.idaapi.MSF_FIXONCE | ida.idaapi.MSF_LDKEEP)
        ida.mem.clear_cache() # we have relocated everything, the cache is no longer valid

    l.debug("Loading Binary: %s" %(lib_name))

    # dynamic stuff
    bin_names = names.Names(ida)
    l.info("Names loaded")

    # Binary loading
    mem.update({item[0]:pysex.s_memory.Cell(5, z3.BitVecVal(ord(item[1]), 8)) for item in ida.mem.iteritems()})

    # link solving
    for sym_name in bin_names.keys():
        if sym_name and bin_names[sym_name].ntype == 'E':
            extrnlib_name = bin_names[sym_name].extrn_lib_name

            if extrnlib_name not in loaded_libs.keys():
                l.info("got external lib %s" %extrnlib_name)
                ida_bin = binary.Binary(get_tmp_fs_copy(bin_names[sym_name].extrn_fs_path)).ida

                # get min and max addr. The segment dictionary is ordered for constructioning
                min_addr_bin = ida_bin.mem.segments().iteritems().next()
                min_addr_bin = min_addr_bin[0]
                for max_addr_bin in ida_bin.mem.segments().iteritems():
                    pass
                max_addr_bin = max_addr_bin[0] + max_addr_bin[1]

                l.info("Calculating rebasing address")
                # new address is expressed as delta for the IDA rebase function
                new_start_bin = ((min_addr_bin - (max_addr_bin + default_offset - sc_addr)))
                delta = new_start_bin - min_addr_bin

                if delta >= 0:
                    sc_addr = new_start_bin
                    l.info("Binary %s will be allocated above the other libraries" % ida_bin.get_filename())
                else: # we have to change it, IDA does not manage negative deltas
                    new_start_bin = (ec_addr + default_offset)
                    ec_addr = (max_addr_bin - min_addr_bin) + new_start_bin
                    delta = new_start_bin - min_addr_bin
                    l.info("Binary %s will be allocated below the other libraries" % ida_bin.get_filename())

                    assert ec_addr <= max_cnt, "Memory is full!"
                delta += (delta % 2)
                link_and_load(ida_bin, mem, delta)

            cnt = loaded_libs[bin_names[sym_name].extrn_lib_name][sym_name].addr
            size = ida.idautils.DecodeInstruction(bin_names[sym_name].addr).size * 8
            assert  size >= cnt.bit_length(), "Address inexpectedly too long"
            # link!
            store_text(mem, bin_names[sym_name].addr, z3.BitVecVal(cnt, size))

    loaded_libs[lib_name] = bin_names
    l.debug("Loaded into memory binary: %s" % lib_name)
    return

def store_text(mem, addr, cnt):
    for off in range(0, cnt.size() / 8):
        cell = pysex.s_memory.Cell(5, z3.Extract((off << 3) + 7, (off << 3), cnt))
        mem[(addr + off)] = cell
