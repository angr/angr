#!/usr/bin/env python

from __future__ import division #floating point division
import os
import pysex
import idalink
import z3
import subprocess
import sys
import logging
import binary
import shutil
import binary_info
import collections
import math

import ipdb

logging.basicConfig()
l = logging.getLogger("loader")
l.setLevel(logging.DEBUG)

loaded_bin = {}
default_offset = 1024 #10k
bit_sys = 64
sc_addr  = 0
ec_addr = 0
granularity = 0x10000

def get_tmp_fs_copy(src_filename):
    dst_filename = "/tmp/" + src_filename.split("/")[-1]
    shutil.copyfile(src_filename, dst_filename)
    return dst_filename


def load_binary(ida):
    global sc_addr
    global ec_addr

    sc_addr = ida.idautils.Segments().next()
    start = sc_addr
    for ec_addr in ida.idautils.Segments():
        pass
    ec_addr = ida.idc.SegEnd(ec_addr)
    link_and_load(ida)

    return pysex.s_memory.Memory(infobin=loaded_bin, sys=bit_sys), start

def link_and_load(ida, delta=0):
    global sc_addr
    global ec_addr
    global loaded_bin

    bin_name = os.path.realpath(os.path.expanduser(ida.get_filename())).split("/")[-1]

    if delta:
        reb = ida.idaapi.rebase_program(delta, ida.idaapi.MSF_FIXONCE | ida.idaapi.MSF_LDKEEP)
        if reb != 0:
            l.error("rebase failed")
            ipdb.set_trace()

    # get used addresses
    lb = ida.idautils.Segments().next()
    for ub in ida.idautils.Segments():
        pass
    ub = ida.idc.SegEnd(ub)

    l.debug("Loading Binary: %s" %bin_name)
    # dynamic stuff
    binfo = binary_info.BinInfo(ida)
    binfo.set_range_addr([lb, ub])

    # link solving
    for sym_name in binfo.keys():
        if sym_name and binfo[sym_name].ntype == 'E':

            extrnlib_name = binfo[sym_name].extrn_lib_name
            if extrnlib_name not in loaded_bin.keys():
                ida_bin = binary.Binary(get_tmp_fs_copy(binfo[sym_name].extrn_fs_path)).ida
                delta = rebase_lib(ida_bin)
                link_and_load(ida_bin, delta)

    loaded_bin[bin_name] = binfo
    l.debug("Loaded into memory binary: %s" % bin_name)
    return

def rebase_lib(ida, max_cnt=2**bit_sys):
    global sc_addr
    global ec_addr

    # get min and max addr. The segment dictionary is ordered for constructioning
    min_addr_bin = ida.idautils.Segments().next()
    for max_addr_bin in ida.idautils.Segments():
        pass
    max_addr_bin = ida.idc.SegEnd(max_addr_bin)

    l.debug("Calculating rebasing address of %s" %ida.get_filename())

    # new address is expressed as delta for the IDA rebase function
    new_start_bin = int(granularity*math.floor(((min_addr_bin - (max_addr_bin + default_offset - sc_addr))) / granularity))
    if new_start_bin >= 0:
        l.debug("Binary %s will be allocated above the other libraries" % ida.get_filename())
        sc_addr = new_start_bin
    else:
        l.debug("Binary %s will be allocated below the other libraries" % ida.get_filename())
        new_start_bin = int(granularity*math.ceil((ec_addr + default_offset) / granularity))
        ec_addr = (new_start_bin - min_addr_bin) + max_addr_bin
        assert ec_addr <= max_cnt, "Memory is full!"

    delta = new_start_bin - min_addr_bin
    delta += (delta % 2)
    return delta
