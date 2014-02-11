#!/usr/bin/env python

import pyvex
import idalink
import sys
import logging
l = logging.getLogger("toir")
l.setLevel(logging.DEBUG)

#import standard_logging


def block_to_vex(start, end):
    if start == end:
        l.warning("... skipping empty block starting at %x" % start)

    l.debug("... block: %x - %x" % (start, end))
    bytes = idalink.idaapi.get_many_bytes(start, end - start)
    l.debug("... bytes: %s" % repr(bytes))
    irsb = pyvex.IRSB(bytes=bytes)
    l.debug("... IRSB has %d statements", len(irsb.statements()))


def function_to_vex(func_addr):
    vex_blocks = {}

    f = idalink.idaapi.FlowChart(idalink.idaapi.get_func(func_addr))
    for block in f:
        start, end = (block.startEA, block.endEA)
        vex_blocks[(start, end)] = block_to_vex(start, end)

if __name__ == '__main__':
    target = sys.argv[1]
    idalink.make_idalink(target)

    for f in idalink.idautils.Functions():
        print "FUNCTION: %x" % f
        function_to_vex(f)
