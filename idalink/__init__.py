#!/usr/bin/env python

import time
import random
import subprocess
import logging
import rpyc
import os
import standard_logging

l = logging.getLogger("idalink")
l.setLevel(logging.DEBUG)

# various locations
module_dir = os.path.dirname(os.path.realpath(__file__))
log_file = module_dir + "/ida.log"
ida_script = module_dir + "/run_ida.sh"
ida_dir = module_dir

def spawn_ida(filename, port):
	fullpath = os.path.realpath(os.path.expanduser(filename))
	l.info("Launching IDA on %s" % fullpath)
	subprocess.call([ "screen", "-d", "-m", "--", ida_script, ida_dir, fullpath, log_file, module_dir + "/server.py", str(port) ])

def connect_ida(port):
	global ida, idc, idaapi, idautils

	ida = rpyc.classic.connect("localhost", port)
	
	idc = ida.root.getmodule("idc")
	idaapi = ida.root.getmodule("idaapi")
	idautils = ida.root.getmodule("idautils")

def make_idalink(filename):
	port = random.randint(40000, 49999)
	spawn_ida(filename, port)

	while True:
		try:
			time.sleep(1)
			l.debug("Trying to connect to IDA on port %d" % port)
			connect_ida(port)
			break
		except Exception:
			l.debug("... failed. Retrying.")
