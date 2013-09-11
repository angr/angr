#!/usr/bin/env python

import subprocess
import logging
import rpyc
import os
import standard_logging

l = logging.getLogger("idalink")
l.setLevel(logging.INFO)
script_dir = os.path.dirname(os.path.realpath(__file__))

def spawn_ida(filename, port):
	fullpath = os.path.realpath(os.path.expanduser(filename))
	l.info("Launching IDA on %s" % fullpath)
	subprocess.call([ "screen", "-d", "-m", "--", script_dir + "/run_ida.sh", fullpath, script_dir + "/ida.log", script_dir + "/server.py", str(port) ])

def connect_ida(port):
	global ida, idc, idaapi, idautils

	ida = rpyc.classic.connect("localhost", port)
	
	idc = ida.root.getmodule("idc")
	idaapi = ida.root.getmodule("idaapi")
	idautils = ida.root.getmodule("idautils")
