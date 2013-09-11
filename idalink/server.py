#!/usr/bin/env python

import idc
print idc.ARGV

if len(idc.ARGV) > 1:
	port = int(idc.ARGV[1])
else:
	port = 18861

from rpyc.core import SlaveService
#from rpyc.utils.server import ThreadedServer
from rpyc.utils.server import OneShotServer

idc.Wait()
OneShotServer(SlaveService, port = port).start()
idc.Exit(0)
