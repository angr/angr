from .s_memory import SimMemory
from .s_exception import SimMergeError
import symexec as se
import dpkt

import logging
l = logging.getLogger("simuvex.s_pcap")


class Pcap(object):
	
	def __init(path)__:
		self.path = path
		self.pos = 0
		self.info = []
		self.handle_data(self.path)
		
		
	def handle_data(path):
		f = open(path)
		pcap = dpkt.pcap.Reader(f)
		
		
