import dpkt

import logging
l = logging.getLogger("simuvex.s_pcap")


class Pcap(object):
	
	def __init__(self,path, ip_port_tup):
		self.path = path
		self.pos = 0
		self.in_streams = []
		self.out_streams = []
		self.initialize(self.path)
		self.ip = ip_port_tup[0]
		self.port= ip_port_tup[1]
		
		
	def initialize(path):
		import ipdb;ipdb.set_trace()
		f = open(path)
		pcap = dpkt.pcap.Reader(f)
		for ts,buf in pcap:
			#data = dpkt.ethernet.Ethernet(buf).ip.data.data
			ip = dpkt.ethernet.Ethernet(buf).ip
			tcp = ip.data
			if ip.data.dst is self.ip and tcp.dport is self.port:
				in_streams.append((len(tcp.data),tcp.data))
			else:
				out_streams.append((len(tcp.data),tcp.data))
						
		
		
