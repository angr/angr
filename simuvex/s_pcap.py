import dpkt
import socket
import logging
l = logging.getLogger("simuvex.s_pcap")


class Pcap(object):
	
	def __init__(self,path, ip_port_tup):
		self.path = path
		self.packet_num = 0
		self.pos = 0
		self.in_streams = []
		self.out_streams = []
		self.ip = ip_port_tup[0]
		self.port = ip_port_tup[1]
		self.initialize(self.path)
		
		self.wtf = 'wtf'
		
	
	def initialize(self,path):
		#import ipdb;ipdb.set_trace()
		f = open(path)
		pcap = dpkt.pcap.Reader(f)
		for ts,buf in pcap:
			#data = dpkt.ethernet.Ethernet(buf).ip.data.data
			ip = dpkt.ethernet.Ethernet(buf).ip
			tcp = ip.data
			myip = socket.inet_ntoa(ip.dst)
			if myip is self.ip and tcp.dport is self.port and len(tcp.data) is not 0:
				self.out_streams.append((len(tcp.data),tcp.data))
			elif len(tcp.data) is not 0:
				self.in_streams.append((len(tcp.data),tcp.data))						
		f.close()
		import ipdb;ipdb.set_trace()

		
		
