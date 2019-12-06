import dpkt
import socket
import logging
l = logging.getLogger(name=__name__)


class PCAP(object):
    def __init__(self,path, ip_port_tup, init=True):
        self.path = path
        self.packet_num = 0
        self.pos = 0
        self.in_streams = []
        self.out_streams = []
        #self.in_buf = ''
        self.ip = ip_port_tup[0]
        self.port = ip_port_tup[1]
        if init:
            self.initialize(self.path)

    def initialize(self,path):
        f = open(path)
        pcap = dpkt.pcap.Reader(f)
        for _,buf in pcap:
            #data = dpkt.ethernet.Ethernet(buf).ip.data.data
            ip = dpkt.ethernet.Ethernet(buf).ip
            tcp = ip.data
            myip = socket.inet_ntoa(ip.dst)
            if myip is self.ip and tcp.dport is self.port and len(tcp.data) is not 0:
                self.out_streams.append((len(tcp.data),tcp.data))
            elif len(tcp.data) is not 0:
                self.in_streams.append((len(tcp.data),tcp.data))
        f.close()

    def recv(self, length):
        temp = 0
        #pcap = self.pcap
        initial_packet = self.packet_num
        plength, pdata = self.in_streams[self.packet_num]
        length = min(length, plength)
        if self.pos is 0:
            if plength > length:
                temp = length
            else:
                self.packet_num += 1

            packet_data = pdata[self.pos:length]
            self.pos += temp
        else:
            if (self.pos + length) >= plength:
                rest = plength-self.pos
                length = rest
                self.packet_num += 1

            packet_data = pdata[self.pos:plength]

        if self.packet_num is not initial_packet:
            self.pos = 0
        return packet_data, length

    def copy(self):
        new_pcap = PCAP(self.path, (self.ip, self.port), init=False)
        new_pcap.packet_num = self.packet_num
        new_pcap.pos = self.pos
        new_pcap.in_streams = self.in_streams
        new_pcap.out_streams = self.out_streams
        return new_pcap
