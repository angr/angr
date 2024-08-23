# pylint:disable=line-too-long
from __future__ import annotations
import logging
from collections import OrderedDict

from ...sim_type import (SimTypeFunction,
    SimTypeShort,
    SimTypeInt,
    SimTypeLong,
    SimTypeLongLong,
    SimTypeDouble,
    SimTypeFloat,
    SimTypePointer,
    SimTypeChar,
    SimStruct,
    SimTypeArray,
    SimTypeBottom,
    SimUnion,
    SimTypeBool,
    SimTypeRef,
)
from ...calling_conventions import SimCCStdcall, SimCCMicrosoftAMD64
from .. import SIM_PROCEDURES as P
from . import SimLibrary


_l = logging.getLogger(name=__name__)


lib = SimLibrary()
lib.type_collection_names = ["win32"]
lib.set_default_cc("X86", SimCCStdcall)
lib.set_default_cc("AMD64", SimCCMicrosoftAMD64)
lib.set_library_names("iphlpapi.dll")
prototypes = \
    {
        #
        'IcmpCreateFile': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'Icmp6CreateFile': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'IcmpCloseHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["IcmpHandle"]),
        #
        'IcmpSendEcho': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("IP_OPTION_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["IcmpHandle", "DestinationAddress", "RequestData", "RequestSize", "RequestOptions", "ReplyBuffer", "ReplySize", "Timeout"]),
        #
        'IcmpSendEcho2': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["ApcContext", "IoStatusBlock", "Reserved"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("IP_OPTION_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["IcmpHandle", "Event", "ApcRoutine", "ApcContext", "DestinationAddress", "RequestData", "RequestSize", "RequestOptions", "ReplyBuffer", "ReplySize", "Timeout"]),
        #
        'IcmpSendEcho2Ex': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["ApcContext", "IoStatusBlock", "Reserved"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("IP_OPTION_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["IcmpHandle", "Event", "ApcRoutine", "ApcContext", "SourceAddress", "DestinationAddress", "RequestData", "RequestSize", "RequestOptions", "ReplyBuffer", "ReplySize", "Timeout"]),
        #
        'Icmp6SendEcho2': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IO_STATUS_BLOCK", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["ApcContext", "IoStatusBlock", "Reserved"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("SOCKADDR_IN6", SimStruct), offset=0), SimTypePointer(SimTypeRef("SOCKADDR_IN6", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("IP_OPTION_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["IcmpHandle", "Event", "ApcRoutine", "ApcContext", "SourceAddress", "DestinationAddress", "RequestData", "RequestSize", "RequestOptions", "ReplyBuffer", "ReplySize", "Timeout"]),
        #
        'IcmpParseReplies': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ReplyBuffer", "ReplySize"]),
        #
        'Icmp6ParseReplies': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ReplyBuffer", "ReplySize"]),
        #
        'GetNumberOfInterfaces': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pdwNumIf"]),
        #
        'GetIfEntry': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IFROW", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pIfRow"]),
        #
        'GetIfTable': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IFTABLE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pIfTable", "pdwSize", "bOrder"]),
        #
        'GetIpAddrTable': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPADDRTABLE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pIpAddrTable", "pdwSize", "bOrder"]),
        #
        'GetIpNetTable': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPNETTABLE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["IpNetTable", "SizePointer", "Order"]),
        #
        'GetIpForwardTable': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPFORWARDTABLE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pIpForwardTable", "pdwSize", "bOrder"]),
        #
        'GetTcpTable': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_TCPTABLE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["TcpTable", "SizePointer", "Order"]),
        #
        'GetExtendedTcpTable': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="TCP_TABLE_CLASS"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pTcpTable", "pdwSize", "bOrder", "ulAf", "TableClass", "Reserved"]),
        #
        'GetOwnerModuleFromTcpEntry': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_TCPROW_OWNER_MODULE", SimStruct), offset=0), SimTypeInt(signed=False, label="TCPIP_OWNER_MODULE_INFO_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pTcpEntry", "Class", "pBuffer", "pdwSize"]),
        #
        'GetUdpTable': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_UDPTABLE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["UdpTable", "SizePointer", "Order"]),
        #
        'GetExtendedUdpTable': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UDP_TABLE_CLASS"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pUdpTable", "pdwSize", "bOrder", "ulAf", "TableClass", "Reserved"]),
        #
        'GetOwnerModuleFromUdpEntry': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_UDPROW_OWNER_MODULE", SimStruct), offset=0), SimTypeInt(signed=False, label="TCPIP_OWNER_MODULE_INFO_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pUdpEntry", "Class", "pBuffer", "pdwSize"]),
        #
        'GetTcpTable2': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_TCPTABLE2", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["TcpTable", "SizePointer", "Order"]),
        #
        'GetTcp6Table': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_TCP6TABLE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["TcpTable", "SizePointer", "Order"]),
        #
        'GetTcp6Table2': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_TCP6TABLE2", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["TcpTable", "SizePointer", "Order"]),
        #
        'GetPerTcpConnectionEStats': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_TCPROW_LH", SimStruct), offset=0), SimTypeInt(signed=False, label="TCP_ESTATS_TYPE"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Row", "EstatsType", "Rw", "RwVersion", "RwSize", "Ros", "RosVersion", "RosSize", "Rod", "RodVersion", "RodSize"]),
        #
        'SetPerTcpConnectionEStats': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_TCPROW_LH", SimStruct), offset=0), SimTypeInt(signed=False, label="TCP_ESTATS_TYPE"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Row", "EstatsType", "Rw", "RwVersion", "RwSize", "Offset"]),
        #
        'GetPerTcp6ConnectionEStats': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_TCP6ROW", SimStruct), offset=0), SimTypeInt(signed=False, label="TCP_ESTATS_TYPE"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Row", "EstatsType", "Rw", "RwVersion", "RwSize", "Ros", "RosVersion", "RosSize", "Rod", "RodVersion", "RodSize"]),
        #
        'SetPerTcp6ConnectionEStats': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_TCP6ROW", SimStruct), offset=0), SimTypeInt(signed=False, label="TCP_ESTATS_TYPE"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Row", "EstatsType", "Rw", "RwVersion", "RwSize", "Offset"]),
        #
        'GetOwnerModuleFromTcp6Entry': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_TCP6ROW_OWNER_MODULE", SimStruct), offset=0), SimTypeInt(signed=False, label="TCPIP_OWNER_MODULE_INFO_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pTcpEntry", "Class", "pBuffer", "pdwSize"]),
        #
        'GetUdp6Table': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_UDP6TABLE", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Udp6Table", "SizePointer", "Order"]),
        #
        'GetOwnerModuleFromUdp6Entry': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_UDP6ROW_OWNER_MODULE", SimStruct), offset=0), SimTypeInt(signed=False, label="TCPIP_OWNER_MODULE_INFO_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pUdpEntry", "Class", "pBuffer", "pdwSize"]),
        #
        'GetOwnerModuleFromPidAndInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypeInt(signed=False, label="TCPIP_OWNER_MODULE_INFO_CLASS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ulPid", "pInfo", "Class", "pBuffer", "pdwSize"]),
        #
        'GetIpStatistics': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPSTATS_LH", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Statistics"]),
        #
        'GetIcmpStatistics': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_ICMP", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Statistics"]),
        #
        'GetTcpStatistics': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_TCPSTATS_LH", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Statistics"]),
        #
        'GetUdpStatistics': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_UDPSTATS", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Stats"]),
        #
        'SetIpStatisticsEx': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPSTATS_LH", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Statistics", "Family"]),
        #
        'GetIpStatisticsEx': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPSTATS_LH", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Statistics", "Family"]),
        #
        'GetIcmpStatisticsEx': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_ICMP_EX_XPSP1", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Statistics", "Family"]),
        #
        'GetTcpStatisticsEx': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_TCPSTATS_LH", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Statistics", "Family"]),
        #
        'GetUdpStatisticsEx': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_UDPSTATS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Statistics", "Family"]),
        #
        'GetTcpStatisticsEx2': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_TCPSTATS2", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Statistics", "Family"]),
        #
        'GetUdpStatisticsEx2': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_UDPSTATS2", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Statistics", "Family"]),
        #
        'SetIfEntry': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IFROW", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pIfRow"]),
        #
        'CreateIpForwardEntry': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPFORWARDROW", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pRoute"]),
        #
        'SetIpForwardEntry': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPFORWARDROW", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pRoute"]),
        #
        'DeleteIpForwardEntry': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPFORWARDROW", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pRoute"]),
        #
        'SetIpStatistics': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPSTATS_LH", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pIpStats"]),
        #
        'SetIpTTL': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["nTTL"]),
        #
        'CreateIpNetEntry': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPNETROW_LH", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pArpEntry"]),
        #
        'SetIpNetEntry': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPNETROW_LH", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pArpEntry"]),
        #
        'DeleteIpNetEntry': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPNETROW_LH", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pArpEntry"]),
        #
        'FlushIpNetTable': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwIfIndex"]),
        #
        'CreateProxyArpEntry': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwAddress", "dwMask", "dwIfIndex"]),
        #
        'DeleteProxyArpEntry': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwAddress", "dwMask", "dwIfIndex"]),
        #
        'SetTcpEntry': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_TCPROW_LH", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pTcpRow"]),
        #
        'GetInterfaceInfo': SimTypeFunction([SimTypePointer(SimTypeRef("IP_INTERFACE_INFO", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pIfTable", "dwOutBufLen"]),
        #
        'GetUniDirectionalAdapterInfo': SimTypeFunction([SimTypePointer(SimTypeRef("IP_UNIDIRECTIONAL_ADAPTER_ADDRESS", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pIPIfInfo", "dwOutBufLen"]),
        #
        'NhpAllocateAndGetInterfaceInfoFromStack': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("IP_INTERFACE_NAME_INFO_W2KSP1", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ppTable", "pdwCount", "bOrder", "hHeap", "dwFlags"]),
        #
        'GetBestInterface': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwDestAddr", "pdwBestIfIndex"]),
        #
        'GetBestInterfaceEx': SimTypeFunction([SimTypePointer(SimTypeRef("SOCKADDR", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pDestAddr", "pdwBestIfIndex"]),
        #
        'GetBestRoute': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MIB_IPFORWARDROW", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwDestAddr", "dwSourceAddr", "pBestRoute"]),
        #
        'NotifyAddrChange': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Handle", "overlapped"]),
        #
        'NotifyRouteChange': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Handle", "overlapped"]),
        #
        'CancelIPChangeNotify': SimTypeFunction([SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["notifyOverlapped"]),
        #
        'GetAdapterIndex': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["AdapterName", "IfIndex"]),
        #
        'AddIPAddress': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Address", "IpMask", "IfIndex", "NTEContext", "NTEInstance"]),
        #
        'DeleteIPAddress': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["NTEContext"]),
        #
        'GetNetworkParams': SimTypeFunction([SimTypePointer(SimTypeRef("FIXED_INFO_W2KSP1", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["pFixedInfo", "pOutBufLen"]),
        #
        'GetAdaptersInfo': SimTypeFunction([SimTypePointer(SimTypeRef("IP_ADAPTER_INFO", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["AdapterInfo", "SizePointer"]),
        #
        'GetAdapterOrderMap': SimTypeFunction([], SimTypePointer(SimTypeRef("IP_ADAPTER_ORDER_MAP", SimStruct), offset=0)),
        #
        'GetAdaptersAddresses': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="GET_ADAPTERS_ADDRESSES_FLAGS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("IP_ADAPTER_ADDRESSES_LH", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Family", "Flags", "Reserved", "AdapterAddresses", "SizePointer"]),
        #
        'GetPerAdapterInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("IP_PER_ADAPTER_INFO_W2KSP1", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["IfIndex", "pPerAdapterInfo", "pOutBufLen"]),
        #
        'GetInterfaceActiveTimestampCapabilities': SimTypeFunction([SimTypePointer(SimUnion({"Value": SimTypeLongLong(signed=False, label="UInt64"), "Info": SimTypeRef("_Info_e__Struct", SimStruct)}, name="<anon>", label="None"), offset=0), SimTypePointer(SimTypeRef("INTERFACE_TIMESTAMP_CAPABILITIES", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["InterfaceLuid", "TimestampCapabilites"]),
        #
        'GetInterfaceSupportedTimestampCapabilities': SimTypeFunction([SimTypePointer(SimUnion({"Value": SimTypeLongLong(signed=False, label="UInt64"), "Info": SimTypeRef("_Info_e__Struct", SimStruct)}, name="<anon>", label="None"), offset=0), SimTypePointer(SimTypeRef("INTERFACE_TIMESTAMP_CAPABILITIES", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["InterfaceLuid", "TimestampCapabilites"]),
        #
        'CaptureInterfaceHardwareCrossTimestamp': SimTypeFunction([SimTypePointer(SimUnion({"Value": SimTypeLongLong(signed=False, label="UInt64"), "Info": SimTypeRef("_Info_e__Struct", SimStruct)}, name="<anon>", label="None"), offset=0), SimTypePointer(SimTypeRef("INTERFACE_HARDWARE_CROSSTIMESTAMP", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["InterfaceLuid", "CrossTimestamp"]),
        #
        'RegisterInterfaceTimestampConfigChange': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallerContext"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Callback", "CallerContext", "NotificationHandle"]),
        #
        'UnregisterInterfaceTimestampConfigChange': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["NotificationHandle"]),
        #
        'GetInterfaceCurrentTimestampCapabilities': SimTypeFunction([SimTypePointer(SimUnion({"Value": SimTypeLongLong(signed=False, label="UInt64"), "Info": SimTypeRef("_Info_e__Struct", SimStruct)}, name="<anon>", label="None"), offset=0), SimTypePointer(SimTypeRef("INTERFACE_TIMESTAMP_CAPABILITIES", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["InterfaceLuid", "TimestampCapabilites"]),
        #
        'GetInterfaceHardwareTimestampCapabilities': SimTypeFunction([SimTypePointer(SimUnion({"Value": SimTypeLongLong(signed=False, label="UInt64"), "Info": SimTypeRef("_Info_e__Struct", SimStruct)}, name="<anon>", label="None"), offset=0), SimTypePointer(SimTypeRef("INTERFACE_TIMESTAMP_CAPABILITIES", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["InterfaceLuid", "TimestampCapabilites"]),
        #
        'NotifyIfTimestampConfigChange': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallerContext"]), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["CallerContext", "Callback", "NotificationHandle"]),
        #
        'CancelIfTimestampConfigChange': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["NotificationHandle"]),
        #
        'IpReleaseAddress': SimTypeFunction([SimTypePointer(SimTypeRef("IP_ADAPTER_INDEX_MAP", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["AdapterInfo"]),
        #
        'IpRenewAddress': SimTypeFunction([SimTypePointer(SimTypeRef("IP_ADAPTER_INDEX_MAP", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["AdapterInfo"]),
        #
        'SendARP': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["DestIP", "SrcIP", "pMacAddr", "PhyAddrLen"]),
        #
        'GetRTTAndHopCount': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DestIpAddress", "HopCount", "MaxHops", "RTT"]),
        #
        'GetFriendlyIfIndex': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["IfIndex"]),
        #
        'EnableRouter': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pHandle", "pOverlapped"]),
        #
        'UnenableRouter': SimTypeFunction([SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pOverlapped", "lpdwEnableCount"]),
        #
        'DisableMediaSense': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pHandle", "pOverLapped"]),
        #
        'RestoreMediaSense': SimTypeFunction([SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pOverlapped", "lpdwEnableCount"]),
        #
        'GetIpErrorString': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ErrorCode", "Buffer", "Size"]),
        #
        'ResolveNeighbor': SimTypeFunction([SimTypePointer(SimTypeRef("SOCKADDR", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["NetworkAddress", "PhysicalAddress", "PhysicalAddressLength"]),
        #
        'CreatePersistentTcpPortReservation': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["StartPort", "NumberOfPorts", "Token"]),
        #
        'CreatePersistentUdpPortReservation': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["StartPort", "NumberOfPorts", "Token"]),
        #
        'DeletePersistentTcpPortReservation': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=False, label="UInt32"), arg_names=["StartPort", "NumberOfPorts"]),
        #
        'DeletePersistentUdpPortReservation': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=False, label="UInt32"), arg_names=["StartPort", "NumberOfPorts"]),
        #
        'LookupPersistentTcpPortReservation': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["StartPort", "NumberOfPorts", "Token"]),
        #
        'LookupPersistentUdpPortReservation': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["StartPort", "NumberOfPorts", "Token"]),
        #
        'ParseNetworkString': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("NET_ADDRESS_INFO", SimStruct), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["NetworkString", "Types", "AddressInfo", "PortNumber", "PrefixLength"]),
        #
        'GetIfEntry2': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IF_ROW2", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Row"]),
        #
        'GetIfEntry2Ex': SimTypeFunction([SimTypeInt(signed=False, label="MIB_IF_ENTRY_LEVEL"), SimTypePointer(SimTypeRef("MIB_IF_ROW2", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Level", "Row"]),
        #
        'GetIfTable2': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("MIB_IF_TABLE2", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Table"]),
        #
        'GetIfTable2Ex': SimTypeFunction([SimTypeInt(signed=False, label="MIB_IF_TABLE_LEVEL"), SimTypePointer(SimTypePointer(SimTypeRef("MIB_IF_TABLE2", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Level", "Table"]),
        #
        'GetIfStackTable': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("MIB_IFSTACK_TABLE", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Table"]),
        #
        'GetInvertedIfStackTable': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("MIB_INVERTEDIFSTACK_TABLE", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Table"]),
        #
        'GetIpInterfaceEntry': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPINTERFACE_ROW", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Row"]),
        #
        'GetIpInterfaceTable': SimTypeFunction([SimTypeInt(signed=False, label="ADDRESS_FAMILY"), SimTypePointer(SimTypePointer(SimTypeRef("MIB_IPINTERFACE_TABLE", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Family", "Table"]),
        #
        'InitializeIpInterfaceEntry': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPINTERFACE_ROW", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Row"]),
        #
        'NotifyIpInterfaceChange': SimTypeFunction([SimTypeInt(signed=False, label="ADDRESS_FAMILY"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("MIB_IPINTERFACE_ROW", SimStruct), offset=0), SimTypeInt(signed=False, label="MIB_NOTIFICATION_TYPE")], SimTypeBottom(label="Void"), arg_names=["CallerContext", "Row", "NotificationType"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Family", "Callback", "CallerContext", "InitialNotification", "NotificationHandle"]),
        #
        'SetIpInterfaceEntry': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPINTERFACE_ROW", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Row"]),
        #
        'GetIpNetworkConnectionBandwidthEstimates': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="ADDRESS_FAMILY"), SimTypePointer(SimTypeRef("MIB_IP_NETWORK_CONNECTION_BANDWIDTH_ESTIMATES", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["InterfaceIndex", "AddressFamily", "BandwidthEstimates"]),
        #
        'CreateUnicastIpAddressEntry': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_UNICASTIPADDRESS_ROW", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Row"]),
        #
        'DeleteUnicastIpAddressEntry': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_UNICASTIPADDRESS_ROW", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Row"]),
        #
        'GetUnicastIpAddressEntry': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_UNICASTIPADDRESS_ROW", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Row"]),
        #
        'GetUnicastIpAddressTable': SimTypeFunction([SimTypeInt(signed=False, label="ADDRESS_FAMILY"), SimTypePointer(SimTypePointer(SimTypeRef("MIB_UNICASTIPADDRESS_TABLE", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Family", "Table"]),
        #
        'InitializeUnicastIpAddressEntry': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_UNICASTIPADDRESS_ROW", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Row"]),
        #
        'NotifyUnicastIpAddressChange': SimTypeFunction([SimTypeInt(signed=False, label="ADDRESS_FAMILY"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("MIB_UNICASTIPADDRESS_ROW", SimStruct), offset=0), SimTypeInt(signed=False, label="MIB_NOTIFICATION_TYPE")], SimTypeBottom(label="Void"), arg_names=["CallerContext", "Row", "NotificationType"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Family", "Callback", "CallerContext", "InitialNotification", "NotificationHandle"]),
        #
        'NotifyStableUnicastIpAddressTable': SimTypeFunction([SimTypeInt(signed=False, label="ADDRESS_FAMILY"), SimTypePointer(SimTypePointer(SimTypeRef("MIB_UNICASTIPADDRESS_TABLE", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("MIB_UNICASTIPADDRESS_TABLE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["CallerContext", "AddressTable"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Family", "Table", "CallerCallback", "CallerContext", "NotificationHandle"]),
        #
        'SetUnicastIpAddressEntry': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_UNICASTIPADDRESS_ROW", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Row"]),
        #
        'CreateAnycastIpAddressEntry': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_ANYCASTIPADDRESS_ROW", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Row"]),
        #
        'DeleteAnycastIpAddressEntry': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_ANYCASTIPADDRESS_ROW", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Row"]),
        #
        'GetAnycastIpAddressEntry': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_ANYCASTIPADDRESS_ROW", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Row"]),
        #
        'GetAnycastIpAddressTable': SimTypeFunction([SimTypeInt(signed=False, label="ADDRESS_FAMILY"), SimTypePointer(SimTypePointer(SimTypeRef("MIB_ANYCASTIPADDRESS_TABLE", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Family", "Table"]),
        #
        'GetMulticastIpAddressEntry': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_MULTICASTIPADDRESS_ROW", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Row"]),
        #
        'GetMulticastIpAddressTable': SimTypeFunction([SimTypeInt(signed=False, label="ADDRESS_FAMILY"), SimTypePointer(SimTypePointer(SimTypeRef("MIB_MULTICASTIPADDRESS_TABLE", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Family", "Table"]),
        #
        'CreateIpForwardEntry2': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPFORWARD_ROW2", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Row"]),
        #
        'DeleteIpForwardEntry2': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPFORWARD_ROW2", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Row"]),
        #
        'GetBestRoute2': SimTypeFunction([SimTypePointer(SimUnion({"Value": SimTypeLongLong(signed=False, label="UInt64"), "Info": SimTypeRef("_Info_e__Struct", SimStruct)}, name="<anon>", label="None"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimUnion({"Ipv4": SimTypeRef("SOCKADDR_IN", SimStruct), "Ipv6": SimTypeRef("SOCKADDR_IN6", SimStruct), "si_family": SimTypeInt(signed=False, label="ADDRESS_FAMILY")}, name="<anon>", label="None"), offset=0), SimTypePointer(SimUnion({"Ipv4": SimTypeRef("SOCKADDR_IN", SimStruct), "Ipv6": SimTypeRef("SOCKADDR_IN6", SimStruct), "si_family": SimTypeInt(signed=False, label="ADDRESS_FAMILY")}, name="<anon>", label="None"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MIB_IPFORWARD_ROW2", SimStruct), offset=0), SimTypePointer(SimUnion({"Ipv4": SimTypeRef("SOCKADDR_IN", SimStruct), "Ipv6": SimTypeRef("SOCKADDR_IN6", SimStruct), "si_family": SimTypeInt(signed=False, label="ADDRESS_FAMILY")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["InterfaceLuid", "InterfaceIndex", "SourceAddress", "DestinationAddress", "AddressSortOptions", "BestRoute", "BestSourceAddress"]),
        #
        'GetIpForwardEntry2': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPFORWARD_ROW2", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Row"]),
        #
        'GetIpForwardTable2': SimTypeFunction([SimTypeInt(signed=False, label="ADDRESS_FAMILY"), SimTypePointer(SimTypePointer(SimTypeRef("MIB_IPFORWARD_TABLE2", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Family", "Table"]),
        #
        'InitializeIpForwardEntry': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPFORWARD_ROW2", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Row"]),
        #
        'NotifyRouteChange2': SimTypeFunction([SimTypeInt(signed=False, label="ADDRESS_FAMILY"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("MIB_IPFORWARD_ROW2", SimStruct), offset=0), SimTypeInt(signed=False, label="MIB_NOTIFICATION_TYPE")], SimTypeBottom(label="Void"), arg_names=["CallerContext", "Row", "NotificationType"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["AddressFamily", "Callback", "CallerContext", "InitialNotification", "NotificationHandle"]),
        #
        'SetIpForwardEntry2': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPFORWARD_ROW2", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Route"]),
        #
        'FlushIpPathTable': SimTypeFunction([SimTypeInt(signed=False, label="ADDRESS_FAMILY")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Family"]),
        #
        'GetIpPathEntry': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPPATH_ROW", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Row"]),
        #
        'GetIpPathTable': SimTypeFunction([SimTypeInt(signed=False, label="ADDRESS_FAMILY"), SimTypePointer(SimTypePointer(SimTypeRef("MIB_IPPATH_TABLE", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Family", "Table"]),
        #
        'CreateIpNetEntry2': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPNET_ROW2", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Row"]),
        #
        'DeleteIpNetEntry2': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPNET_ROW2", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Row"]),
        #
        'FlushIpNetTable2': SimTypeFunction([SimTypeInt(signed=False, label="ADDRESS_FAMILY"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Family", "InterfaceIndex"]),
        #
        'GetIpNetEntry2': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPNET_ROW2", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Row"]),
        #
        'GetIpNetTable2': SimTypeFunction([SimTypeInt(signed=False, label="ADDRESS_FAMILY"), SimTypePointer(SimTypePointer(SimTypeRef("MIB_IPNET_TABLE2", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Family", "Table"]),
        #
        'ResolveIpNetEntry2': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPNET_ROW2", SimStruct), offset=0), SimTypePointer(SimUnion({"Ipv4": SimTypeRef("SOCKADDR_IN", SimStruct), "Ipv6": SimTypeRef("SOCKADDR_IN6", SimStruct), "si_family": SimTypeInt(signed=False, label="ADDRESS_FAMILY")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Row", "SourceAddress"]),
        #
        'SetIpNetEntry2': SimTypeFunction([SimTypePointer(SimTypeRef("MIB_IPNET_ROW2", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Row"]),
        #
        'NotifyTeredoPortChange': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypeInt(signed=False, label="MIB_NOTIFICATION_TYPE")], SimTypeBottom(label="Void"), arg_names=["CallerContext", "Port", "NotificationType"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Callback", "CallerContext", "InitialNotification", "NotificationHandle"]),
        #
        'GetTeredoPort': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Port"]),
        #
        'CancelMibChangeNotify2': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["NotificationHandle"]),
        #
        'FreeMibTable': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Memory"]),
        #
        'CreateSortedAddressPairs': SimTypeFunction([SimTypePointer(SimTypeRef("SOCKADDR_IN6", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SOCKADDR_IN6", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("SOCKADDR_IN6_PAIR", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["SourceAddressList", "SourceAddressCount", "DestinationAddressList", "DestinationAddressCount", "AddressSortOptions", "SortedAddressPairList", "SortedAddressPairCount"]),
        #
        'ConvertCompartmentGuidToId': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["CompartmentGuid", "CompartmentId"]),
        #
        'ConvertCompartmentIdToGuid': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["CompartmentId", "CompartmentGuid"]),
        #
        'ConvertInterfaceNameToLuidA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimUnion({"Value": SimTypeLongLong(signed=False, label="UInt64"), "Info": SimTypeRef("_Info_e__Struct", SimStruct)}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["InterfaceName", "InterfaceLuid"]),
        #
        'ConvertInterfaceNameToLuidW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimUnion({"Value": SimTypeLongLong(signed=False, label="UInt64"), "Info": SimTypeRef("_Info_e__Struct", SimStruct)}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["InterfaceName", "InterfaceLuid"]),
        #
        'ConvertInterfaceLuidToNameA': SimTypeFunction([SimTypePointer(SimUnion({"Value": SimTypeLongLong(signed=False, label="UInt64"), "Info": SimTypeRef("_Info_e__Struct", SimStruct)}, name="<anon>", label="None"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["InterfaceLuid", "InterfaceName", "Length"]),
        #
        'ConvertInterfaceLuidToNameW': SimTypeFunction([SimTypePointer(SimUnion({"Value": SimTypeLongLong(signed=False, label="UInt64"), "Info": SimTypeRef("_Info_e__Struct", SimStruct)}, name="<anon>", label="None"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["InterfaceLuid", "InterfaceName", "Length"]),
        #
        'ConvertInterfaceLuidToIndex': SimTypeFunction([SimTypePointer(SimUnion({"Value": SimTypeLongLong(signed=False, label="UInt64"), "Info": SimTypeRef("_Info_e__Struct", SimStruct)}, name="<anon>", label="None"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["InterfaceLuid", "InterfaceIndex"]),
        #
        'ConvertInterfaceIndexToLuid': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimUnion({"Value": SimTypeLongLong(signed=False, label="UInt64"), "Info": SimTypeRef("_Info_e__Struct", SimStruct)}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["InterfaceIndex", "InterfaceLuid"]),
        #
        'ConvertInterfaceLuidToAlias': SimTypeFunction([SimTypePointer(SimUnion({"Value": SimTypeLongLong(signed=False, label="UInt64"), "Info": SimTypeRef("_Info_e__Struct", SimStruct)}, name="<anon>", label="None"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["InterfaceLuid", "InterfaceAlias", "Length"]),
        #
        'ConvertInterfaceAliasToLuid': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimUnion({"Value": SimTypeLongLong(signed=False, label="UInt64"), "Info": SimTypeRef("_Info_e__Struct", SimStruct)}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["InterfaceAlias", "InterfaceLuid"]),
        #
        'ConvertInterfaceLuidToGuid': SimTypeFunction([SimTypePointer(SimUnion({"Value": SimTypeLongLong(signed=False, label="UInt64"), "Info": SimTypeRef("_Info_e__Struct", SimStruct)}, name="<anon>", label="None"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["InterfaceLuid", "InterfaceGuid"]),
        #
        'ConvertInterfaceGuidToLuid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimUnion({"Value": SimTypeLongLong(signed=False, label="UInt64"), "Info": SimTypeRef("_Info_e__Struct", SimStruct)}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["InterfaceGuid", "InterfaceLuid"]),
        #
        'if_nametoindex': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["InterfaceName"]),
        #
        'if_indextoname': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["InterfaceIndex", "InterfaceName"]),
        #
        'GetCurrentThreadCompartmentId': SimTypeFunction([], SimTypeInt(signed=False, label="WIN32_ERROR")),
        #
        'SetCurrentThreadCompartmentId': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["CompartmentId"]),
        #
        'GetCurrentThreadCompartmentScope': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["CompartmentScope", "CompartmentId"]),
        #
        'SetCurrentThreadCompartmentScope': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["CompartmentScope"]),
        #
        'GetJobCompartmentId': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["JobHandle"]),
        #
        'SetJobCompartmentId': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["JobHandle", "CompartmentId"]),
        #
        'GetSessionCompartmentId': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["SessionId"]),
        #
        'SetSessionCompartmentId': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["SessionId", "CompartmentId"]),
        #
        'GetDefaultCompartmentId': SimTypeFunction([], SimTypeInt(signed=False, label="WIN32_ERROR")),
        #
        'GetNetworkInformation': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["NetworkGuid", "CompartmentId", "SiteId", "NetworkName", "Length"]),
        #
        'SetNetworkInformation': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["NetworkGuid", "CompartmentId", "NetworkName"]),
        #
        'ConvertLengthToIpv4Mask': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["MaskLength", "Mask"]),
        #
        'ConvertIpv4MaskToLength': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Mask", "MaskLength"]),
        #
        'GetDnsSettings': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_SETTINGS", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Settings"]),
        #
        'FreeDnsSettings': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_SETTINGS", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Settings"]),
        #
        'SetDnsSettings': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_SETTINGS", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Settings"]),
        #
        'GetInterfaceDnsSettings': SimTypeFunction([SimTypeBottom(label="Guid"), SimTypePointer(SimTypeRef("DNS_INTERFACE_SETTINGS", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Interface", "Settings"]),
        #
        'FreeInterfaceDnsSettings': SimTypeFunction([SimTypePointer(SimTypeRef("DNS_INTERFACE_SETTINGS", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["Settings"]),
        #
        'SetInterfaceDnsSettings': SimTypeFunction([SimTypeBottom(label="Guid"), SimTypePointer(SimTypeRef("DNS_INTERFACE_SETTINGS", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Interface", "Settings"]),
        #
        'GetNetworkConnectivityHint': SimTypeFunction([SimTypePointer(SimTypeRef("NL_NETWORK_CONNECTIVITY_HINT", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["ConnectivityHint"]),
        #
        'GetNetworkConnectivityHintForInterface': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("NL_NETWORK_CONNECTIVITY_HINT", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["InterfaceIndex", "ConnectivityHint"]),
        #
        'NotifyNetworkConnectivityHintChange': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeRef("NL_NETWORK_CONNECTIVITY_HINT", SimStruct)], SimTypeBottom(label="Void"), arg_names=["CallerContext", "ConnectivityHint"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["Callback", "CallerContext", "InitialNotification", "NotificationHandle"]),
        #
        'PfCreateInterface': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="PFFORWARD_ACTION"), SimTypeInt(signed=False, label="PFFORWARD_ACTION"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwName", "inAction", "outAction", "bUseLog", "bMustBeUnique", "ppInterface"]),
        #
        'PfDeleteInterface': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pInterface"]),
        #
        'PfAddFiltersToInterface': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PF_FILTER_DESCRIPTOR", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PF_FILTER_DESCRIPTOR", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ih", "cInFilters", "pfiltIn", "cOutFilters", "pfiltOut", "pfHandle"]),
        #
        'PfRemoveFiltersFromInterface': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PF_FILTER_DESCRIPTOR", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PF_FILTER_DESCRIPTOR", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ih", "cInFilters", "pfiltIn", "cOutFilters", "pfiltOut"]),
        #
        'PfRemoveFilterHandles': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pInterface", "cFilters", "pvHandles"]),
        #
        'PfUnBindInterface': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pInterface"]),
        #
        'PfBindInterfaceToIndex': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="PFADDRESSTYPE"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pInterface", "dwIndex", "pfatLinkType", "LinkIPAddress"]),
        #
        'PfBindInterfaceToIPAddress': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="PFADDRESSTYPE"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pInterface", "pfatType", "IPAddress"]),
        #
        'PfRebindFilters': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("PF_LATEBIND_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pInterface", "pLateBindInfo"]),
        #
        'PfAddGlobalFilterToInterface': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="GLOBAL_FILTER")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pInterface", "gfFilter"]),
        #
        'PfRemoveGlobalFilterFromInterface': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="GLOBAL_FILTER")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pInterface", "gfFilter"]),
        #
        'PfMakeLog': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hEvent"]),
        #
        'PfSetLogBuffer': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pbBuffer", "dwSize", "dwThreshold", "dwEntries", "pdwLoggedEntries", "pdwLostEntries", "pdwSizeUsed"]),
        #
        'PfDeleteLog': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'PfGetInterfaceStatistics': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("PF_INTERFACE_STATS", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pInterface", "ppfStats", "pdwBufferSize", "fResetCounters"]),
        #
        'PfTestPacket': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="PFFORWARD_ACTION"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pInInterface", "pOutInterface", "cBytes", "pbPacket", "ppAction"]),
    }

lib.set_prototypes(prototypes)
