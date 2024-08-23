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
lib.set_library_names("ws2_32.dll")
prototypes = \
    {
        #
        'WSCEnumProtocols32': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeRef("WSAPROTOCOL_INFOW", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpiProtocols", "lpProtocolBuffer", "lpdwBufferLength", "lpErrno"]),
        #
        'WSCDeinstallProvider32': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpProviderId", "lpErrno"]),
        #
        'WSCInstallProvider64_32': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("WSAPROTOCOL_INFOW", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpProviderId", "lpszProviderDllPath", "lpProtocolInfoList", "dwNumberOfEntries", "lpErrno"]),
        #
        'WSCGetProviderPath32': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpProviderId", "lpszProviderDllPath", "lpProviderDllPathLen", "lpErrno"]),
        #
        'WSCUpdateProvider32': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("WSAPROTOCOL_INFOW", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpProviderId", "lpszProviderDllPath", "lpProtocolInfoList", "dwNumberOfEntries", "lpErrno"]),
        #
        'WSCSetProviderInfo32': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="WSC_PROVIDER_INFO_TYPE"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpProviderId", "InfoType", "Info", "InfoSize", "Flags", "lpErrno"]),
        #
        'WSCGetProviderInfo32': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="WSC_PROVIDER_INFO_TYPE"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpProviderId", "InfoType", "Info", "InfoSize", "Flags", "lpErrno"]),
        #
        'WSCEnumNameSpaceProviders32': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("WSANAMESPACE_INFOW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpdwBufferLength", "lpnspBuffer"]),
        #
        'WSCEnumNameSpaceProvidersEx32': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("WSANAMESPACE_INFOEXW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpdwBufferLength", "lpnspBuffer"]),
        #
        'WSCInstallNameSpace32': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszIdentifier", "lpszPathName", "dwNameSpace", "dwVersion", "lpProviderId"]),
        #
        'WSCInstallNameSpaceEx32': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("BLOB", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszIdentifier", "lpszPathName", "dwNameSpace", "dwVersion", "lpProviderId", "lpProviderSpecific"]),
        #
        'WSCUnInstallNameSpace32': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpProviderId"]),
        #
        'WSCEnableNSProvider32': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpProviderId", "fEnable"]),
        #
        'WSCInstallProviderAndChains64_32': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("WSAPROTOCOL_INFOW", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpProviderId", "lpszProviderDllPath", "lpszProviderDllPath32", "lpszLspName", "dwServiceFlags", "lpProtocolInfoList", "dwNumberOfEntries", "lpdwCatalogEntryId", "lpErrno"]),
        #
        'WSCWriteProviderOrder32': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpwdCatalogEntryId", "dwNumberOfEntries"]),
        #
        'WSCWriteNameSpaceOrder32': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpProviderId", "dwNumberOfEntries"]),
        #
        '__WSAFDIsSet': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("FD_SET", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fd", "param1"]),
        #
        'accept': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("SOCKADDR", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["s", "addr", "addrlen"]),
        #
        'bind': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("SOCKADDR", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "name", "namelen"]),
        #
        'closesocket': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s"]),
        #
        'connect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("SOCKADDR", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "name", "namelen"]),
        #
        'ioctlsocket': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "cmd", "argp"]),
        #
        'getpeername': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("SOCKADDR", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "name", "namelen"]),
        #
        'getsockname': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("SOCKADDR", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "name", "namelen"]),
        #
        'getsockopt': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "level", "optname", "optval", "optlen"]),
        #
        'htonl': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hostlong"]),
        #
        'htons': SimTypeFunction([SimTypeShort(signed=False, label="UInt16")], SimTypeShort(signed=False, label="UInt16"), arg_names=["hostshort"]),
        #
        'inet_addr': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["cp"]),
        #
        'inet_ntoa': SimTypeFunction([SimTypeRef("IN_ADDR", SimStruct)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["in"]),
        #
        'listen': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "backlog"]),
        #
        'ntohl': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["netlong"]),
        #
        'ntohs': SimTypeFunction([SimTypeShort(signed=False, label="UInt16")], SimTypeShort(signed=False, label="UInt16"), arg_names=["netshort"]),
        #
        'recv': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="SEND_RECV_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "buf", "len", "flags"]),
        #
        'recvfrom': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("SOCKADDR", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "buf", "len", "flags", "from", "fromlen"]),
        #
        'select': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("FD_SET", SimStruct), offset=0), SimTypePointer(SimTypeRef("FD_SET", SimStruct), offset=0), SimTypePointer(SimTypeRef("FD_SET", SimStruct), offset=0), SimTypePointer(SimTypeRef("TIMEVAL", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["nfds", "readfds", "writefds", "exceptfds", "timeout"]),
        #
        'send': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="SEND_RECV_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "buf", "len", "flags"]),
        #
        'sendto': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("SOCKADDR", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "buf", "len", "flags", "to", "tolen"]),
        #
        'setsockopt': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "level", "optname", "optval", "optlen"]),
        #
        'shutdown': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="WINSOCK_SHUTDOWN_HOW")], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "how"]),
        #
        'socket': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="WINSOCK_SOCKET_TYPE"), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["af", "type", "protocol"]),
        #
        'gethostbyaddr': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeRef("HOSTENT", SimStruct), offset=0), arg_names=["addr", "len", "type"]),
        #
        'gethostbyname': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeRef("HOSTENT", SimStruct), offset=0), arg_names=["name"]),
        #
        'gethostname': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["name", "namelen"]),
        #
        'GetHostNameW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["name", "namelen"]),
        #
        'getservbyport': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeRef("SERVENT", SimStruct), offset=0), arg_names=["port", "proto"]),
        #
        'getservbyname': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeRef("SERVENT", SimStruct), offset=0), arg_names=["name", "proto"]),
        #
        'getprotobynumber': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeRef("PROTOENT", SimStruct), offset=0), arg_names=["number"]),
        #
        'getprotobyname': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeRef("PROTOENT", SimStruct), offset=0), arg_names=["name"]),
        #
        'WSAStartup': SimTypeFunction([SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("WSADATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["wVersionRequested", "lpWSAData"]),
        #
        'WSACleanup': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'WSASetLastError': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["iError"]),
        #
        'WSAGetLastError': SimTypeFunction([], SimTypeInt(signed=False, label="WSA_ERROR")),
        #
        'WSAIsBlocking': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'WSAUnhookBlockingHook': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'WSASetBlockingHook': SimTypeFunction([SimTypePointer(SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)), offset=0)], SimTypePointer(SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)), offset=0), arg_names=["lpBlockFunc"]),
        #
        'WSACancelBlockingCall': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'WSAAsyncGetServByName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd", "wMsg", "name", "proto", "buf", "buflen"]),
        #
        'WSAAsyncGetServByPort': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd", "wMsg", "port", "proto", "buf", "buflen"]),
        #
        'WSAAsyncGetProtoByName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd", "wMsg", "name", "buf", "buflen"]),
        #
        'WSAAsyncGetProtoByNumber': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd", "wMsg", "number", "buf", "buflen"]),
        #
        'WSAAsyncGetHostByName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd", "wMsg", "name", "buf", "buflen"]),
        #
        'WSAAsyncGetHostByAddr': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWnd", "wMsg", "addr", "len", "type", "buf", "buflen"]),
        #
        'WSACancelAsyncRequest': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hAsyncTaskHandle"]),
        #
        'WSAAsyncSelect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "hWnd", "wMsg", "lEvent"]),
        #
        'WSAAccept': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("SOCKADDR", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeRef("WSABUF", SimStruct), offset=0), SimTypePointer(SimTypeRef("WSABUF", SimStruct), offset=0), SimTypePointer(SimTypeRef("QOS", SimStruct), offset=0), SimTypePointer(SimTypeRef("QOS", SimStruct), offset=0), SimTypePointer(SimTypeRef("WSABUF", SimStruct), offset=0), SimTypePointer(SimTypeRef("WSABUF", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpCallerId", "lpCallerData", "lpSQOS", "lpGQOS", "lpCalleeId", "lpCalleeData", "g", "dwCallbackData"]), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["s", "addr", "addrlen", "lpfnCondition", "dwCallbackData"]),
        #
        'WSACloseEvent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEvent"]),
        #
        'WSAConnect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("SOCKADDR", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("WSABUF", SimStruct), offset=0), SimTypePointer(SimTypeRef("WSABUF", SimStruct), offset=0), SimTypePointer(SimTypeRef("QOS", SimStruct), offset=0), SimTypePointer(SimTypeRef("QOS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "name", "namelen", "lpCallerData", "lpCalleeData", "lpSQOS", "lpGQOS"]),
        #
        'WSAConnectByNameW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("SOCKADDR", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("SOCKADDR", SimStruct), offset=0), SimTypePointer(SimTypeRef("TIMEVAL", SimStruct), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "nodename", "servicename", "LocalAddressLength", "LocalAddress", "RemoteAddressLength", "RemoteAddress", "timeout", "Reserved"]),
        #
        'WSAConnectByNameA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("SOCKADDR", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("SOCKADDR", SimStruct), offset=0), SimTypePointer(SimTypeRef("TIMEVAL", SimStruct), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "nodename", "servicename", "LocalAddressLength", "LocalAddress", "RemoteAddressLength", "RemoteAddress", "timeout", "Reserved"]),
        #
        'WSAConnectByList': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("SOCKET_ADDRESS_LIST", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("SOCKADDR", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("SOCKADDR", SimStruct), offset=0), SimTypePointer(SimTypeRef("TIMEVAL", SimStruct), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "SocketAddress", "LocalAddressLength", "LocalAddress", "RemoteAddressLength", "RemoteAddress", "timeout", "Reserved"]),
        #
        'WSACreateEvent': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'WSADuplicateSocketA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("WSAPROTOCOL_INFOA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "dwProcessId", "lpProtocolInfo"]),
        #
        'WSADuplicateSocketW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("WSAPROTOCOL_INFOW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "dwProcessId", "lpProtocolInfo"]),
        #
        'WSAEnumNetworkEvents': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("WSANETWORKEVENTS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "hEventObject", "lpNetworkEvents"]),
        #
        'WSAEnumProtocolsA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeRef("WSAPROTOCOL_INFOA", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpiProtocols", "lpProtocolBuffer", "lpdwBufferLength"]),
        #
        'WSAEnumProtocolsW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeRef("WSAPROTOCOL_INFOW", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpiProtocols", "lpProtocolBuffer", "lpdwBufferLength"]),
        #
        'WSAEventSelect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "hEventObject", "lNetworkEvents"]),
        #
        'WSAGetOverlappedResult': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "lpOverlapped", "lpcbTransfer", "fWait", "lpdwFlags"]),
        #
        'WSAGetQOSByName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("WSABUF", SimStruct), offset=0), SimTypePointer(SimTypeRef("QOS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "lpQOSName", "lpQOS"]),
        #
        'WSAHtonl': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "hostlong", "lpnetlong"]),
        #
        'WSAHtons': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "hostshort", "lpnetshort"]),
        #
        'WSAIoctl': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["dwError", "cbTransferred", "lpOverlapped", "dwFlags"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "dwIoControlCode", "lpvInBuffer", "cbInBuffer", "lpvOutBuffer", "cbOutBuffer", "lpcbBytesReturned", "lpOverlapped", "lpCompletionRoutine"]),
        #
        'WSAJoinLeaf': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("SOCKADDR", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("WSABUF", SimStruct), offset=0), SimTypePointer(SimTypeRef("WSABUF", SimStruct), offset=0), SimTypePointer(SimTypeRef("QOS", SimStruct), offset=0), SimTypePointer(SimTypeRef("QOS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["s", "name", "namelen", "lpCallerData", "lpCalleeData", "lpSQOS", "lpGQOS", "dwFlags"]),
        #
        'WSANtohl': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "netlong", "lphostlong"]),
        #
        'WSANtohs': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "netshort", "lphostshort"]),
        #
        'WSARecv': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("WSABUF", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["dwError", "cbTransferred", "lpOverlapped", "dwFlags"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "lpBuffers", "dwBufferCount", "lpNumberOfBytesRecvd", "lpFlags", "lpOverlapped", "lpCompletionRoutine"]),
        #
        'WSARecvDisconnect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("WSABUF", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "lpInboundDisconnectData"]),
        #
        'WSARecvFrom': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("WSABUF", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("SOCKADDR", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["dwError", "cbTransferred", "lpOverlapped", "dwFlags"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "lpBuffers", "dwBufferCount", "lpNumberOfBytesRecvd", "lpFlags", "lpFrom", "lpFromlen", "lpOverlapped", "lpCompletionRoutine"]),
        #
        'WSAResetEvent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEvent"]),
        #
        'WSASend': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("WSABUF", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["dwError", "cbTransferred", "lpOverlapped", "dwFlags"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "lpBuffers", "dwBufferCount", "lpNumberOfBytesSent", "dwFlags", "lpOverlapped", "lpCompletionRoutine"]),
        #
        'WSASendMsg': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("WSAMSG", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["dwError", "cbTransferred", "lpOverlapped", "dwFlags"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Handle", "lpMsg", "dwFlags", "lpNumberOfBytesSent", "lpOverlapped", "lpCompletionRoutine"]),
        #
        'WSASendDisconnect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("WSABUF", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "lpOutboundDisconnectData"]),
        #
        'WSASendTo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("WSABUF", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SOCKADDR", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["dwError", "cbTransferred", "lpOverlapped", "dwFlags"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "lpBuffers", "dwBufferCount", "lpNumberOfBytesSent", "dwFlags", "lpTo", "iTolen", "lpOverlapped", "lpCompletionRoutine"]),
        #
        'WSASetEvent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEvent"]),
        #
        'WSASocketA': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("WSAPROTOCOL_INFOA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["af", "type", "protocol", "lpProtocolInfo", "g", "dwFlags"]),
        #
        'WSASocketW': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("WSAPROTOCOL_INFOW", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["af", "type", "protocol", "lpProtocolInfo", "g", "dwFlags"]),
        #
        'WSAWaitForMultipleEvents': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="WAIT_EVENT"), arg_names=["cEvents", "lphEvents", "fWaitAll", "dwTimeout", "fAlertable"]),
        #
        'WSAAddressToStringA': SimTypeFunction([SimTypePointer(SimTypeRef("SOCKADDR", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("WSAPROTOCOL_INFOA", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpsaAddress", "dwAddressLength", "lpProtocolInfo", "lpszAddressString", "lpdwAddressStringLength"]),
        #
        'WSAAddressToStringW': SimTypeFunction([SimTypePointer(SimTypeRef("SOCKADDR", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("WSAPROTOCOL_INFOW", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpsaAddress", "dwAddressLength", "lpProtocolInfo", "lpszAddressString", "lpdwAddressStringLength"]),
        #
        'WSAStringToAddressA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("WSAPROTOCOL_INFOA", SimStruct), offset=0), SimTypePointer(SimTypeRef("SOCKADDR", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AddressString", "AddressFamily", "lpProtocolInfo", "lpAddress", "lpAddressLength"]),
        #
        'WSAStringToAddressW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("WSAPROTOCOL_INFOW", SimStruct), offset=0), SimTypePointer(SimTypeRef("SOCKADDR", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AddressString", "AddressFamily", "lpProtocolInfo", "lpAddress", "lpAddressLength"]),
        #
        'WSALookupServiceBeginA': SimTypeFunction([SimTypePointer(SimTypeRef("WSAQUERYSETA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpqsRestrictions", "dwControlFlags", "lphLookup"]),
        #
        'WSALookupServiceBeginW': SimTypeFunction([SimTypePointer(SimTypeRef("WSAQUERYSETW", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpqsRestrictions", "dwControlFlags", "lphLookup"]),
        #
        'WSALookupServiceNextA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("WSAQUERYSETA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLookup", "dwControlFlags", "lpdwBufferLength", "lpqsResults"]),
        #
        'WSALookupServiceNextW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("WSAQUERYSETW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLookup", "dwControlFlags", "lpdwBufferLength", "lpqsResults"]),
        #
        'WSANSPIoctl': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("WSACOMPLETION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLookup", "dwControlCode", "lpvInBuffer", "cbInBuffer", "lpvOutBuffer", "cbOutBuffer", "lpcbBytesReturned", "lpCompletion"]),
        #
        'WSALookupServiceEnd': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLookup"]),
        #
        'WSAInstallServiceClassA': SimTypeFunction([SimTypePointer(SimTypeRef("WSASERVICECLASSINFOA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpServiceClassInfo"]),
        #
        'WSAInstallServiceClassW': SimTypeFunction([SimTypePointer(SimTypeRef("WSASERVICECLASSINFOW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpServiceClassInfo"]),
        #
        'WSARemoveServiceClass': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpServiceClassId"]),
        #
        'WSAGetServiceClassInfoA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("WSASERVICECLASSINFOA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpProviderId", "lpServiceClassId", "lpdwBufSize", "lpServiceClassInfo"]),
        #
        'WSAGetServiceClassInfoW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("WSASERVICECLASSINFOW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpProviderId", "lpServiceClassId", "lpdwBufSize", "lpServiceClassInfo"]),
        #
        'WSAEnumNameSpaceProvidersA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("WSANAMESPACE_INFOA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpdwBufferLength", "lpnspBuffer"]),
        #
        'WSAEnumNameSpaceProvidersW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("WSANAMESPACE_INFOW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpdwBufferLength", "lpnspBuffer"]),
        #
        'WSAEnumNameSpaceProvidersExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("WSANAMESPACE_INFOEXA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpdwBufferLength", "lpnspBuffer"]),
        #
        'WSAEnumNameSpaceProvidersExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("WSANAMESPACE_INFOEXW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpdwBufferLength", "lpnspBuffer"]),
        #
        'WSAGetServiceClassNameByClassIdA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpServiceClassId", "lpszServiceClassName", "lpdwBufferLength"]),
        #
        'WSAGetServiceClassNameByClassIdW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpServiceClassId", "lpszServiceClassName", "lpdwBufferLength"]),
        #
        'WSASetServiceA': SimTypeFunction([SimTypePointer(SimTypeRef("WSAQUERYSETA", SimStruct), offset=0), SimTypeInt(signed=False, label="WSAESETSERVICEOP"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpqsRegInfo", "essoperation", "dwControlFlags"]),
        #
        'WSASetServiceW': SimTypeFunction([SimTypePointer(SimTypeRef("WSAQUERYSETW", SimStruct), offset=0), SimTypeInt(signed=False, label="WSAESETSERVICEOP"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpqsRegInfo", "essoperation", "dwControlFlags"]),
        #
        'WSAProviderConfigChange': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["dwError", "cbTransferred", "lpOverlapped", "dwFlags"]), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpNotificationHandle", "lpOverlapped", "lpCompletionRoutine"]),
        #
        'WSAPoll': SimTypeFunction([SimTypePointer(SimTypeRef("WSAPOLLFD", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["fdArray", "fds", "timeout"]),
        #
        'ProcessSocketNotifications': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SOCK_NOTIFY_REGISTRATION", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED_ENTRY", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["completionPort", "registrationCount", "registrationInfos", "timeoutMs", "completionCount", "completionPortEntries", "receivedEntryCount"]),
        #
        'WSCEnumProtocols': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeRef("WSAPROTOCOL_INFOW", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpiProtocols", "lpProtocolBuffer", "lpdwBufferLength", "lpErrno"]),
        #
        'WSCDeinstallProvider': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpProviderId", "lpErrno"]),
        #
        'WSCInstallProvider': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("WSAPROTOCOL_INFOW", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpProviderId", "lpszProviderDllPath", "lpProtocolInfoList", "dwNumberOfEntries", "lpErrno"]),
        #
        'WSCGetProviderPath': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpProviderId", "lpszProviderDllPath", "lpProviderDllPathLen", "lpErrno"]),
        #
        'WSCUpdateProvider': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("WSAPROTOCOL_INFOW", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpProviderId", "lpszProviderDllPath", "lpProtocolInfoList", "dwNumberOfEntries", "lpErrno"]),
        #
        'WSCSetProviderInfo': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="WSC_PROVIDER_INFO_TYPE"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpProviderId", "InfoType", "Info", "InfoSize", "Flags", "lpErrno"]),
        #
        'WSCGetProviderInfo': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="WSC_PROVIDER_INFO_TYPE"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpProviderId", "InfoType", "Info", "InfoSize", "Flags", "lpErrno"]),
        #
        'WSCSetApplicationCategory': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Path", "PathLength", "Extra", "ExtraLength", "PermittedLspCategories", "pPrevPermLspCat", "lpErrno"]),
        #
        'WSCGetApplicationCategory': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Path", "PathLength", "Extra", "ExtraLength", "pPermittedLspCategories", "lpErrno"]),
        #
        'WPUCompleteOverlappedRequest': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "lpOverlapped", "dwError", "cbTransferred", "lpErrno"]),
        #
        'WSCInstallNameSpace': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszIdentifier", "lpszPathName", "dwNameSpace", "dwVersion", "lpProviderId"]),
        #
        'WSCUnInstallNameSpace': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpProviderId"]),
        #
        'WSCInstallNameSpaceEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("BLOB", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszIdentifier", "lpszPathName", "dwNameSpace", "dwVersion", "lpProviderId", "lpProviderSpecific"]),
        #
        'WSCEnableNSProvider': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpProviderId", "fEnable"]),
        #
        'WSAAdvertiseProvider': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("NSPV2_ROUTINE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["puuidProviderId", "pNSPv2Routine"]),
        #
        'WSAUnadvertiseProvider': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["puuidProviderId"]),
        #
        'WSAProviderCompleteAsyncCall': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hAsyncCall", "iRetCode"]),
        #
        'getaddrinfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("ADDRINFOA", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("ADDRINFOA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pNodeName", "pServiceName", "pHints", "ppResult"]),
        #
        'GetAddrInfoW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("ADDRINFOW", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("ADDRINFOW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pNodeName", "pServiceName", "pHints", "ppResult"]),
        #
        'GetAddrInfoExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("ADDRINFOEXA", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("ADDRINFOEXA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeRef("TIMEVAL", SimStruct), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["dwError", "dwBytes", "lpOverlapped"]), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pName", "pServiceName", "dwNameSpace", "lpNspId", "hints", "ppResult", "timeout", "lpOverlapped", "lpCompletionRoutine", "lpNameHandle"]),
        #
        'GetAddrInfoExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("ADDRINFOEXW", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("ADDRINFOEXW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeRef("TIMEVAL", SimStruct), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["dwError", "dwBytes", "lpOverlapped"]), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pName", "pServiceName", "dwNameSpace", "lpNspId", "hints", "ppResult", "timeout", "lpOverlapped", "lpCompletionRoutine", "lpHandle"]),
        #
        'GetAddrInfoExCancel': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpHandle"]),
        #
        'GetAddrInfoExOverlappedResult': SimTypeFunction([SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpOverlapped"]),
        #
        'SetAddrInfoExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("SOCKET_ADDRESS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("BLOB", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("TIMEVAL", SimStruct), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["dwError", "dwBytes", "lpOverlapped"]), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pName", "pServiceName", "pAddresses", "dwAddressCount", "lpBlob", "dwFlags", "dwNameSpace", "lpNspId", "timeout", "lpOverlapped", "lpCompletionRoutine", "lpNameHandle"]),
        #
        'SetAddrInfoExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("SOCKET_ADDRESS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("BLOB", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("TIMEVAL", SimStruct), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["dwError", "dwBytes", "lpOverlapped"]), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pName", "pServiceName", "pAddresses", "dwAddressCount", "lpBlob", "dwFlags", "dwNameSpace", "lpNspId", "timeout", "lpOverlapped", "lpCompletionRoutine", "lpNameHandle"]),
        #
        'freeaddrinfo': SimTypeFunction([SimTypePointer(SimTypeRef("ADDRINFOA", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pAddrInfo"]),
        #
        'FreeAddrInfoW': SimTypeFunction([SimTypePointer(SimTypeRef("ADDRINFOW", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pAddrInfo"]),
        #
        'FreeAddrInfoEx': SimTypeFunction([SimTypePointer(SimTypeRef("ADDRINFOEXA", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pAddrInfoEx"]),
        #
        'FreeAddrInfoExW': SimTypeFunction([SimTypePointer(SimTypeRef("ADDRINFOEXW", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pAddrInfoEx"]),
        #
        'getnameinfo': SimTypeFunction([SimTypePointer(SimTypeRef("SOCKADDR", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pSockaddr", "SockaddrLength", "pNodeBuffer", "NodeBufferSize", "pServiceBuffer", "ServiceBufferSize", "Flags"]),
        #
        'GetNameInfoW': SimTypeFunction([SimTypePointer(SimTypeRef("SOCKADDR", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pSockaddr", "SockaddrLength", "pNodeBuffer", "NodeBufferSize", "pServiceBuffer", "ServiceBufferSize", "Flags"]),
        #
        'inet_pton': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Family", "pszAddrString", "pAddrBuf"]),
        #
        'InetPtonW': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Family", "pszAddrString", "pAddrBuf"]),
        #
        'inet_ntop': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["Family", "pAddr", "pStringBuf", "StringBufSize"]),
        #
        'InetNtopW': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeChar(label="Char"), offset=0), arg_names=["Family", "pAddr", "pStringBuf", "StringBufSize"]),
        #
        'WSCWriteProviderOrder': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpwdCatalogEntryId", "dwNumberOfEntries"]),
        #
        'WSCWriteNameSpaceOrder': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpProviderId", "dwNumberOfEntries"]),
    }

lib.set_prototypes(prototypes)
