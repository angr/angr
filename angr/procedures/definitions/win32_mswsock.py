# pylint:disable=line-too-long
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
lib.set_library_names("mswsock.dll")
prototypes = \
    {
        #
        'WSARecvEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["s", "buf", "len", "flags"]),
        #
        'TransmitFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeRef("TRANSMIT_FILE_BUFFERS", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hSocket", "hFile", "nNumberOfBytesToWrite", "nNumberOfBytesPerSend", "lpOverlapped", "lpTransmitBuffers", "dwReserved"]),
        #
        'AcceptEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["sListenSocket", "sAcceptSocket", "lpOutputBuffer", "dwReceiveDataLength", "dwLocalAddressLength", "dwRemoteAddressLength", "lpdwBytesReceived", "lpOverlapped"]),
        #
        'GetAcceptExSockaddrs': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("SOCKADDR", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SOCKADDR", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["lpOutputBuffer", "dwReceiveDataLength", "dwLocalAddressLength", "dwRemoteAddressLength", "LocalSockaddr", "LocalSockaddrLength", "RemoteSockaddr", "RemoteSockaddrLength"]),
        #
        'EnumProtocolsA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpiProtocols", "lpProtocolBuffer", "lpdwBufferLength"]),
        #
        'EnumProtocolsW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpiProtocols", "lpProtocolBuffer", "lpdwBufferLength"]),
        #
        'GetAddressByNameA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SERVICE_ASYNC_INFO", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwNameSpace", "lpServiceType", "lpServiceName", "lpiProtocols", "dwResolution", "lpServiceAsyncInfo", "lpCsaddrBuffer", "lpdwBufferLength", "lpAliasBuffer", "lpdwAliasBufferLength"]),
        #
        'GetAddressByNameW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SERVICE_ASYNC_INFO", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwNameSpace", "lpServiceType", "lpServiceName", "lpiProtocols", "dwResolution", "lpServiceAsyncInfo", "lpCsaddrBuffer", "lpdwBufferLength", "lpAliasBuffer", "lpdwAliasBufferLength"]),
        #
        'GetTypeByNameA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpServiceName", "lpServiceType"]),
        #
        'GetTypeByNameW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpServiceName", "lpServiceType"]),
        #
        'GetNameByTypeA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpServiceType", "lpServiceName", "dwNameLength"]),
        #
        'GetNameByTypeW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpServiceType", "lpServiceName", "dwNameLength"]),
        #
        'SetServiceA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="SET_SERVICE_OPERATION"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SERVICE_INFOA", SimStruct), offset=0), SimTypePointer(SimTypeRef("SERVICE_ASYNC_INFO", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwNameSpace", "dwOperation", "dwFlags", "lpServiceInfo", "lpServiceAsyncInfo", "lpdwStatusFlags"]),
        #
        'SetServiceW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="SET_SERVICE_OPERATION"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SERVICE_INFOW", SimStruct), offset=0), SimTypePointer(SimTypeRef("SERVICE_ASYNC_INFO", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwNameSpace", "dwOperation", "dwFlags", "lpServiceInfo", "lpServiceAsyncInfo", "lpdwStatusFlags"]),
        #
        'GetServiceA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("SERVICE_ASYNC_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwNameSpace", "lpGuid", "lpServiceName", "dwProperties", "lpBuffer", "lpdwBufferSize", "lpServiceAsyncInfo"]),
        #
        'GetServiceW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("SERVICE_ASYNC_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwNameSpace", "lpGuid", "lpServiceName", "dwProperties", "lpBuffer", "lpdwBufferSize", "lpServiceAsyncInfo"]),
    }

lib.set_prototypes(prototypes)
