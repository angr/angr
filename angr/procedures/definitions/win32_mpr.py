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
lib.set_library_names("mpr.dll")
prototypes = \
    {
        #
        'WNetAddConnectionA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["lpRemoteName", "lpPassword", "lpLocalName"]),
        #
        'WNetAddConnectionW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["lpRemoteName", "lpPassword", "lpLocalName"]),
        #
        'WNetAddConnection2A': SimTypeFunction([SimTypePointer(SimTypeRef("NETRESOURCEA", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["lpNetResource", "lpPassword", "lpUserName", "dwFlags"]),
        #
        'WNetAddConnection2W': SimTypeFunction([SimTypePointer(SimTypeRef("NETRESOURCEW", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["lpNetResource", "lpPassword", "lpUserName", "dwFlags"]),
        #
        'WNetAddConnection3A': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("NETRESOURCEA", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hwndOwner", "lpNetResource", "lpPassword", "lpUserName", "dwFlags"]),
        #
        'WNetAddConnection3W': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("NETRESOURCEW", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hwndOwner", "lpNetResource", "lpPassword", "lpUserName", "dwFlags"]),
        #
        'WNetAddConnection4A': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("NETRESOURCEA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hwndOwner", "lpNetResource", "pAuthBuffer", "cbAuthBuffer", "dwFlags", "lpUseOptions", "cbUseOptions"]),
        #
        'WNetAddConnection4W': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("NETRESOURCEW", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hwndOwner", "lpNetResource", "pAuthBuffer", "cbAuthBuffer", "dwFlags", "lpUseOptions", "cbUseOptions"]),
        #
        'WNetCancelConnectionA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["lpName", "fForce"]),
        #
        'WNetCancelConnectionW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["lpName", "fForce"]),
        #
        'WNetCancelConnection2A': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["lpName", "dwFlags", "fForce"]),
        #
        'WNetCancelConnection2W': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["lpName", "dwFlags", "fForce"]),
        #
        'WNetGetConnectionA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["lpLocalName", "lpRemoteName", "lpnLength"]),
        #
        'WNetGetConnectionW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["lpLocalName", "lpRemoteName", "lpnLength"]),
        #
        'WNetUseConnectionA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("NETRESOURCEA", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="NET_USE_CONNECT_FLAGS"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hwndOwner", "lpNetResource", "lpPassword", "lpUserId", "dwFlags", "lpAccessName", "lpBufferSize", "lpResult"]),
        #
        'WNetUseConnectionW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("NETRESOURCEW", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="NET_USE_CONNECT_FLAGS"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hwndOwner", "lpNetResource", "lpPassword", "lpUserId", "dwFlags", "lpAccessName", "lpBufferSize", "lpResult"]),
        #
        'WNetUseConnection4A': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("NETRESOURCEA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hwndOwner", "lpNetResource", "pAuthBuffer", "cbAuthBuffer", "dwFlags", "lpUseOptions", "cbUseOptions", "lpAccessName", "lpBufferSize", "lpResult"]),
        #
        'WNetUseConnection4W': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("NETRESOURCEW", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hwndOwner", "lpNetResource", "pAuthBuffer", "cbAuthBuffer", "dwFlags", "lpUseOptions", "cbUseOptions", "lpAccessName", "lpBufferSize", "lpResult"]),
        #
        'WNetConnectionDialog': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hwnd", "dwType"]),
        #
        'WNetDisconnectDialog': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hwnd", "dwType"]),
        #
        'WNetConnectionDialog1A': SimTypeFunction([SimTypePointer(SimTypeRef("CONNECTDLGSTRUCTA", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["lpConnDlgStruct"]),
        #
        'WNetConnectionDialog1W': SimTypeFunction([SimTypePointer(SimTypeRef("CONNECTDLGSTRUCTW", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["lpConnDlgStruct"]),
        #
        'WNetDisconnectDialog1A': SimTypeFunction([SimTypePointer(SimTypeRef("DISCDLGSTRUCTA", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["lpConnDlgStruct"]),
        #
        'WNetDisconnectDialog1W': SimTypeFunction([SimTypePointer(SimTypeRef("DISCDLGSTRUCTW", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["lpConnDlgStruct"]),
        #
        'WNetOpenEnumA': SimTypeFunction([SimTypeInt(signed=False, label="NET_RESOURCE_SCOPE"), SimTypeInt(signed=False, label="NET_RESOURCE_TYPE"), SimTypeInt(signed=False, label="WNET_OPEN_ENUM_USAGE"), SimTypePointer(SimTypeRef("NETRESOURCEA", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["dwScope", "dwType", "dwUsage", "lpNetResource", "lphEnum"]),
        #
        'WNetOpenEnumW': SimTypeFunction([SimTypeInt(signed=False, label="NET_RESOURCE_SCOPE"), SimTypeInt(signed=False, label="NET_RESOURCE_TYPE"), SimTypeInt(signed=False, label="WNET_OPEN_ENUM_USAGE"), SimTypePointer(SimTypeRef("NETRESOURCEW", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["dwScope", "dwType", "dwUsage", "lpNetResource", "lphEnum"]),
        #
        'WNetEnumResourceA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hEnum", "lpcCount", "lpBuffer", "lpBufferSize"]),
        #
        'WNetEnumResourceW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hEnum", "lpcCount", "lpBuffer", "lpBufferSize"]),
        #
        'WNetCloseEnum': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["hEnum"]),
        #
        'WNetGetResourceParentA': SimTypeFunction([SimTypePointer(SimTypeRef("NETRESOURCEA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["lpNetResource", "lpBuffer", "lpcbBuffer"]),
        #
        'WNetGetResourceParentW': SimTypeFunction([SimTypePointer(SimTypeRef("NETRESOURCEW", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["lpNetResource", "lpBuffer", "lpcbBuffer"]),
        #
        'WNetGetResourceInformationA': SimTypeFunction([SimTypePointer(SimTypeRef("NETRESOURCEA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["lpNetResource", "lpBuffer", "lpcbBuffer", "lplpSystem"]),
        #
        'WNetGetResourceInformationW': SimTypeFunction([SimTypePointer(SimTypeRef("NETRESOURCEW", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["lpNetResource", "lpBuffer", "lpcbBuffer", "lplpSystem"]),
        #
        'WNetGetUniversalNameA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UNC_INFO_LEVEL"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["lpLocalPath", "dwInfoLevel", "lpBuffer", "lpBufferSize"]),
        #
        'WNetGetUniversalNameW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UNC_INFO_LEVEL"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["lpLocalPath", "dwInfoLevel", "lpBuffer", "lpBufferSize"]),
        #
        'WNetGetUserA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["lpName", "lpUserName", "lpnLength"]),
        #
        'WNetGetUserW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["lpName", "lpUserName", "lpnLength"]),
        #
        'WNetGetProviderNameA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["dwNetType", "lpProviderName", "lpBufferSize"]),
        #
        'WNetGetProviderNameW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["dwNetType", "lpProviderName", "lpBufferSize"]),
        #
        'WNetGetNetworkInformationA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("NETINFOSTRUCT", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["lpProvider", "lpNetInfoStruct"]),
        #
        'WNetGetNetworkInformationW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("NETINFOSTRUCT", SimStruct), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["lpProvider", "lpNetInfoStruct"]),
        #
        'WNetGetLastErrorA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["lpError", "lpErrorBuf", "nErrorBufSize", "lpNameBuf", "nNameBufSize"]),
        #
        'WNetGetLastErrorW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["lpError", "lpErrorBuf", "nErrorBufSize", "lpNameBuf", "nNameBufSize"]),
        #
        'MultinetGetConnectionPerformanceA': SimTypeFunction([SimTypePointer(SimTypeRef("NETRESOURCEA", SimStruct), offset=0), SimTypePointer(SimTypeRef("NETCONNECTINFOSTRUCT", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpNetResource", "lpNetConnectInfoStruct"]),
        #
        'MultinetGetConnectionPerformanceW': SimTypeFunction([SimTypePointer(SimTypeRef("NETRESOURCEW", SimStruct), offset=0), SimTypePointer(SimTypeRef("NETCONNECTINFOSTRUCT", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpNetResource", "lpNetConnectInfoStruct"]),
        #
        'WNetSetLastErrorA': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["err", "lpError", "lpProviders"]),
        #
        'WNetSetLastErrorW': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["err", "lpError", "lpProviders"]),
    }

lib.set_prototypes(prototypes)
