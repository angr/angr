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
lib.set_library_names("ntlanman.dll")
prototypes = \
    {
        #
        'RegisterAppInstance': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ProcessHandle", "AppInstanceId", "ChildrenInheritAppInstance"]),
        #
        'RegisterAppInstanceVersion': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=False, label="UInt32"), arg_names=["AppInstanceId", "InstanceVersionHigh", "InstanceVersionLow"]),
        #
        'QueryAppInstanceVersion': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["AppInstanceId", "InstanceVersionHigh", "InstanceVersionLow", "VersionStatus"]),
        #
        'ResetAllAppInstanceVersions': SimTypeFunction([], SimTypeInt(signed=False, label="UInt32")),
        #
        'SetAppInstanceCsvFlags': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ProcessHandle", "Mask", "Flags"]),
        #
        'NPAddConnection4': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("NETRESOURCEW", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hwndOwner", "lpNetResource", "lpAuthBuffer", "cbAuthBuffer", "dwFlags", "lpUseOptions", "cbUseOptions"]),
        #
        'NPCancelConnection2': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpName", "fForce", "dwFlags"]),
        #
        'NPGetConnection3': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpLocalName", "dwLevel", "lpBuffer", "lpBufferSize"]),
        #
        'NPGetConnectionPerformance': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("NETCONNECTINFOSTRUCT", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpRemoteName", "lpNetConnectInfo"]),
        #
        'NPGetPersistentUseOptionsForConnection': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpRemotePath", "lpReadUseOptions", "cbReadUseOptions", "lpWriteUseOptions", "lpSizeWriteUseOptions"]),
    }

lib.set_prototypes(prototypes)
