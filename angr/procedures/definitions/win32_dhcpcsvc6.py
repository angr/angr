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
lib.set_library_names("dhcpcsvc6.dll")
prototypes = \
    {
        #
        'Dhcpv6CApiInitialize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Version"]),
        #
        'Dhcpv6CApiCleanup': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'Dhcpv6RequestParams': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCPV6CAPI_CLASSID", SimStruct), offset=0), SimTypeRef("DHCPV6CAPI_PARAMS_ARRAY", SimStruct), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["forceNewInform", "reserved", "adapterName", "classId", "recdParams", "buffer", "pSize"]),
        #
        'Dhcpv6RequestPrefix': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCPV6CAPI_CLASSID", SimStruct), offset=0), SimTypePointer(SimTypeRef("DHCPV6PrefixLeaseInformation", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["adapterName", "pclassId", "prefixleaseInfo", "pdwTimeToWait"]),
        #
        'Dhcpv6RenewPrefix': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCPV6CAPI_CLASSID", SimStruct), offset=0), SimTypePointer(SimTypeRef("DHCPV6PrefixLeaseInformation", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["adapterName", "pclassId", "prefixleaseInfo", "pdwTimeToWait", "bValidatePrefix"]),
        #
        'Dhcpv6ReleasePrefix': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DHCPV6CAPI_CLASSID", SimStruct), offset=0), SimTypePointer(SimTypeRef("DHCPV6PrefixLeaseInformation", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["adapterName", "classId", "leaseInfo"]),
    }

lib.set_prototypes(prototypes)
