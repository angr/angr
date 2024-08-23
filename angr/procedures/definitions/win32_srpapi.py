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
lib.set_library_names("srpapi.dll")
prototypes = \
    {
        #
        'SrpCreateThreadNetworkContext': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("HTHREAD_NETWORK_CONTEXT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["enterpriseId", "threadNetworkContext"]),
        #
        'SrpCloseThreadNetworkContext': SimTypeFunction([SimTypePointer(SimTypeRef("HTHREAD_NETWORK_CONTEXT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["threadNetworkContext"]),
        #
        'SrpSetTokenEnterpriseId': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["tokenHandle", "enterpriseId"]),
        #
        'SrpGetEnterpriseIds': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["tokenHandle", "numberOfBytes", "enterpriseIds", "enterpriseIdCount"]),
        #
        'SrpEnablePermissiveModeFileEncryption': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["enterpriseId"]),
        #
        'SrpDisablePermissiveModeFileEncryption': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'SrpGetEnterprisePolicy': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="ENTERPRISE_DATA_POLICIES"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["tokenHandle", "policyFlags"]),
        #
        'SrpIsTokenService': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["TokenHandle", "IsTokenService"]),
        #
        'SrpDoesPolicyAllowAppExecution': SimTypeFunction([SimTypePointer(SimTypeRef("PACKAGE_ID", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["packageId", "isAllowed"]),
        #
        'SrpHostingInitialize': SimTypeFunction([SimTypeInt(signed=False, label="SRPHOSTING_VERSION"), SimTypeInt(signed=False, label="SRPHOSTING_TYPE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Version", "Type", "pvData", "cbData"]),
        #
        'SrpHostingTerminate': SimTypeFunction([SimTypeInt(signed=False, label="SRPHOSTING_TYPE")], SimTypeBottom(label="Void"), arg_names=["Type"]),
    }

lib.set_prototypes(prototypes)
