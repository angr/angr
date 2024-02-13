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
lib.set_library_names("api-ms-win-net-isolation-l1-1-0.dll")
prototypes = \
    {
        #
        'NetworkIsolationSetupAppContainerBinaries': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["applicationContainerSid", "packageFullName", "packageFolder", "displayName", "bBinariesFullyComputed", "binaries", "binariesCount"]),
        #
        'NetworkIsolationRegisterForAppContainerChanges': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("INET_FIREWALL_AC_CHANGE", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["context", "pChange"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["flags", "callback", "context", "registrationObject"]),
        #
        'NetworkIsolationUnregisterForAppContainerChanges': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["registrationObject"]),
        #
        'NetworkIsolationFreeAppContainers': SimTypeFunction([SimTypePointer(SimTypeRef("INET_FIREWALL_APP_CONTAINER", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pPublicAppCs"]),
        #
        'NetworkIsolationEnumAppContainers': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("INET_FIREWALL_APP_CONTAINER", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Flags", "pdwNumPublicAppCs", "ppPublicAppCs"]),
        #
        'NetworkIsolationGetAppContainerConfig': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("SID_AND_ATTRIBUTES", SimStruct), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pdwNumPublicAppCs", "appContainerSids"]),
        #
        'NetworkIsolationSetAppContainerConfig': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SID_AND_ATTRIBUTES", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwNumPublicAppCs", "appContainerSids"]),
        #
        'NetworkIsolationDiagnoseConnectFailureAndGetInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="NETISO_ERROR_TYPE"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["wszServerName", "netIsoError"]),
    }

lib.set_prototypes(prototypes)
