# pylint:disable=line-too-long
import logging

from ...sim_type import SimTypeFunction,     SimTypeShort, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeDouble, SimTypeFloat,     SimTypePointer,     SimTypeChar,     SimStruct,     SimTypeFixedSizeArray,     SimTypeBottom,     SimUnion,     SimTypeBool
from ...calling_conventions import SimCCStdcall, SimCCMicrosoftAMD64
from .. import SIM_PROCEDURES as P
from . import SimLibrary


_l = logging.getLogger(name=__name__)


lib = SimLibrary()
lib.set_default_cc('X86', SimCCStdcall)
lib.set_default_cc('AMD64', SimCCMicrosoftAMD64)
lib.set_library_names("api-ms-win-net-isolation-l1-1-0.dll")
prototypes = \
    {
        #
        'NetworkIsolationSetupAppContainerBinaries': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["applicationContainerSid", "packageFullName", "packageFolder", "displayName", "bBinariesFullyComputed", "binaries", "binariesCount"]),
        #
        'NetworkIsolationRegisterForAppContainerChanges': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimStruct({"changeType": SimTypeInt(signed=False, label="INET_FIREWALL_AC_CHANGE_TYPE"), "createType": SimTypeInt(signed=False, label="INET_FIREWALL_AC_CREATION_TYPE"), "appContainerSid": SimTypePointer(SimTypeBottom(label="SID"), offset=0), "userSid": SimTypePointer(SimTypeBottom(label="SID"), offset=0), "displayName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "Anonymous": SimUnion({"capabilities": SimStruct({"count": SimTypeInt(signed=False, label="UInt32"), "capabilities": SimTypePointer(SimTypeBottom(label="SID_AND_ATTRIBUTES"), offset=0)}, name="INET_FIREWALL_AC_CAPABILITIES", pack=False, align=None), "binaries": SimStruct({"count": SimTypeInt(signed=False, label="UInt32"), "binaries": SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)}, name="INET_FIREWALL_AC_BINARIES", pack=False, align=None)}, name="<anon>", label="None")}, name="INET_FIREWALL_AC_CHANGE", pack=False, align=None), offset=0)], SimTypeBottom(label="Void"), arg_names=["context", "pChange"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["flags", "callback", "context", "registrationObject"]),
        #
        'NetworkIsolationUnregisterForAppContainerChanges': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["registrationObject"]),
        #
        'NetworkIsolationFreeAppContainers': SimTypeFunction([SimTypePointer(SimStruct({"appContainerSid": SimTypePointer(SimTypeBottom(label="SID"), offset=0), "userSid": SimTypePointer(SimTypeBottom(label="SID"), offset=0), "appContainerName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "displayName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "description": SimTypePointer(SimTypeChar(label="Char"), offset=0), "capabilities": SimStruct({"count": SimTypeInt(signed=False, label="UInt32"), "capabilities": SimTypePointer(SimTypeBottom(label="SID_AND_ATTRIBUTES"), offset=0)}, name="INET_FIREWALL_AC_CAPABILITIES", pack=False, align=None), "binaries": SimStruct({"count": SimTypeInt(signed=False, label="UInt32"), "binaries": SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)}, name="INET_FIREWALL_AC_BINARIES", pack=False, align=None), "workingDirectory": SimTypePointer(SimTypeChar(label="Char"), offset=0), "packageFullName": SimTypePointer(SimTypeChar(label="Char"), offset=0)}, name="INET_FIREWALL_APP_CONTAINER", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pPublicAppCs"]),
        #
        'NetworkIsolationEnumAppContainers': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimStruct({"appContainerSid": SimTypePointer(SimTypeBottom(label="SID"), offset=0), "userSid": SimTypePointer(SimTypeBottom(label="SID"), offset=0), "appContainerName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "displayName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "description": SimTypePointer(SimTypeChar(label="Char"), offset=0), "capabilities": SimStruct({"count": SimTypeInt(signed=False, label="UInt32"), "capabilities": SimTypePointer(SimTypeBottom(label="SID_AND_ATTRIBUTES"), offset=0)}, name="INET_FIREWALL_AC_CAPABILITIES", pack=False, align=None), "binaries": SimStruct({"count": SimTypeInt(signed=False, label="UInt32"), "binaries": SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)}, name="INET_FIREWALL_AC_BINARIES", pack=False, align=None), "workingDirectory": SimTypePointer(SimTypeChar(label="Char"), offset=0), "packageFullName": SimTypePointer(SimTypeChar(label="Char"), offset=0)}, name="INET_FIREWALL_APP_CONTAINER", pack=False, align=None), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Flags", "pdwNumPublicAppCs", "ppPublicAppCs"]),
        #
        'NetworkIsolationGetAppContainerConfig': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimStruct({"Sid": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "Attributes": SimTypeInt(signed=False, label="UInt32")}, name="SID_AND_ATTRIBUTES", pack=False, align=None), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pdwNumPublicAppCs", "appContainerSids"]),
        #
        'NetworkIsolationSetAppContainerConfig': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"Sid": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "Attributes": SimTypeInt(signed=False, label="UInt32")}, name="SID_AND_ATTRIBUTES", pack=False, align=None), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwNumPublicAppCs", "appContainerSids"]),
        #
        'NetworkIsolationDiagnoseConnectFailureAndGetInfo': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="NETISO_ERROR_TYPE"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["wszServerName", "netIsoError"]),
    }

lib.set_prototypes(prototypes)
