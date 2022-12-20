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
lib.set_library_names("wldp.dll")
prototypes = \
    {
        #
        'WldpGetLockdownPolicy': SimTypeFunction([SimTypePointer(SimStruct({"dwRevision": SimTypeInt(signed=False, label="UInt32"), "dwHostId": SimTypeInt(signed=False, label="WLDP_HOST_ID"), "szSource": SimTypePointer(SimTypeChar(label="Char"), offset=0), "hSource": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="WLDP_HOST_INFORMATION", pack=False, align=None), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hostInformation", "lockdownState", "lockdownFlags"]),
        #
        'WldpIsClassInApprovedList': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimStruct({"dwRevision": SimTypeInt(signed=False, label="UInt32"), "dwHostId": SimTypeInt(signed=False, label="WLDP_HOST_ID"), "szSource": SimTypePointer(SimTypeChar(label="Char"), offset=0), "hSource": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="WLDP_HOST_INFORMATION", pack=False, align=None), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["classID", "hostInformation", "isApproved", "optionalFlags"]),
        #
        'WldpSetDynamicCodeTrust': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fileHandle"]),
        #
        'WldpIsDynamicCodePolicyEnabled': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["isEnabled"]),
        #
        'WldpQueryDynamicCodeTrust': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["fileHandle", "baseImage", "imageSize"]),
    }

lib.set_prototypes(prototypes)
