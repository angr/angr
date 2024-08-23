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
lib.set_library_names("wldp.dll")
prototypes = \
    {
        #
        'WldpGetLockdownPolicy': SimTypeFunction([SimTypePointer(SimTypeRef("WLDP_HOST_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hostInformation", "lockdownState", "lockdownFlags"]),
        #
        'WldpIsClassInApprovedList': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("WLDP_HOST_INFORMATION", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["classID", "hostInformation", "isApproved", "optionalFlags"]),
        #
        'WldpSetDynamicCodeTrust': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fileHandle"]),
        #
        'WldpIsDynamicCodePolicyEnabled': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["isEnabled"]),
        #
        'WldpQueryDynamicCodeTrust': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["fileHandle", "baseImage", "imageSize"]),
        #
        'WldpQueryDeviceSecurityInformation': SimTypeFunction([SimTypePointer(SimTypeRef("WLDP_DEVICE_SECURITY_INFORMATION", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["information", "informationLength", "returnLength"]),
        #
        'WldpCanExecuteFile': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="WLDP_EXECUTION_EVALUATION_OPTIONS"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="WLDP_EXECUTION_POLICY"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["host", "options", "fileHandle", "auditInfo", "result"]),
        #
        'WldpCanExecuteBuffer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="WLDP_EXECUTION_EVALUATION_OPTIONS"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="WLDP_EXECUTION_POLICY"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["host", "options", "buffer", "bufferSize", "auditInfo", "result"]),
        #
        'WldpCanExecuteStream': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="WLDP_EXECUTION_EVALUATION_OPTIONS"), SimTypeBottom(label="IStream"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="WLDP_EXECUTION_POLICY"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["host", "options", "stream", "auditInfo", "result"]),
    }

lib.set_prototypes(prototypes)
