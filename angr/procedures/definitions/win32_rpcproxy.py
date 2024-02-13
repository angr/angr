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
lib.set_library_names("rpcproxy.dll")
prototypes = \
    {
        #
        'GetExtensionVersion': SimTypeFunction([SimTypePointer(SimTypeRef("HSE_VERSION_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pVer"]),
        #
        'HttpExtensionProc': SimTypeFunction([SimTypePointer(SimTypeRef("EXTENSION_CONTROL_BLOCK", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pECB"]),
        #
        'HttpFilterProc': SimTypeFunction([SimTypePointer(SimTypeRef("HTTP_FILTER_CONTEXT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pfc", "NotificationType", "pvNotification"]),
        #
        'GetFilterVersion': SimTypeFunction([SimTypePointer(SimTypeRef("HTTP_FILTER_VERSION", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pVer"]),
    }

lib.set_prototypes(prototypes)
