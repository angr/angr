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
lib.set_library_names("api-ms-win-gaming-tcui-l1-1-1.dll")
prototypes = \
    {
        #
        'CheckGamingPrivilegeWithUI': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="HSTRING"), SimTypeBottom(label="HSTRING"), SimTypeBottom(label="HSTRING"), SimTypePointer(SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["returnCode", "context"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["privilegeId", "scope", "policy", "friendlyMessage", "completionRoutine", "context"]),
        #
        'CheckGamingPrivilegeSilently': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="HSTRING"), SimTypeBottom(label="HSTRING"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["privilegeId", "scope", "policy", "hasPrivilege"]),
    }

lib.set_prototypes(prototypes)
