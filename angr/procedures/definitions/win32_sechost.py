# pylint:disable=line-too-long
from __future__ import annotations
import logging
from collections import OrderedDict

from angr.sim_type import SimTypeFunction, SimTypeShort, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeDouble, SimTypeFloat, SimTypePointer, SimTypeChar, SimStruct, SimTypeArray, SimTypeBottom, SimUnion, SimTypeBool, SimTypeRef
from angr.calling_conventions import SimCCStdcall, SimCCMicrosoftAMD64
from angr.procedures import SIM_PROCEDURES as P
from . import SimLibrary


_l = logging.getLogger(name=__name__)


lib = SimLibrary()
lib.type_collection_names = ["win32"]
lib.set_default_cc("X86", SimCCStdcall)
lib.set_default_cc("AMD64", SimCCMicrosoftAMD64)
lib.set_library_names("sechost.dll")
prototypes = \
    {
        #
        'SubscribeServiceChangeNotifications': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SC_EVENT_TYPE"), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["dwNotify", "pCallbackContext"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hService", "eEventType", "pCallback", "pCallbackContext", "pSubscription"]),
        #
        'UnsubscribeServiceChangeNotifications': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["pSubscription"]),
    }

lib.set_prototypes(prototypes)
