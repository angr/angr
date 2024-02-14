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
lib.set_library_names("api-ms-win-core-featurestaging-l1-1-0.dll")
prototypes = \
    {
        #
        'GetFeatureEnabledState': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FEATURE_CHANGE_TIME")], SimTypeInt(signed=False, label="FEATURE_ENABLED_STATE"), arg_names=["featureId", "changeTime"]),
        #
        'RecordFeatureUsage': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["featureId", "kind", "addend", "originName"]),
        #
        'RecordFeatureError': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("FEATURE_ERROR", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["featureId", "error"]),
        #
        'SubscribeFeatureStateChangeNotification': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["subscription", "callback", "context"]),
        #
        'UnsubscribeFeatureStateChangeNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["subscription"]),
    }

lib.set_prototypes(prototypes)
