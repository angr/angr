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
lib.set_library_names("api-ms-win-core-featurestaging-l1-1-0.dll")
prototypes = \
    {
        #
        'GetFeatureEnabledState': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="FEATURE_CHANGE_TIME")], SimTypeInt(signed=False, label="FEATURE_ENABLED_STATE"), arg_names=["featureId", "changeTime"]),
        #
        'RecordFeatureUsage': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeBottom(label="Void"), arg_names=["featureId", "kind", "addend", "originName"]),
        #
        'RecordFeatureError': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"hr": SimTypeInt(signed=True, label="Int32"), "lineNumber": SimTypeShort(signed=False, label="UInt16"), "file": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "process": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "module": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "callerReturnAddressOffset": SimTypeInt(signed=False, label="UInt32"), "callerModule": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "message": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "originLineNumber": SimTypeShort(signed=False, label="UInt16"), "originFile": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "originModule": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "originCallerReturnAddressOffset": SimTypeInt(signed=False, label="UInt32"), "originCallerModule": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "originName": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="FEATURE_ERROR", pack=False, align=None), offset=0)], SimTypeBottom(label="Void"), arg_names=["featureId", "error"]),
        #
        'SubscribeFeatureStateChangeNotification': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["context"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["subscription", "callback", "context"]),
        #
        'UnsubscribeFeatureStateChangeNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["subscription"]),
    }

lib.set_prototypes(prototypes)
