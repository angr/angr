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
lib.set_library_names("comsvcs.dll")
prototypes = \
    {
        # 
        'CoCreateActivity': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pIUnknown", "riid", "ppObj"]),
        # 
        'CoEnterServiceDomain': SimTypeFunction([SimTypeBottom(label="IUnknown")], SimTypeInt(signed=True, label="Int32"), arg_names=["pConfigObject"]),
        # 
        'CoLeaveServiceDomain': SimTypeFunction([SimTypeBottom(label="IUnknown")], SimTypeBottom(label="Void"), arg_names=["pUnkStatus"]),
        # 
        'GetManagedExtensions': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwExts"]),
        # 
        'SafeRef': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeBottom(label="IUnknown")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["rid", "pUnk"]),
        # 
        'RecycleSurrogate': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lReasonCode"]),
        # 
        'MTSCreateActivity': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["riid", "ppobj"]),
    }

lib.set_prototypes(prototypes)
