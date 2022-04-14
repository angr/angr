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
lib.set_library_names("api-ms-win-core-psm-appnotify-l1-1-0.dll")
prototypes = \
    {
        # 
        'RegisterAppStateChangeNotification': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypeChar(label="Byte"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Quiesced", "Context"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimStruct({}, name="_APPSTATE_REGISTRATION", pack=False, align=None), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Routine", "Context", "Registration"]),
        # 
        'UnregisterAppStateChangeNotification': SimTypeFunction([SimTypePointer(SimStruct({}, name="_APPSTATE_REGISTRATION", pack=False, align=None), offset=0)], SimTypeBottom(label="Void"), arg_names=["Registration"]),
    }

lib.set_prototypes(prototypes)
