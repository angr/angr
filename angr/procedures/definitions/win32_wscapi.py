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
lib.set_library_names("wscapi.dll")
prototypes = \
    {
        # 
        'WscRegisterForChanges': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpThreadParameter"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Reserved", "phCallbackRegistration", "lpCallbackAddress", "pContext"]),
        # 
        'WscUnRegisterChanges': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hRegistrationHandle"]),
        # 
        'WscRegisterForUserNotifications': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        # 
        'WscGetSecurityProviderHealth': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="WSC_SECURITY_PROVIDER_HEALTH"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Providers", "pHealth"]),
        # 
        'WscQueryAntiMalwareUri': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        # 
        'WscGetAntiMalwareUri': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppszUri"]),
    }

lib.set_prototypes(prototypes)
