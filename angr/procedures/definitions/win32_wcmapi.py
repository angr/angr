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
lib.set_library_names("wcmapi.dll")
prototypes = \
    {
        #
        'WcmQueryProperty': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="WCM_PROPERTY"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pInterface", "strProfileName", "Property", "pReserved", "pdwDataSize", "ppData"]),
        #
        'WcmSetProperty': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="WCM_PROPERTY"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pInterface", "strProfileName", "Property", "pReserved", "dwDataSize", "pbData"]),
        #
        'WcmGetProfileList': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimStruct({"dwNumberOfItems": SimTypeInt(signed=False, label="UInt32"), "ProfileInfo": SimTypePointer(SimStruct({"strProfileName": SimTypeFixedSizeArray(SimTypeChar(label="Char"), 256), "AdapterGUID": SimTypeBottom(label="Guid"), "Media": SimTypeInt(signed=False, label="WCM_MEDIA_TYPE")}, name="WCM_PROFILE_INFO", pack=False, align=None), offset=0)}, name="WCM_PROFILE_INFO_LIST", pack=False, align=None), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pReserved", "ppProfileList"]),
        #
        'WcmSetProfileList': SimTypeFunction([SimTypePointer(SimStruct({"dwNumberOfItems": SimTypeInt(signed=False, label="UInt32"), "ProfileInfo": SimTypePointer(SimStruct({"strProfileName": SimTypeFixedSizeArray(SimTypeChar(label="Char"), 256), "AdapterGUID": SimTypeBottom(label="Guid"), "Media": SimTypeInt(signed=False, label="WCM_MEDIA_TYPE")}, name="WCM_PROFILE_INFO", pack=False, align=None), offset=0)}, name="WCM_PROFILE_INFO_LIST", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pProfileList", "dwPosition", "fIgnoreUnknownProfiles", "pReserved"]),
        #
        'WcmFreeMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pMemory"]),
    }

lib.set_prototypes(prototypes)
