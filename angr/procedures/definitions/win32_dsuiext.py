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
lib.set_library_names("dsuiext.dll")
prototypes = \
    {
        # 
        'DsBrowseForContainerW': SimTypeFunction([SimTypePointer(SimStruct({"cbStruct": SimTypeInt(signed=False, label="UInt32"), "hwndOwner": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "pszCaption": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pszTitle": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pszRoot": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pszPath": SimTypePointer(SimTypeChar(label="Char"), offset=0), "cchPath": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "pfnCallback": SimTypeBottom(label="BFFCALLBACK"), "lParam": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "dwReturnFormat": SimTypeInt(signed=False, label="UInt32"), "pUserName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pPassword": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pszObjectClass": SimTypePointer(SimTypeChar(label="Char"), offset=0), "cchObjectClass": SimTypeInt(signed=False, label="UInt32")}, name="DSBROWSEINFOW", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pInfo"]),
        # 
        'DsBrowseForContainerA': SimTypeFunction([SimTypePointer(SimStruct({"cbStruct": SimTypeInt(signed=False, label="UInt32"), "hwndOwner": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "pszCaption": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "pszTitle": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "pszRoot": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pszPath": SimTypePointer(SimTypeChar(label="Char"), offset=0), "cchPath": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "pfnCallback": SimTypeBottom(label="BFFCALLBACK"), "lParam": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "dwReturnFormat": SimTypeInt(signed=False, label="UInt32"), "pUserName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pPassword": SimTypePointer(SimTypeChar(label="Char"), offset=0), "pszObjectClass": SimTypePointer(SimTypeChar(label="Char"), offset=0), "cchObjectClass": SimTypeInt(signed=False, label="UInt32")}, name="DSBROWSEINFOA", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pInfo"]),
        # 
        'DsGetIcon': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["dwFlags", "pszObjectClass", "cxImage", "cyImage"]),
        # 
        'DsGetFriendlyClassName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszObjectClass", "pszBuffer", "cchBuffer"]),
    }

lib.set_prototypes(prototypes)
