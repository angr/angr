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
lib.set_library_names("compstui.dll")
prototypes = \
    {
        # 
        'CommonPropertySheetUIA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimStruct({"cbSize": SimTypeShort(signed=False, label="UInt16"), "Version": SimTypeShort(signed=False, label="UInt16"), "Flags": SimTypeShort(signed=False, label="UInt16"), "Reason": SimTypeShort(signed=False, label="UInt16"), "hComPropSheet": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "pfnComPropSheet": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hComPropSheet", "Function", "lParam1", "lParam2"]), offset=0), "lParamInit": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "UserData": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "Result": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)}, name="PROPSHEETUI_INFO", pack=False, align=None), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pPSUIInfo", "lParam"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWndOwner", "pfnPropSheetUI", "lParam", "pResult"]),
        # 
        'CommonPropertySheetUIW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimStruct({"cbSize": SimTypeShort(signed=False, label="UInt16"), "Version": SimTypeShort(signed=False, label="UInt16"), "Flags": SimTypeShort(signed=False, label="UInt16"), "Reason": SimTypeShort(signed=False, label="UInt16"), "hComPropSheet": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "pfnComPropSheet": SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hComPropSheet", "Function", "lParam1", "lParam2"]), offset=0), "lParamInit": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "UserData": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), "Result": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)}, name="PROPSHEETUI_INFO", pack=False, align=None), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pPSUIInfo", "lParam"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWndOwner", "pfnPropSheetUI", "lParam", "pResult"]),
        # 
        'GetCPSUIUserData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["hDlg"]),
        # 
        'SetCPSUIUserData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDlg", "CPSUIUserData"]),
    }

lib.set_prototypes(prototypes)
