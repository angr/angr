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
lib.set_library_names("shdocvw.dll")
prototypes = \
    {
        # 
        'SoftwareUpdateMessageBox': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"cbSize": SimTypeInt(signed=False, label="UInt32"), "dwFlags": SimTypeInt(signed=False, label="UInt32"), "dwAdState": SimTypeInt(signed=False, label="UInt32"), "szTitle": SimTypePointer(SimTypeChar(label="Char"), offset=0), "szAbstract": SimTypePointer(SimTypeChar(label="Char"), offset=0), "szHREF": SimTypePointer(SimTypeChar(label="Char"), offset=0), "dwInstalledVersionMS": SimTypeInt(signed=False, label="UInt32"), "dwInstalledVersionLS": SimTypeInt(signed=False, label="UInt32"), "dwUpdateVersionMS": SimTypeInt(signed=False, label="UInt32"), "dwUpdateVersionLS": SimTypeInt(signed=False, label="UInt32"), "dwAdvertisedVersionMS": SimTypeInt(signed=False, label="UInt32"), "dwAdvertisedVersionLS": SimTypeInt(signed=False, label="UInt32"), "dwReserved": SimTypeInt(signed=False, label="UInt32")}, name="SOFTDISTINFO", pack=False, align=None), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hWnd", "pszDistUnit", "dwFlags", "psdi"]),
        # 
        'ImportPrivacySettings': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszFilename", "pfParsePrivacyPreferences", "pfParsePerSiteRules"]),
        # 
        'DoPrivacyDlg': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IEnumPrivacyRecords"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndOwner", "pszUrl", "pPrivacyEnum", "fReportAllSites"]),
    }

lib.set_prototypes(prototypes)
