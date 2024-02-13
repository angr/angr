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
lib.set_library_names("hlink.dll")
prototypes = \
    {
        #
        'HlinkCreateFromMoniker': SimTypeFunction([SimTypeBottom(label="IMoniker"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IHlinkSite"), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pimkTrgt", "pwzLocation", "pwzFriendlyName", "pihlsite", "dwSiteData", "piunkOuter", "riid", "ppvObj"]),
        #
        'HlinkCreateFromString': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IHlinkSite"), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzTarget", "pwzLocation", "pwzFriendlyName", "pihlsite", "dwSiteData", "piunkOuter", "riid", "ppvObj"]),
        #
        'HlinkCreateFromData': SimTypeFunction([SimTypeBottom(label="IDataObject"), SimTypeBottom(label="IHlinkSite"), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["piDataObj", "pihlsite", "dwSiteData", "piunkOuter", "riid", "ppvObj"]),
        #
        'HlinkQueryCreateFromData': SimTypeFunction([SimTypeBottom(label="IDataObject")], SimTypeInt(signed=True, label="Int32"), arg_names=["piDataObj"]),
        #
        'HlinkClone': SimTypeFunction([SimTypeBottom(label="IHlink"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeBottom(label="IHlinkSite"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pihl", "riid", "pihlsiteForClone", "dwSiteData", "ppvObj"]),
        #
        'HlinkCreateBrowseContext': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["piunkOuter", "riid", "ppvObj"]),
        #
        'HlinkNavigateToStringReference': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IHlinkSite"), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IHlinkFrame"), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IBindCtx"), SimTypeBottom(label="IBindStatusCallback"), SimTypeBottom(label="IHlinkBrowseContext")], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzTarget", "pwzLocation", "pihlsite", "dwSiteData", "pihlframe", "grfHLNF", "pibc", "pibsc", "pihlbc"]),
        #
        'HlinkNavigate': SimTypeFunction([SimTypeBottom(label="IHlink"), SimTypeBottom(label="IHlinkFrame"), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IBindCtx"), SimTypeBottom(label="IBindStatusCallback"), SimTypeBottom(label="IHlinkBrowseContext")], SimTypeInt(signed=True, label="Int32"), arg_names=["pihl", "pihlframe", "grfHLNF", "pbc", "pibsc", "pihlbc"]),
        #
        'HlinkOnNavigate': SimTypeFunction([SimTypeBottom(label="IHlinkFrame"), SimTypeBottom(label="IHlinkBrowseContext"), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IMoniker"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pihlframe", "pihlbc", "grfHLNF", "pimkTarget", "pwzLocation", "pwzFriendlyName", "puHLID"]),
        #
        'HlinkUpdateStackItem': SimTypeFunction([SimTypeBottom(label="IHlinkFrame"), SimTypeBottom(label="IHlinkBrowseContext"), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IMoniker"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pihlframe", "pihlbc", "uHLID", "pimkTrgt", "pwzLocation", "pwzFriendlyName"]),
        #
        'HlinkOnRenameDocument': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IHlinkBrowseContext"), SimTypeBottom(label="IMoniker"), SimTypeBottom(label="IMoniker")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwReserved", "pihlbc", "pimkOld", "pimkNew"]),
        #
        'HlinkResolveMonikerForData': SimTypeFunction([SimTypeBottom(label="IMoniker"), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IBindCtx"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("FORMATETC", SimStruct), offset=0), SimTypeBottom(label="IBindStatusCallback"), SimTypeBottom(label="IMoniker")], SimTypeInt(signed=True, label="Int32"), arg_names=["pimkReference", "reserved", "pibc", "cFmtetc", "rgFmtetc", "pibsc", "pimkBase"]),
        #
        'HlinkResolveStringForData': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IBindCtx"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("FORMATETC", SimStruct), offset=0), SimTypeBottom(label="IBindStatusCallback"), SimTypeBottom(label="IMoniker")], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzReference", "reserved", "pibc", "cFmtetc", "rgFmtetc", "pibsc", "pimkBase"]),
        #
        'HlinkParseDisplayName': SimTypeFunction([SimTypeBottom(label="IBindCtx"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="IMoniker"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pibc", "pwzDisplayName", "fNoForceAbs", "pcchEaten", "ppimk"]),
        #
        'HlinkCreateExtensionServices': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzAdditionalHeaders", "phwnd", "pszUsername", "pszPassword", "piunkOuter", "riid", "ppvObj"]),
        #
        'HlinkPreprocessMoniker': SimTypeFunction([SimTypeBottom(label="IBindCtx"), SimTypeBottom(label="IMoniker"), SimTypePointer(SimTypeBottom(label="IMoniker"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pibc", "pimkIn", "ppimkOut"]),
        #
        'OleSaveToStreamEx': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypeBottom(label="IStream"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["piunk", "pistm", "fClearDirty"]),
        #
        'HlinkSetSpecialReference': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uReference", "pwzReference"]),
        #
        'HlinkGetSpecialReference': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uReference", "ppwzReference"]),
        #
        'HlinkCreateShortcut': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IHlink"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["grfHLSHORTCUTF", "pihl", "pwzDir", "pwzFileName", "ppwzShortcutFile", "dwReserved"]),
        #
        'HlinkCreateShortcutFromMoniker': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IMoniker"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["grfHLSHORTCUTF", "pimkTarget", "pwzLocation", "pwzDir", "pwzFileName", "ppwzShortcutFile", "dwReserved"]),
        #
        'HlinkCreateShortcutFromString': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["grfHLSHORTCUTF", "pwzTarget", "pwzLocation", "pwzDir", "pwzFileName", "ppwzShortcutFile", "dwReserved"]),
        #
        'HlinkResolveShortcut': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IHlinkSite"), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzShortcutFileName", "pihlsite", "dwSiteData", "piunkOuter", "riid", "ppvObj"]),
        #
        'HlinkResolveShortcutToMoniker': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="IMoniker"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzShortcutFileName", "ppimkTarget", "ppwzLocation"]),
        #
        'HlinkResolveShortcutToString': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzShortcutFileName", "ppwzTarget", "ppwzLocation"]),
        #
        'HlinkIsShortcut': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzFileName"]),
        #
        'HlinkGetValueFromParams': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzParams", "pwzName", "ppwzValue"]),
        #
        'HlinkTranslateURL': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzURL", "grfFlags", "ppwzTranslatedURL"]),
    }

lib.set_prototypes(prototypes)
