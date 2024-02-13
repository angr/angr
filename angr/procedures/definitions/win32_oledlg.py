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
lib.set_library_names("oledlg.dll")
prototypes = \
    {
        #
        'OleUIAddVerbMenuW': SimTypeFunction([SimTypeBottom(label="IOleObject"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpOleObj", "lpszShortType", "hMenu", "uPos", "uIDVerbMin", "uIDVerbMax", "bAddConvert", "idConvert", "lphMenu"]),
        #
        'OleUIAddVerbMenuA': SimTypeFunction([SimTypeBottom(label="IOleObject"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpOleObj", "lpszShortType", "hMenu", "uPos", "uIDVerbMin", "uIDVerbMax", "bAddConvert", "idConvert", "lphMenu"]),
        #
        'OleUIInsertObjectW': SimTypeFunction([SimTypePointer(SimTypeRef("OLEUIINSERTOBJECTW", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUIInsertObjectA': SimTypeFunction([SimTypePointer(SimTypeRef("OLEUIINSERTOBJECTA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUIPasteSpecialW': SimTypeFunction([SimTypePointer(SimTypeRef("OLEUIPASTESPECIALW", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUIPasteSpecialA': SimTypeFunction([SimTypePointer(SimTypeRef("OLEUIPASTESPECIALA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUIEditLinksW': SimTypeFunction([SimTypePointer(SimTypeRef("OLEUIEDITLINKSW", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUIEditLinksA': SimTypeFunction([SimTypePointer(SimTypeRef("OLEUIEDITLINKSA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUIChangeIconW': SimTypeFunction([SimTypePointer(SimTypeRef("OLEUICHANGEICONW", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUIChangeIconA': SimTypeFunction([SimTypePointer(SimTypeRef("OLEUICHANGEICONA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUIConvertW': SimTypeFunction([SimTypePointer(SimTypeRef("OLEUICONVERTW", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUIConvertA': SimTypeFunction([SimTypePointer(SimTypeRef("OLEUICONVERTA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUICanConvertOrActivateAs': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeShort(signed=False, label="UInt16")], SimTypeInt(signed=True, label="Int32"), arg_names=["rClsid", "fIsLinkedObject", "wFormat"]),
        #
        'OleUIBusyW': SimTypeFunction([SimTypePointer(SimTypeRef("OLEUIBUSYW", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUIBusyA': SimTypeFunction([SimTypePointer(SimTypeRef("OLEUIBUSYA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUIChangeSourceW': SimTypeFunction([SimTypePointer(SimTypeRef("OLEUICHANGESOURCEW", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUIChangeSourceA': SimTypeFunction([SimTypePointer(SimTypeRef("OLEUICHANGESOURCEA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUIObjectPropertiesW': SimTypeFunction([SimTypePointer(SimTypeRef("OLEUIOBJECTPROPSW", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUIObjectPropertiesA': SimTypeFunction([SimTypePointer(SimTypeRef("OLEUIOBJECTPROPSA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["param0"]),
        #
        'OleUIPromptUserW': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["nTemplate", "hwndParent"]),
        #
        'OleUIPromptUserA': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["nTemplate", "hwndParent"]),
        #
        'OleUIUpdateLinksW': SimTypeFunction([SimTypeBottom(label="IOleUILinkContainerW"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpOleUILinkCntr", "hwndParent", "lpszTitle", "cLinks"]),
        #
        'OleUIUpdateLinksA': SimTypeFunction([SimTypeBottom(label="IOleUILinkContainerA"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpOleUILinkCntr", "hwndParent", "lpszTitle", "cLinks"]),
    }

lib.set_prototypes(prototypes)
