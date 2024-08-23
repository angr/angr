# pylint:disable=line-too-long
from __future__ import annotations
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
lib.set_library_names("comdlg32.dll")
prototypes = \
    {
        #
        'GetOpenFileNameA': SimTypeFunction([SimTypePointer(SimTypeRef("OPENFILENAMEA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'GetOpenFileNameW': SimTypeFunction([SimTypePointer(SimTypeRef("OPENFILENAMEW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'GetSaveFileNameA': SimTypeFunction([SimTypePointer(SimTypeRef("OPENFILENAMEA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'GetSaveFileNameW': SimTypeFunction([SimTypePointer(SimTypeRef("OPENFILENAMEW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'GetFileTitleA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypeShort(signed=True, label="Int16"), arg_names=["param0", "Buf", "cchSize"]),
        #
        'GetFileTitleW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeShort(signed=False, label="UInt16")], SimTypeShort(signed=True, label="Int16"), arg_names=["param0", "Buf", "cchSize"]),
        #
        'ChooseColorA': SimTypeFunction([SimTypePointer(SimTypeRef("CHOOSECOLORA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'ChooseColorW': SimTypeFunction([SimTypePointer(SimTypeRef("CHOOSECOLORW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'FindTextA': SimTypeFunction([SimTypePointer(SimTypeRef("FINDREPLACEA", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0"]),
        #
        'FindTextW': SimTypeFunction([SimTypePointer(SimTypeRef("FINDREPLACEW", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0"]),
        #
        'ReplaceTextA': SimTypeFunction([SimTypePointer(SimTypeRef("FINDREPLACEA", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0"]),
        #
        'ReplaceTextW': SimTypeFunction([SimTypePointer(SimTypeRef("FINDREPLACEW", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["param0"]),
        #
        'ChooseFontA': SimTypeFunction([SimTypePointer(SimTypeRef("CHOOSEFONTA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'ChooseFontW': SimTypeFunction([SimTypePointer(SimTypeRef("CHOOSEFONTW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'PrintDlgA': SimTypeFunction([SimTypePointer(SimTypeRef("PRINTDLGA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pPD"]),
        #
        'PrintDlgW': SimTypeFunction([SimTypePointer(SimTypeRef("PRINTDLGW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pPD"]),
        #
        'PrintDlgExA': SimTypeFunction([SimTypePointer(SimTypeRef("PRINTDLGEXA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pPD"]),
        #
        'PrintDlgExW': SimTypeFunction([SimTypePointer(SimTypeRef("PRINTDLGEXW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pPD"]),
        #
        'CommDlgExtendedError': SimTypeFunction([], SimTypeInt(signed=False, label="COMMON_DLG_ERRORS")),
        #
        'PageSetupDlgA': SimTypeFunction([SimTypePointer(SimTypeRef("PAGESETUPDLGA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'PageSetupDlgW': SimTypeFunction([SimTypePointer(SimTypeRef("PAGESETUPDLGW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
    }

lib.set_prototypes(prototypes)
