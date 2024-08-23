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
lib.set_library_names("dsuiext.dll")
prototypes = \
    {
        #
        'DsBrowseForContainerW': SimTypeFunction([SimTypePointer(SimTypeRef("DSBROWSEINFOW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pInfo"]),
        #
        'DsBrowseForContainerA': SimTypeFunction([SimTypePointer(SimTypeRef("DSBROWSEINFOA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pInfo"]),
        #
        'DsGetIcon': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["dwFlags", "pszObjectClass", "cxImage", "cyImage"]),
        #
        'DsGetFriendlyClassName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszObjectClass", "pszBuffer", "cchBuffer"]),
    }

lib.set_prototypes(prototypes)
