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
lib.set_library_names("bcp47mrm.dll")
prototypes = \
    {
        #
        'GetDistanceOfClosestLanguageInList': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeChar(label="Char"), SimTypePointer(SimTypeFloat(size=64), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszLanguage", "pszLanguagesList", "wchListDelimiter", "pClosestDistance"]),
        #
        'IsWellFormedTag': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeChar(label="Byte"), arg_names=["pszTag"]),
    }

lib.set_prototypes(prototypes)
