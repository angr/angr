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
lib.set_library_names("scarddlg.dll")
prototypes = \
    {
        #
        'SCardUIDlgSelectCardA': SimTypeFunction([SimTypePointer(SimTypeRef("OPENCARDNAME_EXA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'SCardUIDlgSelectCardW': SimTypeFunction([SimTypePointer(SimTypeRef("OPENCARDNAME_EXW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'GetOpenCardNameA': SimTypeFunction([SimTypePointer(SimTypeRef("OPENCARDNAMEA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'GetOpenCardNameW': SimTypeFunction([SimTypePointer(SimTypeRef("OPENCARDNAMEW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]),
        #
        'SCardDlgExtendedError': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
    }

lib.set_prototypes(prototypes)
