# pylint:disable=line-too-long
from __future__ import annotations
import logging
from collections import OrderedDict

from angr.sim_type import SimTypeFunction, SimTypeShort, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeDouble, SimTypeFloat, SimTypePointer, SimTypeChar, SimStruct, SimTypeArray, SimTypeBottom, SimUnion, SimTypeBool, SimTypeRef
from angr.calling_conventions import SimCCStdcall, SimCCMicrosoftAMD64
from angr.procedures import SIM_PROCEDURES as P
from . import SimLibrary


_l = logging.getLogger(name=__name__)


lib = SimLibrary()
lib.type_collection_names = ["win32"]
lib.set_default_cc("X86", SimCCStdcall)
lib.set_default_cc("AMD64", SimCCMicrosoftAMD64)
lib.set_library_names("ualapi.dll")
prototypes = \
    {
        #
        'UalStart': SimTypeFunction([SimTypePointer(SimTypeRef("UAL_DATA_BLOB", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Data"]),
        #
        'UalStop': SimTypeFunction([SimTypePointer(SimTypeRef("UAL_DATA_BLOB", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Data"]),
        #
        'UalInstrument': SimTypeFunction([SimTypePointer(SimTypeRef("UAL_DATA_BLOB", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Data"]),
        #
        'UalRegisterProduct': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["wszProductName", "wszRoleName", "wszGuid"]),
    }

lib.set_prototypes(prototypes)
