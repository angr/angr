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
lib.set_library_names("elscore.dll")
prototypes = \
    {
        #
        'MappingGetServices': SimTypeFunction([SimTypePointer(SimTypeRef("MAPPING_ENUM_OPTIONS", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("MAPPING_SERVICE_INFO", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pOptions", "prgServices", "pdwServicesCount"]),
        #
        'MappingFreeServices': SimTypeFunction([SimTypePointer(SimTypeRef("MAPPING_SERVICE_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pServiceInfo"]),
        #
        'MappingRecognizeText': SimTypeFunction([SimTypePointer(SimTypeRef("MAPPING_SERVICE_INFO", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MAPPING_OPTIONS", SimStruct), offset=0), SimTypePointer(SimTypeRef("MAPPING_PROPERTY_BAG", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pServiceInfo", "pszText", "dwLength", "dwIndex", "pOptions", "pbag"]),
        #
        'MappingDoAction': SimTypeFunction([SimTypePointer(SimTypeRef("MAPPING_PROPERTY_BAG", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pBag", "dwRangeIndex", "pszActionId"]),
        #
        'MappingFreePropertyBag': SimTypeFunction([SimTypePointer(SimTypeRef("MAPPING_PROPERTY_BAG", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pBag"]),
    }

lib.set_prototypes(prototypes)
