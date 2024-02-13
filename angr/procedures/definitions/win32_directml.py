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
lib.set_library_names("directml.dll")
prototypes = \
    {
        #
        'DMLCreateDevice': SimTypeFunction([SimTypeBottom(label="ID3D12Device"), SimTypeInt(signed=False, label="DML_CREATE_DEVICE_FLAGS"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["d3d12Device", "flags", "riid", "ppv"]),
        #
        'DMLCreateDevice1': SimTypeFunction([SimTypeBottom(label="ID3D12Device"), SimTypeInt(signed=False, label="DML_CREATE_DEVICE_FLAGS"), SimTypeInt(signed=False, label="DML_FEATURE_LEVEL"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["d3d12Device", "flags", "minimumFeatureLevel", "riid", "ppv"]),
    }

lib.set_prototypes(prototypes)
