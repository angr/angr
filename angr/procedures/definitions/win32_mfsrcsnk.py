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
lib.set_library_names("mfsrcsnk.dll")
prototypes = \
    {
        #
        'MFCreateAVIMediaSink': SimTypeFunction([SimTypeBottom(label="IMFByteStream"), SimTypeBottom(label="IMFMediaType"), SimTypeBottom(label="IMFMediaType"), SimTypePointer(SimTypeBottom(label="IMFMediaSink"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pIByteStream", "pVideoMediaType", "pAudioMediaType", "ppIMediaSink"]),
        #
        'MFCreateWAVEMediaSink': SimTypeFunction([SimTypeBottom(label="IMFByteStream"), SimTypeBottom(label="IMFMediaType"), SimTypePointer(SimTypeBottom(label="IMFMediaSink"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pTargetByteStream", "pAudioMediaType", "ppMediaSink"]),
    }

lib.set_prototypes(prototypes)
