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
lib.set_library_names("mfreadwrite.dll")
prototypes = \
    {
        #
        'MFCreateSourceReaderFromURL': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IMFAttributes"), SimTypePointer(SimTypeBottom(label="IMFSourceReader"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszURL", "pAttributes", "ppSourceReader"]),
        #
        'MFCreateSourceReaderFromByteStream': SimTypeFunction([SimTypeBottom(label="IMFByteStream"), SimTypeBottom(label="IMFAttributes"), SimTypePointer(SimTypeBottom(label="IMFSourceReader"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pByteStream", "pAttributes", "ppSourceReader"]),
        #
        'MFCreateSourceReaderFromMediaSource': SimTypeFunction([SimTypeBottom(label="IMFMediaSource"), SimTypeBottom(label="IMFAttributes"), SimTypePointer(SimTypeBottom(label="IMFSourceReader"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMediaSource", "pAttributes", "ppSourceReader"]),
        #
        'MFCreateSinkWriterFromURL': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IMFByteStream"), SimTypeBottom(label="IMFAttributes"), SimTypePointer(SimTypeBottom(label="IMFSinkWriter"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszOutputURL", "pByteStream", "pAttributes", "ppSinkWriter"]),
        #
        'MFCreateSinkWriterFromMediaSink': SimTypeFunction([SimTypeBottom(label="IMFMediaSink"), SimTypeBottom(label="IMFAttributes"), SimTypePointer(SimTypeBottom(label="IMFSinkWriter"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMediaSink", "pAttributes", "ppSinkWriter"]),
    }

lib.set_prototypes(prototypes)
