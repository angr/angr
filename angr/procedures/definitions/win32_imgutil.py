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
lib.set_library_names("imgutil.dll")
prototypes = \
    {
        #
        'CreateMIMEMap': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMapMIMEToCLSID"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppMap"]),
        #
        'DecodeImage': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypeBottom(label="IMapMIMEToCLSID"), SimTypeBottom(label="IUnknown")], SimTypeInt(signed=True, label="Int32"), arg_names=["pStream", "pMap", "pEventSink"]),
        #
        'SniffStream': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="IStream"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pInStream", "pnFormat", "ppOutStream"]),
        #
        'GetMaxMIMEIDBytes': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pnMaxBytes"]),
        #
        'IdentifyMIMEType': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pbBytes", "nBytes", "pnFormat"]),
        #
        'ComputeInvCMAP': SimTypeFunction([SimTypePointer(SimTypeRef("RGBQUAD", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pRGBColors", "nColors", "pInvTable", "cbTable"]),
        #
        'DitherTo8': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeRef("RGBQUAD", SimStruct), offset=0), SimTypePointer(SimTypeRef("RGBQUAD", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pDestBits", "nDestPitch", "pSrcBits", "nSrcPitch", "bfidSrc", "prgbDestColors", "prgbSrcColors", "pbDestInvMap", "x", "y", "cx", "cy", "lDestTrans", "lSrcTrans"]),
        #
        'CreateDDrawSurfaceOnDIB': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="IDirectDrawSurface"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hbmDib", "ppSurface"]),
        #
        'DecodeImageEx': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypeBottom(label="IMapMIMEToCLSID"), SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pStream", "pMap", "pEventSink", "pszMIMETypeParam"]),
    }

lib.set_prototypes(prototypes)
