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
lib.set_library_names("avifil32.dll")
prototypes = \
    {
        #
        'AVIFileInit': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'AVIFileExit': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'AVIFileAddRef': SimTypeFunction([SimTypeBottom(label="IAVIFile")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pfile"]),
        #
        'AVIFileRelease': SimTypeFunction([SimTypeBottom(label="IAVIFile")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pfile"]),
        #
        'AVIFileOpenA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IAVIFile"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppfile", "szFile", "uMode", "lpHandler"]),
        #
        'AVIFileOpenW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IAVIFile"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppfile", "szFile", "uMode", "lpHandler"]),
        #
        'AVIFileInfoW': SimTypeFunction([SimTypeBottom(label="IAVIFile"), SimTypePointer(SimTypeRef("AVIFILEINFOW", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pfile", "pfi", "lSize"]),
        #
        'AVIFileInfoA': SimTypeFunction([SimTypeBottom(label="IAVIFile"), SimTypePointer(SimTypeRef("AVIFILEINFOA", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pfile", "pfi", "lSize"]),
        #
        'AVIFileGetStream': SimTypeFunction([SimTypeBottom(label="IAVIFile"), SimTypePointer(SimTypeBottom(label="IAVIStream"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pfile", "ppavi", "fccType", "lParam"]),
        #
        'AVIFileCreateStreamW': SimTypeFunction([SimTypeBottom(label="IAVIFile"), SimTypePointer(SimTypeBottom(label="IAVIStream"), offset=0), SimTypePointer(SimTypeRef("AVISTREAMINFOW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pfile", "ppavi", "psi"]),
        #
        'AVIFileCreateStreamA': SimTypeFunction([SimTypeBottom(label="IAVIFile"), SimTypePointer(SimTypeBottom(label="IAVIStream"), offset=0), SimTypePointer(SimTypeRef("AVISTREAMINFOA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pfile", "ppavi", "psi"]),
        #
        'AVIFileWriteData': SimTypeFunction([SimTypeBottom(label="IAVIFile"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pfile", "ckid", "lpData", "cbData"]),
        #
        'AVIFileReadData': SimTypeFunction([SimTypeBottom(label="IAVIFile"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pfile", "ckid", "lpData", "lpcbData"]),
        #
        'AVIFileEndRecord': SimTypeFunction([SimTypeBottom(label="IAVIFile")], SimTypeInt(signed=True, label="Int32"), arg_names=["pfile"]),
        #
        'AVIStreamAddRef': SimTypeFunction([SimTypeBottom(label="IAVIStream")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pavi"]),
        #
        'AVIStreamRelease': SimTypeFunction([SimTypeBottom(label="IAVIStream")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pavi"]),
        #
        'AVIStreamInfoW': SimTypeFunction([SimTypeBottom(label="IAVIStream"), SimTypePointer(SimTypeRef("AVISTREAMINFOW", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pavi", "psi", "lSize"]),
        #
        'AVIStreamInfoA': SimTypeFunction([SimTypeBottom(label="IAVIStream"), SimTypePointer(SimTypeRef("AVISTREAMINFOA", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pavi", "psi", "lSize"]),
        #
        'AVIStreamFindSample': SimTypeFunction([SimTypeBottom(label="IAVIStream"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pavi", "lPos", "lFlags"]),
        #
        'AVIStreamReadFormat': SimTypeFunction([SimTypeBottom(label="IAVIStream"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pavi", "lPos", "lpFormat", "lpcbFormat"]),
        #
        'AVIStreamSetFormat': SimTypeFunction([SimTypeBottom(label="IAVIStream"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pavi", "lPos", "lpFormat", "cbFormat"]),
        #
        'AVIStreamReadData': SimTypeFunction([SimTypeBottom(label="IAVIStream"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pavi", "fcc", "lp", "lpcb"]),
        #
        'AVIStreamWriteData': SimTypeFunction([SimTypeBottom(label="IAVIStream"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pavi", "fcc", "lp", "cb"]),
        #
        'AVIStreamRead': SimTypeFunction([SimTypeBottom(label="IAVIStream"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pavi", "lStart", "lSamples", "lpBuffer", "cbBuffer", "plBytes", "plSamples"]),
        #
        'AVIStreamWrite': SimTypeFunction([SimTypeBottom(label="IAVIStream"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pavi", "lStart", "lSamples", "lpBuffer", "cbBuffer", "dwFlags", "plSampWritten", "plBytesWritten"]),
        #
        'AVIStreamStart': SimTypeFunction([SimTypeBottom(label="IAVIStream")], SimTypeInt(signed=True, label="Int32"), arg_names=["pavi"]),
        #
        'AVIStreamLength': SimTypeFunction([SimTypeBottom(label="IAVIStream")], SimTypeInt(signed=True, label="Int32"), arg_names=["pavi"]),
        #
        'AVIStreamTimeToSample': SimTypeFunction([SimTypeBottom(label="IAVIStream"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pavi", "lTime"]),
        #
        'AVIStreamSampleToTime': SimTypeFunction([SimTypeBottom(label="IAVIStream"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pavi", "lSample"]),
        #
        'AVIStreamBeginStreaming': SimTypeFunction([SimTypeBottom(label="IAVIStream"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pavi", "lStart", "lEnd", "lRate"]),
        #
        'AVIStreamEndStreaming': SimTypeFunction([SimTypeBottom(label="IAVIStream")], SimTypeInt(signed=True, label="Int32"), arg_names=["pavi"]),
        #
        'AVIStreamGetFrameOpen': SimTypeFunction([SimTypeBottom(label="IAVIStream"), SimTypePointer(SimTypeRef("BITMAPINFOHEADER", SimStruct), offset=0)], SimTypeBottom(label="IGetFrame"), arg_names=["pavi", "lpbiWanted"]),
        #
        'AVIStreamGetFrame': SimTypeFunction([SimTypeBottom(label="IGetFrame"), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["pg", "lPos"]),
        #
        'AVIStreamGetFrameClose': SimTypeFunction([SimTypeBottom(label="IGetFrame")], SimTypeInt(signed=True, label="Int32"), arg_names=["pg"]),
        #
        'AVIStreamOpenFromFileA': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IAVIStream"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppavi", "szFile", "fccType", "lParam", "mode", "pclsidHandler"]),
        #
        'AVIStreamOpenFromFileW': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IAVIStream"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppavi", "szFile", "fccType", "lParam", "mode", "pclsidHandler"]),
        #
        'AVIStreamCreate': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IAVIStream"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppavi", "lParam1", "lParam2", "pclsidHandler"]),
        #
        'AVIMakeCompressedStream': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IAVIStream"), offset=0), SimTypeBottom(label="IAVIStream"), SimTypePointer(SimTypeRef("AVICOMPRESSOPTIONS", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppsCompressed", "ppsSource", "lpOptions", "pclsidHandler"]),
        #
        'AVISaveA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeBottom(label="IAVIStream"), SimTypePointer(SimTypeRef("AVICOMPRESSOPTIONS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["szFile", "pclsidHandler", "lpfnCallback", "nStreams", "pfile", "lpOptions"]),
        #
        'AVISaveVA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="IAVIStream"), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("AVICOMPRESSOPTIONS", SimStruct), offset=0), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["szFile", "pclsidHandler", "lpfnCallback", "nStreams", "ppavi", "plpOptions"]),
        #
        'AVISaveW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeBottom(label="IAVIStream"), SimTypePointer(SimTypeRef("AVICOMPRESSOPTIONS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["szFile", "pclsidHandler", "lpfnCallback", "nStreams", "pfile", "lpOptions"]),
        #
        'AVISaveVW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["param0"]), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="IAVIStream"), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("AVICOMPRESSOPTIONS", SimStruct), offset=0), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["szFile", "pclsidHandler", "lpfnCallback", "nStreams", "ppavi", "plpOptions"]),
        #
        'AVISaveOptions': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="IAVIStream"), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("AVICOMPRESSOPTIONS", SimStruct), offset=0), label="LPArray", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hwnd", "uiFlags", "nStreams", "ppavi", "plpOptions"]),
        #
        'AVISaveOptionsFree': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeRef("AVICOMPRESSOPTIONS", SimStruct), offset=0), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["nStreams", "plpOptions"]),
        #
        'AVIBuildFilterW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszFilter", "cbFilter", "fSaving"]),
        #
        'AVIBuildFilterA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpszFilter", "cbFilter", "fSaving"]),
        #
        'AVIMakeFileFromStreams': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IAVIFile"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="IAVIStream"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppfile", "nStreams", "papStreams"]),
        #
        'AVIMakeStreamFromClipboard': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="IAVIStream"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cfFormat", "hGlobal", "ppstream"]),
        #
        'AVIPutFileOnClipboard': SimTypeFunction([SimTypeBottom(label="IAVIFile")], SimTypeInt(signed=True, label="Int32"), arg_names=["pf"]),
        #
        'AVIGetFromClipboard': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IAVIFile"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lppf"]),
        #
        'AVIClearClipboard': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'CreateEditableStream': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IAVIStream"), offset=0), SimTypeBottom(label="IAVIStream")], SimTypeInt(signed=True, label="Int32"), arg_names=["ppsEditable", "psSource"]),
        #
        'EditStreamCut': SimTypeFunction([SimTypeBottom(label="IAVIStream"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeBottom(label="IAVIStream"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pavi", "plStart", "plLength", "ppResult"]),
        #
        'EditStreamCopy': SimTypeFunction([SimTypeBottom(label="IAVIStream"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeBottom(label="IAVIStream"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pavi", "plStart", "plLength", "ppResult"]),
        #
        'EditStreamPaste': SimTypeFunction([SimTypeBottom(label="IAVIStream"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeBottom(label="IAVIStream"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pavi", "plPos", "plLength", "pstream", "lStart", "lEnd"]),
        #
        'EditStreamClone': SimTypeFunction([SimTypeBottom(label="IAVIStream"), SimTypePointer(SimTypeBottom(label="IAVIStream"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pavi", "ppResult"]),
        #
        'EditStreamSetNameA': SimTypeFunction([SimTypeBottom(label="IAVIStream"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pavi", "lpszName"]),
        #
        'EditStreamSetNameW': SimTypeFunction([SimTypeBottom(label="IAVIStream"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pavi", "lpszName"]),
        #
        'EditStreamSetInfoW': SimTypeFunction([SimTypeBottom(label="IAVIStream"), SimTypePointer(SimTypeRef("AVISTREAMINFOW", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pavi", "lpInfo", "cbInfo"]),
        #
        'EditStreamSetInfoA': SimTypeFunction([SimTypeBottom(label="IAVIStream"), SimTypePointer(SimTypeRef("AVISTREAMINFOA", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pavi", "lpInfo", "cbInfo"]),
    }

lib.set_prototypes(prototypes)
