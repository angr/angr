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
lib.set_library_names("msdmo.dll")
prototypes = \
    {
        #
        'DMORegister': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DMO_PARTIAL_MEDIATYPE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DMO_PARTIAL_MEDIATYPE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["szName", "clsidDMO", "guidCategory", "dwFlags", "cInTypes", "pInTypes", "cOutTypes", "pOutTypes"]),
        #
        'DMOUnregister': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["clsidDMO", "guidCategory"]),
        #
        'DMOEnum': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DMO_PARTIAL_MEDIATYPE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DMO_PARTIAL_MEDIATYPE", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="IEnumDMO"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["guidCategory", "dwFlags", "cInTypes", "pInTypes", "cOutTypes", "pOutTypes", "ppEnum"]),
        #
        'DMOGetTypes': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("DMO_PARTIAL_MEDIATYPE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("DMO_PARTIAL_MEDIATYPE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["clsidDMO", "ulInputTypesRequested", "pulInputTypesSupplied", "pInputTypes", "ulOutputTypesRequested", "pulOutputTypesSupplied", "pOutputTypes"]),
        #
        'DMOGetName': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["clsidDMO", "szName"]),
        #
        'MoInitMediaType': SimTypeFunction([SimTypePointer(SimTypeRef("DMO_MEDIA_TYPE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pmt", "cbFormat"]),
        #
        'MoFreeMediaType': SimTypeFunction([SimTypePointer(SimTypeRef("DMO_MEDIA_TYPE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pmt"]),
        #
        'MoCopyMediaType': SimTypeFunction([SimTypePointer(SimTypeRef("DMO_MEDIA_TYPE", SimStruct), offset=0), SimTypePointer(SimTypeRef("DMO_MEDIA_TYPE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pmtDest", "pmtSrc"]),
        #
        'MoCreateMediaType': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("DMO_MEDIA_TYPE", SimStruct), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ppmt", "cbFormat"]),
        #
        'MoDeleteMediaType': SimTypeFunction([SimTypePointer(SimTypeRef("DMO_MEDIA_TYPE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pmt"]),
        #
        'MoDuplicateMediaType': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("DMO_MEDIA_TYPE", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeRef("DMO_MEDIA_TYPE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppmtDest", "pmtSrc"]),
    }

lib.set_prototypes(prototypes)
