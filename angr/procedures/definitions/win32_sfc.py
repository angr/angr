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
lib.set_library_names("sfc.dll")
prototypes = \
    {
        #
        'SfcGetNextProtectedFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PROTECTED_FILE_DATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["RpcHandle", "ProtFileData"]),
        #
        'SfcIsFileProtected': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["RpcHandle", "ProtFileName"]),
        #
        'SfcIsKeyProtected': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["KeyHandle", "SubKeyName", "KeySam"]),
        #
        'SfpVerifyFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszFileName", "pszError", "dwErrSize"]),
        #
        'SRSetRestorePointA': SimTypeFunction([SimTypePointer(SimTypeRef("RESTOREPOINTINFOA", SimStruct), offset=0), SimTypePointer(SimTypeRef("STATEMGRSTATUS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pRestorePtSpec", "pSMgrStatus"]),
        #
        'SRSetRestorePointW': SimTypeFunction([SimTypePointer(SimTypeRef("RESTOREPOINTINFOW", SimStruct), offset=0), SimTypePointer(SimTypeRef("STATEMGRSTATUS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pRestorePtSpec", "pSMgrStatus"]),
    }

lib.set_prototypes(prototypes)
