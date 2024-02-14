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
lib.set_library_names("rstrtmgr.dll")
prototypes = \
    {
        #
        'RmStartSession': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["pSessionHandle", "dwSessionFlags", "strSessionKey"]),
        #
        'RmJoinSession': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["pSessionHandle", "strSessionKey"]),
        #
        'RmEndSession': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["dwSessionHandle"]),
        #
        'RmRegisterResources': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("RM_UNIQUE_PROCESS", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), label="LPArray", offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["dwSessionHandle", "nFiles", "rgsFileNames", "nApplications", "rgApplications", "nServices", "rgsServiceNames"]),
        #
        'RmGetList': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("RM_PROCESS_INFO", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["dwSessionHandle", "pnProcInfoNeeded", "pnProcInfo", "rgAffectedApps", "lpdwRebootReasons"]),
        #
        'RmShutdown': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["nPercentComplete"]), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["dwSessionHandle", "lActionFlags", "fnStatus"]),
        #
        'RmRestart': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["nPercentComplete"]), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["dwSessionHandle", "dwRestartFlags", "fnStatus"]),
        #
        'RmCancelCurrentTask': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["dwSessionHandle"]),
        #
        'RmAddFilter': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("RM_UNIQUE_PROCESS", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="RM_FILTER_ACTION")], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["dwSessionHandle", "strModuleName", "pProcess", "strServiceShortName", "FilterAction"]),
        #
        'RmRemoveFilter': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("RM_UNIQUE_PROCESS", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["dwSessionHandle", "strModuleName", "pProcess", "strServiceShortName"]),
        #
        'RmGetFilterList': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="WIN32_ERROR"), arg_names=["dwSessionHandle", "pbFilterBuf", "cbFilterBuf", "cbFilterBufNeeded"]),
    }

lib.set_prototypes(prototypes)
