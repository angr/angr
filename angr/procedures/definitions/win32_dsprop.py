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
lib.set_library_names("dsprop.dll")
prototypes = \
    {
        #
        'ADsPropCreateNotifyObj': SimTypeFunction([SimTypeBottom(label="IDataObject"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAppThdDataObj", "pwzADsObjName", "phNotifyObj"]),
        #
        'ADsPropGetInitInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("ADSPROPINITPARAMS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hNotifyObj", "pInitParams"]),
        #
        'ADsPropSetHwndWithTitle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="SByte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hNotifyObj", "hPage", "ptzTitle"]),
        #
        'ADsPropSetHwnd': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hNotifyObj", "hPage"]),
        #
        'ADsPropCheckIfWritable': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("ADS_ATTR_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwzAttr", "pWritableAttrs"]),
        #
        'ADsPropSendErrorMessage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("ADSPROPERROR", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hNotifyObj", "pError"]),
        #
        'ADsPropShowErrorDialog': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hNotifyObj", "hPage"]),
    }

lib.set_prototypes(prototypes)
