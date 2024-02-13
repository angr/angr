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
lib.set_library_names("xpsprint.dll")
prototypes = \
    {
        #
        'StartXpsPrintJob': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IXpsPrintJob"), offset=0), SimTypePointer(SimTypeBottom(label="IXpsPrintJobStream"), offset=0), SimTypePointer(SimTypeBottom(label="IXpsPrintJobStream"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["printerName", "jobName", "outputFileName", "progressEvent", "completionEvent", "printablePagesOn", "printablePagesOnCount", "xpsPrintJob", "documentStream", "printTicketStream"]),
        #
        'StartXpsPrintJob1': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="IXpsPrintJob"), offset=0), SimTypePointer(SimTypeBottom(label="IXpsOMPackageTarget"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["printerName", "jobName", "outputFileName", "progressEvent", "completionEvent", "xpsPrintJob", "printContentReceiver"]),
    }

lib.set_prototypes(prototypes)
