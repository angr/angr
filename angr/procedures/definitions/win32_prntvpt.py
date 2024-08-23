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
lib.set_library_names("prntvpt.dll")
prototypes = \
    {
        #
        'PTQuerySchemaVersionSupport': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPrinterName", "pMaxVersion"]),
        #
        'PTOpenProvider': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPrinterName", "dwVersion", "phProvider"]),
        #
        'PTOpenProviderEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPrinterName", "dwMaxVersion", "dwPrefVersion", "phProvider", "pUsedVersion"]),
        #
        'PTCloseProvider': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProvider"]),
        #
        'PTReleaseMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pBuffer"]),
        #
        'PTGetPrintCapabilities': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeBottom(label="IStream"), SimTypeBottom(label="IStream"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProvider", "pPrintTicket", "pCapabilities", "pbstrErrorMessage"]),
        #
        'PTGetPrintDeviceCapabilities': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeBottom(label="IStream"), SimTypeBottom(label="IStream"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProvider", "pPrintTicket", "pDeviceCapabilities", "pbstrErrorMessage"]),
        #
        'PTGetPrintDeviceResources': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IStream"), SimTypeBottom(label="IStream"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProvider", "pszLocaleName", "pPrintTicket", "pDeviceResources", "pbstrErrorMessage"]),
        #
        'PTMergeAndValidatePrintTicket': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeBottom(label="IStream"), SimTypeBottom(label="IStream"), SimTypeInt(signed=False, label="EPrintTicketScope"), SimTypeBottom(label="IStream"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProvider", "pBaseTicket", "pDeltaTicket", "scope", "pResultTicket", "pbstrErrorMessage"]),
        #
        'PTConvertPrintTicketToDevMode': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeBottom(label="IStream"), SimTypeInt(signed=False, label="EDefaultDevmodeType"), SimTypeInt(signed=False, label="EPrintTicketScope"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("DEVMODEA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProvider", "pPrintTicket", "baseDevmodeType", "scope", "pcbDevmode", "ppDevmode", "pbstrErrorMessage"]),
        #
        'PTConvertDevModeToPrintTicket': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DEVMODEA", SimStruct), offset=0), SimTypeInt(signed=False, label="EPrintTicketScope"), SimTypeBottom(label="IStream")], SimTypeInt(signed=True, label="Int32"), arg_names=["hProvider", "cbDevmode", "pDevmode", "scope", "pPrintTicket"]),
    }

lib.set_prototypes(prototypes)
