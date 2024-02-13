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
lib.set_library_names("spoolss.dll")
prototypes = \
    {
        #
        'GetJobAttributes': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DEVMODEW", SimStruct), offset=0), SimTypePointer(SimTypeRef("ATTRIBUTE_INFO_3", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pPrinterName", "pDevmode", "pAttributeInfo"]),
        #
        'GetJobAttributesEx': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("DEVMODEW", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pPrinterName", "pDevmode", "dwLevel", "pAttributeInfo", "nSize", "dwFlags"]),
        #
        'RevertToPrinterSelf': SimTypeFunction([], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)),
        #
        'ImpersonatePrinterClient': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hToken"]),
        #
        'ReplyPrinterChangeNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPrinter", "fdwChangeFlags", "pdwResult", "pPrinterNotifyInfo"]),
        #
        'ReplyPrinterChangeNotificationEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hNotify", "dwColor", "fdwFlags", "pdwResult", "pPrinterNotifyInfo"]),
        #
        'PartialReplyPrinterChangeNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PRINTER_NOTIFY_INFO_DATA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPrinter", "pDataSrc"]),
        #
        'RouterAllocPrinterNotifyInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("PRINTER_NOTIFY_INFO", SimStruct), offset=0), arg_names=["cPrinterNotifyInfoData"]),
        #
        'RouterFreePrinterNotifyInfo': SimTypeFunction([SimTypePointer(SimTypeRef("PRINTER_NOTIFY_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pInfo"]),
        #
        'RouterAllocBidiResponseContainer': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeRef("BIDI_RESPONSE_CONTAINER", SimStruct), offset=0), arg_names=["Count"]),
        #
        'RouterAllocBidiMem': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["NumBytes"]),
        #
        'RouterFreeBidiMem': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pMemPointer"]),
        #
        'AppendPrinterNotifyInfoData': SimTypeFunction([SimTypePointer(SimTypeRef("PRINTER_NOTIFY_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("PRINTER_NOTIFY_INFO_DATA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pInfoDest", "pDataSrc", "fdwFlags"]),
        #
        'CallRouterFindFirstPrinterChangeNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PRINTER_NOTIFY_OPTIONS", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPrinterRPC", "fdwFilterFlags", "fdwOptions", "hNotify", "pPrinterNotifyOptions"]),
        #
        'ProvidorFindFirstPrinterChangeNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPrinter", "fdwFlags", "fdwOptions", "hNotify", "pPrinterNotifyOptions", "pvReserved1"]),
        #
        'ProvidorFindClosePrinterChangeNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPrinter"]),
        #
        'SpoolerFindFirstPrinterChangeNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPrinter", "fdwFilterFlags", "fdwOptions", "pPrinterNotifyOptions", "pvReserved", "pNotificationConfig", "phNotify", "phEvent"]),
        #
        'SpoolerFindNextPrinterChangeNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPrinter", "pfdwChange", "pPrinterNotifyOptions", "ppPrinterNotifyInfo"]),
        #
        'SpoolerRefreshPrinterChangeNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PRINTER_NOTIFY_OPTIONS", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("PRINTER_NOTIFY_INFO", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPrinter", "dwColor", "pOptions", "ppInfo"]),
        #
        'SpoolerFreePrinterNotifyInfo': SimTypeFunction([SimTypePointer(SimTypeRef("PRINTER_NOTIFY_INFO", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pInfo"]),
        #
        'SpoolerFindClosePrinterChangeNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPrinter"]),
        #
        'SplPromptUIInUsersSession': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("SHOWUIPARAMS", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPrinter", "JobId", "pUIParams", "pResponse"]),
        #
        'SplIsSessionZero': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPrinter", "JobId", "pIsSessionZero"]),
        #
        'AddPrintDeviceObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPrinter", "phDeviceObject"]),
        #
        'UpdatePrintDeviceObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hPrinter", "hDeviceObject"]),
        #
        'RemovePrintDeviceObject': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDeviceObject"]),
    }

lib.set_prototypes(prototypes)
