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
lib.set_library_names("winfax.dll")
prototypes = \
    {
        #
        'FaxConnectFaxServerA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["MachineName", "FaxHandle"]),
        #
        'FaxConnectFaxServerW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["MachineName", "FaxHandle"]),
        #
        'FaxClose': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle"]),
        #
        'FaxOpenPort': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "DeviceId", "Flags", "FaxPortHandle"]),
        #
        'FaxCompleteJobParamsA': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("FAX_JOB_PARAMA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("FAX_COVERPAGE_INFOA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["JobParams", "CoverpageInfo"]),
        #
        'FaxCompleteJobParamsW': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeRef("FAX_JOB_PARAMW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("FAX_COVERPAGE_INFOW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["JobParams", "CoverpageInfo"]),
        #
        'FaxSendDocumentA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("FAX_JOB_PARAMA", SimStruct), offset=0), SimTypePointer(SimTypeRef("FAX_COVERPAGE_INFOA", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "FileName", "JobParams", "CoverpageInfo", "FaxJobId"]),
        #
        'FaxSendDocumentW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("FAX_JOB_PARAMW", SimStruct), offset=0), SimTypePointer(SimTypeRef("FAX_COVERPAGE_INFOW", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "FileName", "JobParams", "CoverpageInfo", "FaxJobId"]),
        #
        'FaxSendDocumentForBroadcastA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("FAX_JOB_PARAMA", SimStruct), offset=0), SimTypePointer(SimTypeRef("FAX_COVERPAGE_INFOA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "RecipientNumber", "Context", "JobParams", "CoverpageInfo"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "FileName", "FaxJobId", "FaxRecipientCallback", "Context"]),
        #
        'FaxSendDocumentForBroadcastW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeRef("FAX_JOB_PARAMW", SimStruct), offset=0), SimTypePointer(SimTypeRef("FAX_COVERPAGE_INFOW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "RecipientNumber", "Context", "JobParams", "CoverpageInfo"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "FileName", "FaxJobId", "FaxRecipientCallback", "Context"]),
        #
        'FaxEnumJobsA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("FAX_JOB_ENTRYA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "JobEntry", "JobsReturned"]),
        #
        'FaxEnumJobsW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("FAX_JOB_ENTRYW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "JobEntry", "JobsReturned"]),
        #
        'FaxGetJobA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("FAX_JOB_ENTRYA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "JobId", "JobEntry"]),
        #
        'FaxGetJobW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("FAX_JOB_ENTRYW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "JobId", "JobEntry"]),
        #
        'FaxSetJobA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("FAX_JOB_ENTRYA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "JobId", "Command", "JobEntry"]),
        #
        'FaxSetJobW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("FAX_JOB_ENTRYW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "JobId", "Command", "JobEntry"]),
        #
        'FaxGetPageData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "JobId", "Buffer", "BufferSize", "ImageWidth", "ImageHeight"]),
        #
        'FaxGetDeviceStatusA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("FAX_DEVICE_STATUSA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxPortHandle", "DeviceStatus"]),
        #
        'FaxGetDeviceStatusW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("FAX_DEVICE_STATUSW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxPortHandle", "DeviceStatus"]),
        #
        'FaxAbort': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "JobId"]),
        #
        'FaxGetConfigurationA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("FAX_CONFIGURATIONA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "FaxConfig"]),
        #
        'FaxGetConfigurationW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("FAX_CONFIGURATIONW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "FaxConfig"]),
        #
        'FaxSetConfigurationA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FAX_CONFIGURATIONA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "FaxConfig"]),
        #
        'FaxSetConfigurationW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FAX_CONFIGURATIONW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "FaxConfig"]),
        #
        'FaxGetLoggingCategoriesA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("FAX_LOG_CATEGORYA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "Categories", "NumberCategories"]),
        #
        'FaxGetLoggingCategoriesW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("FAX_LOG_CATEGORYW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "Categories", "NumberCategories"]),
        #
        'FaxSetLoggingCategoriesA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FAX_LOG_CATEGORYA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "Categories", "NumberCategories"]),
        #
        'FaxSetLoggingCategoriesW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FAX_LOG_CATEGORYW", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "Categories", "NumberCategories"]),
        #
        'FaxEnumPortsA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("FAX_PORT_INFOA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "PortInfo", "PortsReturned"]),
        #
        'FaxEnumPortsW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("FAX_PORT_INFOW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "PortInfo", "PortsReturned"]),
        #
        'FaxGetPortA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("FAX_PORT_INFOA", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxPortHandle", "PortInfo"]),
        #
        'FaxGetPortW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("FAX_PORT_INFOW", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxPortHandle", "PortInfo"]),
        #
        'FaxSetPortA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FAX_PORT_INFOA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxPortHandle", "PortInfo"]),
        #
        'FaxSetPortW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FAX_PORT_INFOW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxPortHandle", "PortInfo"]),
        #
        'FaxEnumRoutingMethodsA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("FAX_ROUTING_METHODA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxPortHandle", "RoutingMethod", "MethodsReturned"]),
        #
        'FaxEnumRoutingMethodsW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("FAX_ROUTING_METHODW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxPortHandle", "RoutingMethod", "MethodsReturned"]),
        #
        'FaxEnableRoutingMethodA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxPortHandle", "RoutingGuid", "Enabled"]),
        #
        'FaxEnableRoutingMethodW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxPortHandle", "RoutingGuid", "Enabled"]),
        #
        'FaxEnumGlobalRoutingInfoA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("FAX_GLOBAL_ROUTING_INFOA", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "RoutingInfo", "MethodsReturned"]),
        #
        'FaxEnumGlobalRoutingInfoW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("FAX_GLOBAL_ROUTING_INFOW", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "RoutingInfo", "MethodsReturned"]),
        #
        'FaxSetGlobalRoutingInfoA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FAX_GLOBAL_ROUTING_INFOA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "RoutingInfo"]),
        #
        'FaxSetGlobalRoutingInfoW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("FAX_GLOBAL_ROUTING_INFOW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "RoutingInfo"]),
        #
        'FaxGetRoutingInfoA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxPortHandle", "RoutingGuid", "RoutingInfoBuffer", "RoutingInfoBufferSize"]),
        #
        'FaxGetRoutingInfoW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxPortHandle", "RoutingGuid", "RoutingInfoBuffer", "RoutingInfoBufferSize"]),
        #
        'FaxSetRoutingInfoA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxPortHandle", "RoutingGuid", "RoutingInfoBuffer", "RoutingInfoBufferSize"]),
        #
        'FaxSetRoutingInfoW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxPortHandle", "RoutingGuid", "RoutingInfoBuffer", "RoutingInfoBufferSize"]),
        #
        'FaxInitializeEventQueue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "CompletionPort", "CompletionKey", "hWnd", "MessageStart"]),
        #
        'FaxFreeBuffer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["Buffer"]),
        #
        'FaxStartPrintJobA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("FAX_PRINT_INFOA", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("FAX_CONTEXT_INFOA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PrinterName", "PrintInfo", "FaxJobId", "FaxContextInfo"]),
        #
        'FaxStartPrintJobW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("FAX_PRINT_INFOW", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("FAX_CONTEXT_INFOW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PrinterName", "PrintInfo", "FaxJobId", "FaxContextInfo"]),
        #
        'FaxPrintCoverPageA': SimTypeFunction([SimTypePointer(SimTypeRef("FAX_CONTEXT_INFOA", SimStruct), offset=0), SimTypePointer(SimTypeRef("FAX_COVERPAGE_INFOA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxContextInfo", "CoverPageInfo"]),
        #
        'FaxPrintCoverPageW': SimTypeFunction([SimTypePointer(SimTypeRef("FAX_CONTEXT_INFOW", SimStruct), offset=0), SimTypePointer(SimTypeRef("FAX_COVERPAGE_INFOW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxContextInfo", "CoverPageInfo"]),
        #
        'FaxRegisterServiceProviderW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceProvider", "FriendlyName", "ImageName", "TspName"]),
        #
        'FaxUnregisterServiceProviderW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["DeviceProvider"]),
        #
        'FaxRegisterRoutingExtensionW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "Context", "MethodName", "FriendlyName", "FunctionName", "Guid"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "ExtensionName", "FriendlyName", "ImageName", "CallBack", "Context"]),
        #
        'FaxAccessCheck': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FaxHandle", "AccessMask"]),
    }

lib.set_prototypes(prototypes)
