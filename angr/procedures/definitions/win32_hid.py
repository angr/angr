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
lib.set_library_names("hid.dll")
prototypes = \
    {
        #
        'HidP_GetCaps': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("HIDP_CAPS", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["PreparsedData", "Capabilities"]),
        #
        'HidP_GetLinkCollectionNodes': SimTypeFunction([SimTypePointer(SimTypeRef("HIDP_LINK_COLLECTION_NODE", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["LinkCollectionNodes", "LinkCollectionNodesLength", "PreparsedData"]),
        #
        'HidP_GetSpecificButtonCaps': SimTypeFunction([SimTypeInt(signed=False, label="HIDP_REPORT_TYPE"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("HIDP_BUTTON_CAPS", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ReportType", "UsagePage", "LinkCollection", "Usage", "ButtonCaps", "ButtonCapsLength", "PreparsedData"]),
        #
        'HidP_GetButtonCaps': SimTypeFunction([SimTypeInt(signed=False, label="HIDP_REPORT_TYPE"), SimTypePointer(SimTypeRef("HIDP_BUTTON_CAPS", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ReportType", "ButtonCaps", "ButtonCapsLength", "PreparsedData"]),
        #
        'HidP_GetSpecificValueCaps': SimTypeFunction([SimTypeInt(signed=False, label="HIDP_REPORT_TYPE"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("HIDP_VALUE_CAPS", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ReportType", "UsagePage", "LinkCollection", "Usage", "ValueCaps", "ValueCapsLength", "PreparsedData"]),
        #
        'HidP_GetValueCaps': SimTypeFunction([SimTypeInt(signed=False, label="HIDP_REPORT_TYPE"), SimTypePointer(SimTypeRef("HIDP_VALUE_CAPS", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ReportType", "ValueCaps", "ValueCapsLength", "PreparsedData"]),
        #
        'HidP_GetExtendedAttributes': SimTypeFunction([SimTypeInt(signed=False, label="HIDP_REPORT_TYPE"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("HIDP_EXTENDED_ATTRIBUTES", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ReportType", "DataIndex", "PreparsedData", "Attributes", "LengthAttributes"]),
        #
        'HidP_InitializeReportForID': SimTypeFunction([SimTypeInt(signed=False, label="HIDP_REPORT_TYPE"), SimTypeChar(label="Byte"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ReportType", "ReportID", "PreparsedData", "Report", "ReportLength"]),
        #
        'HidP_SetData': SimTypeFunction([SimTypeInt(signed=False, label="HIDP_REPORT_TYPE"), SimTypePointer(SimTypeRef("HIDP_DATA", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ReportType", "DataList", "DataLength", "PreparsedData", "Report", "ReportLength"]),
        #
        'HidP_GetData': SimTypeFunction([SimTypeInt(signed=False, label="HIDP_REPORT_TYPE"), SimTypePointer(SimTypeRef("HIDP_DATA", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ReportType", "DataList", "DataLength", "PreparsedData", "Report", "ReportLength"]),
        #
        'HidP_MaxDataListLength': SimTypeFunction([SimTypeInt(signed=False, label="HIDP_REPORT_TYPE"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ReportType", "PreparsedData"]),
        #
        'HidP_SetUsages': SimTypeFunction([SimTypeInt(signed=False, label="HIDP_REPORT_TYPE"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ReportType", "UsagePage", "LinkCollection", "UsageList", "UsageLength", "PreparsedData", "Report", "ReportLength"]),
        #
        'HidP_UnsetUsages': SimTypeFunction([SimTypeInt(signed=False, label="HIDP_REPORT_TYPE"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ReportType", "UsagePage", "LinkCollection", "UsageList", "UsageLength", "PreparsedData", "Report", "ReportLength"]),
        #
        'HidP_GetUsages': SimTypeFunction([SimTypeInt(signed=False, label="HIDP_REPORT_TYPE"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ReportType", "UsagePage", "LinkCollection", "UsageList", "UsageLength", "PreparsedData", "Report", "ReportLength"]),
        #
        'HidP_GetUsagesEx': SimTypeFunction([SimTypeInt(signed=False, label="HIDP_REPORT_TYPE"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("USAGE_AND_PAGE", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ReportType", "LinkCollection", "ButtonList", "UsageLength", "PreparsedData", "Report", "ReportLength"]),
        #
        'HidP_MaxUsageListLength': SimTypeFunction([SimTypeInt(signed=False, label="HIDP_REPORT_TYPE"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ReportType", "UsagePage", "PreparsedData"]),
        #
        'HidP_SetUsageValue': SimTypeFunction([SimTypeInt(signed=False, label="HIDP_REPORT_TYPE"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ReportType", "UsagePage", "LinkCollection", "Usage", "UsageValue", "PreparsedData", "Report", "ReportLength"]),
        #
        'HidP_SetScaledUsageValue': SimTypeFunction([SimTypeInt(signed=False, label="HIDP_REPORT_TYPE"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ReportType", "UsagePage", "LinkCollection", "Usage", "UsageValue", "PreparsedData", "Report", "ReportLength"]),
        #
        'HidP_SetUsageValueArray': SimTypeFunction([SimTypeInt(signed=False, label="HIDP_REPORT_TYPE"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ReportType", "UsagePage", "LinkCollection", "Usage", "UsageValue", "UsageValueByteLength", "PreparsedData", "Report", "ReportLength"]),
        #
        'HidP_GetUsageValue': SimTypeFunction([SimTypeInt(signed=False, label="HIDP_REPORT_TYPE"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ReportType", "UsagePage", "LinkCollection", "Usage", "UsageValue", "PreparsedData", "Report", "ReportLength"]),
        #
        'HidP_GetScaledUsageValue': SimTypeFunction([SimTypeInt(signed=False, label="HIDP_REPORT_TYPE"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ReportType", "UsagePage", "LinkCollection", "Usage", "UsageValue", "PreparsedData", "Report", "ReportLength"]),
        #
        'HidP_GetUsageValueArray': SimTypeFunction([SimTypeInt(signed=False, label="HIDP_REPORT_TYPE"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ReportType", "UsagePage", "LinkCollection", "Usage", "UsageValue", "UsageValueByteLength", "PreparsedData", "Report", "ReportLength"]),
        #
        'HidP_UsageListDifference': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["PreviousUsageList", "CurrentUsageList", "BreakUsageList", "MakeUsageList", "UsageListLength"]),
        #
        'HidP_GetButtonArray': SimTypeFunction([SimTypeInt(signed=False, label="HIDP_REPORT_TYPE"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("HIDP_BUTTON_ARRAY_DATA", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ReportType", "UsagePage", "LinkCollection", "Usage", "ButtonData", "ButtonDataLength", "PreparsedData", "Report", "ReportLength"]),
        #
        'HidP_SetButtonArray': SimTypeFunction([SimTypeInt(signed=False, label="HIDP_REPORT_TYPE"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("HIDP_BUTTON_ARRAY_DATA", SimStruct), label="LPArray", offset=0), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ReportType", "UsagePage", "LinkCollection", "Usage", "ButtonData", "ButtonDataLength", "PreparsedData", "Report", "ReportLength"]),
        #
        'HidP_TranslateUsagesToI8042ScanCodes': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="HIDP_KEYBOARD_DIRECTION"), SimTypePointer(SimTypeRef("HIDP_KEYBOARD_MODIFIER_STATE", SimStruct), offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["Context", "NewScanCodes", "Length"]), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ChangedUsageList", "UsageListLength", "KeyAction", "ModifierState", "InsertCodesProcedure", "InsertCodesContext"]),
        #
        'HidD_GetAttributes': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("HIDD_ATTRIBUTES", SimStruct), offset=0)], SimTypeChar(label="Byte"), arg_names=["HidDeviceObject", "Attributes"]),
        #
        'HidD_GetHidGuid': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeBottom(label="Void"), arg_names=["HidGuid"]),
        #
        'HidD_GetPreparsedData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeChar(label="Byte"), arg_names=["HidDeviceObject", "PreparsedData"]),
        #
        'HidD_FreePreparsedData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeChar(label="Byte"), arg_names=["PreparsedData"]),
        #
        'HidD_FlushQueue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeChar(label="Byte"), arg_names=["HidDeviceObject"]),
        #
        'HidD_GetConfiguration': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("HIDD_CONFIGURATION", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["HidDeviceObject", "Configuration", "ConfigurationLength"]),
        #
        'HidD_SetConfiguration': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("HIDD_CONFIGURATION", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["HidDeviceObject", "Configuration", "ConfigurationLength"]),
        #
        'HidD_GetFeature': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["HidDeviceObject", "ReportBuffer", "ReportBufferLength"]),
        #
        'HidD_SetFeature': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["HidDeviceObject", "ReportBuffer", "ReportBufferLength"]),
        #
        'HidD_GetInputReport': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["HidDeviceObject", "ReportBuffer", "ReportBufferLength"]),
        #
        'HidD_SetOutputReport': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["HidDeviceObject", "ReportBuffer", "ReportBufferLength"]),
        #
        'HidD_GetNumInputBuffers': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeChar(label="Byte"), arg_names=["HidDeviceObject", "NumberBuffers"]),
        #
        'HidD_SetNumInputBuffers': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["HidDeviceObject", "NumberBuffers"]),
        #
        'HidD_GetPhysicalDescriptor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["HidDeviceObject", "Buffer", "BufferLength"]),
        #
        'HidD_GetManufacturerString': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["HidDeviceObject", "Buffer", "BufferLength"]),
        #
        'HidD_GetProductString': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["HidDeviceObject", "Buffer", "BufferLength"]),
        #
        'HidD_GetIndexedString': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["HidDeviceObject", "StringIndex", "Buffer", "BufferLength"]),
        #
        'HidD_GetSerialNumberString': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["HidDeviceObject", "Buffer", "BufferLength"]),
        #
        'HidD_GetMsGenreDescriptor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeChar(label="Byte"), arg_names=["HidDeviceObject", "Buffer", "BufferLength"]),
    }

lib.set_prototypes(prototypes)
