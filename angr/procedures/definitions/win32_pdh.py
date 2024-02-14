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
lib.set_library_names("pdh.dll")
prototypes = \
    {
        #
        'PdhGetDllVersion': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="PDH_DLL_VERSION"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpdwVersion"]),
        #
        'PdhOpenQueryW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szDataSource", "dwUserData", "phQuery"]),
        #
        'PdhOpenQueryA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szDataSource", "dwUserData", "phQuery"]),
        #
        'PdhAddCounterW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hQuery", "szFullCounterPath", "dwUserData", "phCounter"]),
        #
        'PdhAddCounterA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hQuery", "szFullCounterPath", "dwUserData", "phCounter"]),
        #
        'PdhAddEnglishCounterW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hQuery", "szFullCounterPath", "dwUserData", "phCounter"]),
        #
        'PdhAddEnglishCounterA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hQuery", "szFullCounterPath", "dwUserData", "phCounter"]),
        #
        'PdhCollectQueryDataWithTime': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hQuery", "pllTimeStamp"]),
        #
        'PdhValidatePathExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDataSource", "szFullPathBuffer"]),
        #
        'PdhValidatePathExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDataSource", "szFullPathBuffer"]),
        #
        'PdhRemoveCounter': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hCounter"]),
        #
        'PdhCollectQueryData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hQuery"]),
        #
        'PdhCloseQuery': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hQuery"]),
        #
        'PdhGetFormattedCounterValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="PDH_FMT"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("PDH_FMT_COUNTERVALUE", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hCounter", "dwFormat", "lpdwType", "pValue"]),
        #
        'PdhGetFormattedCounterArrayA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="PDH_FMT"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("PDH_FMT_COUNTERVALUE_ITEM_A", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hCounter", "dwFormat", "lpdwBufferSize", "lpdwItemCount", "ItemBuffer"]),
        #
        'PdhGetFormattedCounterArrayW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="PDH_FMT"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("PDH_FMT_COUNTERVALUE_ITEM_W", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hCounter", "dwFormat", "lpdwBufferSize", "lpdwItemCount", "ItemBuffer"]),
        #
        'PdhGetRawCounterValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("PDH_RAW_COUNTER", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hCounter", "lpdwType", "pValue"]),
        #
        'PdhGetRawCounterArrayA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("PDH_RAW_COUNTER_ITEM_A", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hCounter", "lpdwBufferSize", "lpdwItemCount", "ItemBuffer"]),
        #
        'PdhGetRawCounterArrayW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("PDH_RAW_COUNTER_ITEM_W", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hCounter", "lpdwBufferSize", "lpdwItemCount", "ItemBuffer"]),
        #
        'PdhCalculateCounterFromRawValue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="PDH_FMT"), SimTypePointer(SimTypeRef("PDH_RAW_COUNTER", SimStruct), offset=0), SimTypePointer(SimTypeRef("PDH_RAW_COUNTER", SimStruct), offset=0), SimTypePointer(SimTypeRef("PDH_FMT_COUNTERVALUE", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hCounter", "dwFormat", "rawValue1", "rawValue2", "fmtValue"]),
        #
        'PdhComputeCounterStatistics': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="PDH_FMT"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PDH_RAW_COUNTER", SimStruct), offset=0), SimTypePointer(SimTypeRef("PDH_STATISTICS", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hCounter", "dwFormat", "dwFirstEntry", "dwNumEntries", "lpRawValueArray", "data"]),
        #
        'PdhGetCounterInfoW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("PDH_COUNTER_INFO_W", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hCounter", "bRetrieveExplainText", "pdwBufferSize", "lpBuffer"]),
        #
        'PdhGetCounterInfoA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeChar(label="Byte"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("PDH_COUNTER_INFO_A", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hCounter", "bRetrieveExplainText", "pdwBufferSize", "lpBuffer"]),
        #
        'PdhSetCounterScaleFactor': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hCounter", "lFactor"]),
        #
        'PdhConnectMachineW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szMachineName"]),
        #
        'PdhConnectMachineA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szMachineName"]),
        #
        'PdhEnumMachinesW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szDataSource", "mszMachineList", "pcchBufferSize"]),
        #
        'PdhEnumMachinesA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szDataSource", "mszMachineList", "pcchBufferSize"]),
        #
        'PdhEnumObjectsW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="PERF_DETAIL"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szDataSource", "szMachineName", "mszObjectList", "pcchBufferSize", "dwDetailLevel", "bRefresh"]),
        #
        'PdhEnumObjectsA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="PERF_DETAIL"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szDataSource", "szMachineName", "mszObjectList", "pcchBufferSize", "dwDetailLevel", "bRefresh"]),
        #
        'PdhEnumObjectItemsW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="PERF_DETAIL"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szDataSource", "szMachineName", "szObjectName", "mszCounterList", "pcchCounterListLength", "mszInstanceList", "pcchInstanceListLength", "dwDetailLevel", "dwFlags"]),
        #
        'PdhEnumObjectItemsA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="PERF_DETAIL"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szDataSource", "szMachineName", "szObjectName", "mszCounterList", "pcchCounterListLength", "mszInstanceList", "pcchInstanceListLength", "dwDetailLevel", "dwFlags"]),
        #
        'PdhMakeCounterPathW': SimTypeFunction([SimTypePointer(SimTypeRef("PDH_COUNTER_PATH_ELEMENTS_W", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="PDH_PATH_FLAGS")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pCounterPathElements", "szFullPathBuffer", "pcchBufferSize", "dwFlags"]),
        #
        'PdhMakeCounterPathA': SimTypeFunction([SimTypePointer(SimTypeRef("PDH_COUNTER_PATH_ELEMENTS_A", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="PDH_PATH_FLAGS")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pCounterPathElements", "szFullPathBuffer", "pcchBufferSize", "dwFlags"]),
        #
        'PdhParseCounterPathW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("PDH_COUNTER_PATH_ELEMENTS_W", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szFullPathBuffer", "pCounterPathElements", "pdwBufferSize", "dwFlags"]),
        #
        'PdhParseCounterPathA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("PDH_COUNTER_PATH_ELEMENTS_A", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szFullPathBuffer", "pCounterPathElements", "pdwBufferSize", "dwFlags"]),
        #
        'PdhParseInstanceNameW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szInstanceString", "szInstanceName", "pcchInstanceNameLength", "szParentName", "pcchParentNameLength", "lpIndex"]),
        #
        'PdhParseInstanceNameA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szInstanceString", "szInstanceName", "pcchInstanceNameLength", "szParentName", "pcchParentNameLength", "lpIndex"]),
        #
        'PdhValidatePathW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szFullPathBuffer"]),
        #
        'PdhValidatePathA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szFullPathBuffer"]),
        #
        'PdhGetDefaultPerfObjectW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szDataSource", "szMachineName", "szDefaultObjectName", "pcchBufferSize"]),
        #
        'PdhGetDefaultPerfObjectA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szDataSource", "szMachineName", "szDefaultObjectName", "pcchBufferSize"]),
        #
        'PdhGetDefaultPerfCounterW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szDataSource", "szMachineName", "szObjectName", "szDefaultCounterName", "pcchBufferSize"]),
        #
        'PdhGetDefaultPerfCounterA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szDataSource", "szMachineName", "szObjectName", "szDefaultCounterName", "pcchBufferSize"]),
        #
        'PdhBrowseCountersW': SimTypeFunction([SimTypePointer(SimTypeRef("PDH_BROWSE_DLG_CONFIG_W", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pBrowseDlgData"]),
        #
        'PdhBrowseCountersA': SimTypeFunction([SimTypePointer(SimTypeRef("PDH_BROWSE_DLG_CONFIG_A", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pBrowseDlgData"]),
        #
        'PdhExpandCounterPathW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szWildCardPath", "mszExpandedPathList", "pcchPathListLength"]),
        #
        'PdhExpandCounterPathA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szWildCardPath", "mszExpandedPathList", "pcchPathListLength"]),
        #
        'PdhLookupPerfNameByIndexW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szMachineName", "dwNameIndex", "szNameBuffer", "pcchNameBufferSize"]),
        #
        'PdhLookupPerfNameByIndexA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szMachineName", "dwNameIndex", "szNameBuffer", "pcchNameBufferSize"]),
        #
        'PdhLookupPerfIndexByNameW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szMachineName", "szNameBuffer", "pdwIndex"]),
        #
        'PdhLookupPerfIndexByNameA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szMachineName", "szNameBuffer", "pdwIndex"]),
        #
        'PdhExpandWildCardPathA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szDataSource", "szWildCardPath", "mszExpandedPathList", "pcchPathListLength", "dwFlags"]),
        #
        'PdhExpandWildCardPathW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["szDataSource", "szWildCardPath", "mszExpandedPathList", "pcchPathListLength", "dwFlags"]),
        #
        'PdhOpenLogW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="PDH_LOG"), SimTypePointer(SimTypeInt(signed=False, label="PDH_LOG_TYPE"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szLogFileName", "dwAccessFlags", "lpdwLogType", "hQuery", "dwMaxSize", "szUserCaption", "phLog"]),
        #
        'PdhOpenLogA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="PDH_LOG"), SimTypePointer(SimTypeInt(signed=False, label="PDH_LOG_TYPE"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szLogFileName", "dwAccessFlags", "lpdwLogType", "hQuery", "dwMaxSize", "szUserCaption", "phLog"]),
        #
        'PdhUpdateLogW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hLog", "szUserString"]),
        #
        'PdhUpdateLogA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hLog", "szUserString"]),
        #
        'PdhUpdateLogFileCatalog': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hLog"]),
        #
        'PdhGetLogFileSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hLog", "llSize"]),
        #
        'PdhCloseLog': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hLog", "dwFlags"]),
        #
        'PdhSelectDataSourceW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="PDH_SELECT_DATA_SOURCE_FLAGS"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hWndOwner", "dwFlags", "szDataSource", "pcchBufferLength"]),
        #
        'PdhSelectDataSourceA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="PDH_SELECT_DATA_SOURCE_FLAGS"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hWndOwner", "dwFlags", "szDataSource", "pcchBufferLength"]),
        #
        'PdhIsRealTimeQuery': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hQuery"]),
        #
        'PdhSetQueryTimeRange': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PDH_TIME_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hQuery", "pInfo"]),
        #
        'PdhGetDataSourceTimeRangeW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("PDH_TIME_INFO", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szDataSource", "pdwNumEntries", "pInfo", "pdwBufferSize"]),
        #
        'PdhGetDataSourceTimeRangeA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("PDH_TIME_INFO", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szDataSource", "pdwNumEntries", "pInfo", "pdwBufferSize"]),
        #
        'PdhCollectQueryDataEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hQuery", "dwIntervalTime", "hNewDataEvent"]),
        #
        'PdhFormatFromRawValue': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="PDH_FMT"), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0), SimTypePointer(SimTypeRef("PDH_RAW_COUNTER", SimStruct), offset=0), SimTypePointer(SimTypeRef("PDH_RAW_COUNTER", SimStruct), offset=0), SimTypePointer(SimTypeRef("PDH_FMT_COUNTERVALUE", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwCounterType", "dwFormat", "pTimeBase", "pRawValue1", "pRawValue2", "pFmtValue"]),
        #
        'PdhGetCounterTimeBase': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=True, label="Int64"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hCounter", "pTimeBase"]),
        #
        'PdhReadRawLogRecord': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeRef("FILETIME", SimStruct), SimTypePointer(SimTypeRef("PDH_RAW_LOG_RECORD", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hLog", "ftRecord", "pRawLogRecord", "pdwBufferLength"]),
        #
        'PdhSetDefaultRealTimeDataSource': SimTypeFunction([SimTypeInt(signed=False, label="REAL_TIME_DATA_SOURCE_ID_FLAGS")], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwDataSourceId"]),
        #
        'PdhBindInputDataSourceW': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["phDataSource", "LogFileNameList"]),
        #
        'PdhBindInputDataSourceA': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["phDataSource", "LogFileNameList"]),
        #
        'PdhOpenQueryH': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDataSource", "dwUserData", "phQuery"]),
        #
        'PdhEnumMachinesHW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDataSource", "mszMachineList", "pcchBufferSize"]),
        #
        'PdhEnumMachinesHA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDataSource", "mszMachineList", "pcchBufferSize"]),
        #
        'PdhEnumObjectsHW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="PERF_DETAIL"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDataSource", "szMachineName", "mszObjectList", "pcchBufferSize", "dwDetailLevel", "bRefresh"]),
        #
        'PdhEnumObjectsHA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="PERF_DETAIL"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDataSource", "szMachineName", "mszObjectList", "pcchBufferSize", "dwDetailLevel", "bRefresh"]),
        #
        'PdhEnumObjectItemsHW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="PERF_DETAIL"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDataSource", "szMachineName", "szObjectName", "mszCounterList", "pcchCounterListLength", "mszInstanceList", "pcchInstanceListLength", "dwDetailLevel", "dwFlags"]),
        #
        'PdhEnumObjectItemsHA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="PERF_DETAIL"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDataSource", "szMachineName", "szObjectName", "mszCounterList", "pcchCounterListLength", "mszInstanceList", "pcchInstanceListLength", "dwDetailLevel", "dwFlags"]),
        #
        'PdhExpandWildCardPathHW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDataSource", "szWildCardPath", "mszExpandedPathList", "pcchPathListLength", "dwFlags"]),
        #
        'PdhExpandWildCardPathHA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDataSource", "szWildCardPath", "mszExpandedPathList", "pcchPathListLength", "dwFlags"]),
        #
        'PdhGetDataSourceTimeRangeH': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("PDH_TIME_INFO", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDataSource", "pdwNumEntries", "pInfo", "pdwBufferSize"]),
        #
        'PdhGetDefaultPerfObjectHW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDataSource", "szMachineName", "szDefaultObjectName", "pcchBufferSize"]),
        #
        'PdhGetDefaultPerfObjectHA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDataSource", "szMachineName", "szDefaultObjectName", "pcchBufferSize"]),
        #
        'PdhGetDefaultPerfCounterHW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDataSource", "szMachineName", "szObjectName", "szDefaultCounterName", "pcchBufferSize"]),
        #
        'PdhGetDefaultPerfCounterHA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDataSource", "szMachineName", "szObjectName", "szDefaultCounterName", "pcchBufferSize"]),
        #
        'PdhBrowseCountersHW': SimTypeFunction([SimTypePointer(SimTypeRef("PDH_BROWSE_DLG_CONFIG_HW", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pBrowseDlgData"]),
        #
        'PdhBrowseCountersHA': SimTypeFunction([SimTypePointer(SimTypeRef("PDH_BROWSE_DLG_CONFIG_HA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pBrowseDlgData"]),
        #
        'PdhVerifySQLDBW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szDataSource"]),
        #
        'PdhVerifySQLDBA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szDataSource"]),
        #
        'PdhCreateSQLTablesW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szDataSource"]),
        #
        'PdhCreateSQLTablesA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szDataSource"]),
        #
        'PdhEnumLogSetNamesW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szDataSource", "mszDataSetNameList", "pcchBufferLength"]),
        #
        'PdhEnumLogSetNamesA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["szDataSource", "mszDataSetNameList", "pcchBufferLength"]),
        #
        'PdhGetLogSetGUID': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hLog", "pGuid", "pRunId"]),
        #
        'PdhSetLogSetRunID': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hLog", "RunId"]),
    }

lib.set_prototypes(prototypes)
