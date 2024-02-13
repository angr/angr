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
lib.set_library_names("httpapi.dll")
prototypes = \
    {
        #
        'HttpInitialize': SimTypeFunction([SimTypeRef("HTTPAPI_VERSION", SimStruct), SimTypeInt(signed=False, label="HTTP_INITIALIZE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Version", "Flags", "pReserved"]),
        #
        'HttpTerminate': SimTypeFunction([SimTypeInt(signed=False, label="HTTP_INITIALIZE"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Flags", "pReserved"]),
        #
        'HttpCreateHttpHandle': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["RequestQueueHandle", "Reserved"]),
        #
        'HttpCreateRequestQueue': SimTypeFunction([SimTypeRef("HTTPAPI_VERSION", SimStruct), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Version", "Name", "SecurityAttributes", "Flags", "RequestQueueHandle"]),
        #
        'HttpCloseRequestQueue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RequestQueueHandle"]),
        #
        'HttpSetRequestQueueProperty': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="HTTP_SERVER_PROPERTY"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RequestQueueHandle", "Property", "PropertyInformation", "PropertyInformationLength", "Reserved1", "Reserved2"]),
        #
        'HttpQueryRequestQueueProperty': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="HTTP_SERVER_PROPERTY"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RequestQueueHandle", "Property", "PropertyInformation", "PropertyInformationLength", "Reserved1", "ReturnLength", "Reserved2"]),
        #
        'HttpSetRequestProperty': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="HTTP_REQUEST_PROPERTY"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RequestQueueHandle", "Id", "PropertyId", "Input", "InputPropertySize", "Overlapped"]),
        #
        'HttpShutdownRequestQueue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RequestQueueHandle"]),
        #
        'HttpReceiveClientCertificate': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("HTTP_SSL_CLIENT_CERT_INFO", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RequestQueueHandle", "ConnectionId", "Flags", "SslClientCertInfo", "SslClientCertInfoSize", "BytesReceived", "Overlapped"]),
        #
        'HttpCreateServerSession': SimTypeFunction([SimTypeRef("HTTPAPI_VERSION", SimStruct), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Version", "ServerSessionId", "Reserved"]),
        #
        'HttpCloseServerSession': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerSessionId"]),
        #
        'HttpQueryServerSessionProperty': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="HTTP_SERVER_PROPERTY"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerSessionId", "Property", "PropertyInformation", "PropertyInformationLength", "ReturnLength"]),
        #
        'HttpSetServerSessionProperty': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="HTTP_SERVER_PROPERTY"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerSessionId", "Property", "PropertyInformation", "PropertyInformationLength"]),
        #
        'HttpAddUrl': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RequestQueueHandle", "FullyQualifiedUrl", "Reserved"]),
        #
        'HttpRemoveUrl': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RequestQueueHandle", "FullyQualifiedUrl"]),
        #
        'HttpCreateUrlGroup': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServerSessionId", "pUrlGroupId", "Reserved"]),
        #
        'HttpCloseUrlGroup': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=False, label="UInt32"), arg_names=["UrlGroupId"]),
        #
        'HttpAddUrlToUrlGroup': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["UrlGroupId", "pFullyQualifiedUrl", "UrlContext", "Reserved"]),
        #
        'HttpRemoveUrlFromUrlGroup': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["UrlGroupId", "pFullyQualifiedUrl", "Flags"]),
        #
        'HttpSetUrlGroupProperty': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="HTTP_SERVER_PROPERTY"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["UrlGroupId", "Property", "PropertyInformation", "PropertyInformationLength"]),
        #
        'HttpQueryUrlGroupProperty': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="HTTP_SERVER_PROPERTY"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["UrlGroupId", "Property", "PropertyInformation", "PropertyInformationLength", "ReturnLength"]),
        #
        'HttpPrepareUrl': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Reserved", "Flags", "Url", "PreparedUrl"]),
        #
        'HttpReceiveHttpRequest': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="HTTP_RECEIVE_HTTP_REQUEST_FLAGS"), SimTypePointer(SimTypeRef("HTTP_REQUEST_V2", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RequestQueueHandle", "RequestId", "Flags", "RequestBuffer", "RequestBufferLength", "BytesReturned", "Overlapped"]),
        #
        'HttpReceiveRequestEntityBody': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RequestQueueHandle", "RequestId", "Flags", "EntityBuffer", "EntityBufferLength", "BytesReturned", "Overlapped"]),
        #
        'HttpSendHttpResponse': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("HTTP_RESPONSE_V2", SimStruct), offset=0), SimTypePointer(SimTypeRef("HTTP_CACHE_POLICY", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeRef("HTTP_LOG_DATA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RequestQueueHandle", "RequestId", "Flags", "HttpResponse", "CachePolicy", "BytesSent", "Reserved1", "Reserved2", "Overlapped", "LogData"]),
        #
        'HttpSendResponseEntityBody': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32"), SimTypeShort(signed=False, label="UInt16"), SimTypePointer(SimTypeRef("HTTP_DATA_CHUNK", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeRef("HTTP_LOG_DATA", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RequestQueueHandle", "RequestId", "Flags", "EntityChunkCount", "EntityChunks", "BytesSent", "Reserved1", "Reserved2", "Overlapped", "LogData"]),
        #
        'HttpDeclarePush': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="HTTP_VERB"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("HTTP_REQUEST_HEADERS", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RequestQueueHandle", "RequestId", "Verb", "Path", "Query", "Headers"]),
        #
        'HttpWaitForDisconnect': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RequestQueueHandle", "ConnectionId", "Overlapped"]),
        #
        'HttpWaitForDisconnectEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RequestQueueHandle", "ConnectionId", "Reserved", "Overlapped"]),
        #
        'HttpCancelHttpRequest': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RequestQueueHandle", "RequestId", "Overlapped"]),
        #
        'HttpWaitForDemandStart': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RequestQueueHandle", "Overlapped"]),
        #
        'HttpIsFeatureSupported': SimTypeFunction([SimTypeInt(signed=False, label="HTTP_FEATURE_ID")], SimTypeInt(signed=True, label="Int32"), arg_names=["FeatureId"]),
        #
        'HttpDelegateRequestEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("HTTP_DELEGATE_REQUEST_PROPERTY_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RequestQueueHandle", "DelegateQueueHandle", "RequestId", "DelegateUrlGroupId", "PropertyInfoSetSize", "PropertyInfoSet"]),
        #
        'HttpFindUrlGroupId': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["FullyQualifiedUrl", "RequestQueueHandle", "UrlGroupId"]),
        #
        'HttpFlushResponseCache': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RequestQueueHandle", "UrlPrefix", "Flags", "Overlapped"]),
        #
        'HttpAddFragmentToCache': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("HTTP_DATA_CHUNK", SimStruct), offset=0), SimTypePointer(SimTypeRef("HTTP_CACHE_POLICY", SimStruct), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RequestQueueHandle", "UrlPrefix", "DataChunk", "CachePolicy", "Overlapped"]),
        #
        'HttpReadFragmentFromCache': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("HTTP_BYTE_RANGE", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["RequestQueueHandle", "UrlPrefix", "ByteRange", "Buffer", "BufferLength", "BytesRead", "Overlapped"]),
        #
        'HttpSetServiceConfiguration': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="HTTP_SERVICE_CONFIG_ID"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServiceHandle", "ConfigId", "pConfigInformation", "ConfigInformationLength", "pOverlapped"]),
        #
        'HttpUpdateServiceConfiguration': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="HTTP_SERVICE_CONFIG_ID"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["Handle", "ConfigId", "ConfigInfo", "ConfigInfoLength", "Overlapped"]),
        #
        'HttpDeleteServiceConfiguration': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="HTTP_SERVICE_CONFIG_ID"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServiceHandle", "ConfigId", "pConfigInformation", "ConfigInformationLength", "pOverlapped"]),
        #
        'HttpQueryServiceConfiguration': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="HTTP_SERVICE_CONFIG_ID"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["ServiceHandle", "ConfigId", "pInput", "InputLength", "pOutput", "OutputLength", "pReturnLength", "pOverlapped"]),
        #
        'HttpGetExtension': SimTypeFunction([SimTypeRef("HTTPAPI_VERSION", SimStruct), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["Version", "Extension", "Buffer", "BufferSize"]),
    }

lib.set_prototypes(prototypes)
