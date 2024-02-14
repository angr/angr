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
lib.set_library_names("peerdist.dll")
prototypes = \
    {
        #
        'PeerDistStartup': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwVersionRequested", "phPeerDist", "pdwSupportedVersion"]),
        #
        'PeerDistShutdown': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPeerDist"]),
        #
        'PeerDistGetStatus': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="PEERDIST_STATUS"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPeerDist", "pPeerDistStatus"]),
        #
        'PeerDistRegisterForStatusChangeNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="PEERDIST_STATUS"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPeerDist", "hCompletionPort", "ulCompletionKey", "lpOverlapped", "pPeerDistStatus"]),
        #
        'PeerDistUnregisterForStatusChangeNotification': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPeerDist"]),
        #
        'PeerDistServerPublishStream': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("PEERDIST_PUBLICATION_OPTIONS", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPeerDist", "cbContentIdentifier", "pContentIdentifier", "cbContentLength", "pPublishOptions", "hCompletionPort", "ulCompletionKey", "phStream"]),
        #
        'PeerDistServerPublishAddToStream': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPeerDist", "hStream", "cbNumberOfBytes", "pBuffer", "lpOverlapped"]),
        #
        'PeerDistServerPublishCompleteStream': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPeerDist", "hStream", "lpOverlapped"]),
        #
        'PeerDistServerCloseStreamHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPeerDist", "hStream"]),
        #
        'PeerDistServerUnpublish': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPeerDist", "cbContentIdentifier", "pContentIdentifier"]),
        #
        'PeerDistServerOpenContentInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPeerDist", "cbContentIdentifier", "pContentIdentifier", "ullContentOffset", "cbContentLength", "hCompletionPort", "ulCompletionKey", "phContentInfo"]),
        #
        'PeerDistServerRetrieveContentInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPeerDist", "hContentInfo", "cbMaxNumberOfBytes", "pBuffer", "lpOverlapped"]),
        #
        'PeerDistServerCloseContentInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPeerDist", "hContentInfo"]),
        #
        'PeerDistServerCancelAsyncOperation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPeerDist", "cbContentIdentifier", "pContentIdentifier", "pOverlapped"]),
        #
        'PeerDistClientOpenContent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PEERDIST_CONTENT_TAG", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPeerDist", "pContentTag", "hCompletionPort", "ulCompletionKey", "phContentHandle"]),
        #
        'PeerDistClientCloseContent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPeerDist", "hContentHandle"]),
        #
        'PeerDistClientAddContentInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPeerDist", "hContentHandle", "cbNumberOfBytes", "pBuffer", "lpOverlapped"]),
        #
        'PeerDistClientCompleteContentInformation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPeerDist", "hContentHandle", "lpOverlapped"]),
        #
        'PeerDistClientAddData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPeerDist", "hContentHandle", "cbNumberOfBytes", "pBuffer", "lpOverlapped"]),
        #
        'PeerDistClientBlockRead': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPeerDist", "hContentHandle", "cbMaxNumberOfBytes", "pBuffer", "dwTimeoutInMilliseconds", "lpOverlapped"]),
        #
        'PeerDistClientStreamRead': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPeerDist", "hContentHandle", "cbMaxNumberOfBytes", "pBuffer", "dwTimeoutInMilliseconds", "lpOverlapped"]),
        #
        'PeerDistClientFlushContent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PEERDIST_CONTENT_TAG", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPeerDist", "pContentTag", "hCompletionPort", "ulCompletionKey", "lpOverlapped"]),
        #
        'PeerDistClientCancelAsyncOperation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPeerDist", "hContentHandle", "pOverlapped"]),
        #
        'PeerDistGetStatusEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PEERDIST_STATUS_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPeerDist", "pPeerDistStatus"]),
        #
        'PeerDistRegisterForStatusChangeNotificationEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeRef("PEERDIST_STATUS_INFO", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPeerDist", "hCompletionPort", "ulCompletionKey", "lpOverlapped", "pPeerDistStatus"]),
        #
        'PeerDistGetOverlappedResult': SimTypeFunction([SimTypePointer(SimTypeRef("OVERLAPPED", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["lpOverlapped", "lpNumberOfBytesTransferred", "bWait"]),
        #
        'PeerDistServerOpenContentInformationEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeRef("PEERDIST_RETRIEVAL_OPTIONS", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPeerDist", "cbContentIdentifier", "pContentIdentifier", "ullContentOffset", "cbContentLength", "pRetrievalOptions", "hCompletionPort", "ulCompletionKey", "phContentInfo"]),
        #
        'PeerDistClientGetInformationByHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="PEERDIST_CLIENT_INFO_BY_HANDLE_CLASS"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hPeerDist", "hContentHandle", "PeerDistClientInfoClass", "dwBufferSize", "lpInformation"]),
    }

lib.set_prototypes(prototypes)
