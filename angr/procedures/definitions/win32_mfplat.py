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
lib.set_library_names("mfplat.dll")
prototypes = \
    {
        #
        'MFSerializeAttributesToStream': SimTypeFunction([SimTypeBottom(label="IMFAttributes"), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IStream")], SimTypeInt(signed=True, label="Int32"), arg_names=["pAttr", "dwOptions", "pStm"]),
        #
        'MFDeserializeAttributesFromStream': SimTypeFunction([SimTypeBottom(label="IMFAttributes"), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IStream")], SimTypeInt(signed=True, label="Int32"), arg_names=["pAttr", "dwOptions", "pStm"]),
        #
        'MFCreateTransformActivate': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMFActivate"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppActivate"]),
        #
        'MFCreateSourceResolver': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMFSourceResolver"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppISourceResolver"]),
        #
        'CreatePropertyStore': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IPropertyStore"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppStore"]),
        #
        'MFGetSupportedSchemes': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pPropVarSchemeArray"]),
        #
        'MFGetSupportedMimeTypes': SimTypeFunction([SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pPropVarMimeTypeArray"]),
        #
        'MFGetSystemTime': SimTypeFunction([], SimTypeLongLong(signed=True, label="Int64")),
        #
        'MFCreateSystemTimeSource': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMFPresentationTimeSource"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppSystemTimeSource"]),
        #
        'MFCreatePresentationDescriptor': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IMFStreamDescriptor"), label="LPArray", offset=0), SimTypePointer(SimTypeBottom(label="IMFPresentationDescriptor"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cStreamDescriptors", "apStreamDescriptors", "ppPresentationDescriptor"]),
        #
        'MFSerializePresentationDescriptor': SimTypeFunction([SimTypeBottom(label="IMFPresentationDescriptor"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pPD", "pcbData", "ppbData"]),
        #
        'MFDeserializePresentationDescriptor': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeBottom(label="IMFPresentationDescriptor"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cbData", "pbData", "ppPD"]),
        #
        'MFCreateStreamDescriptor': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IMFMediaType"), label="LPArray", offset=0), SimTypePointer(SimTypeBottom(label="IMFStreamDescriptor"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwStreamIdentifier", "cMediaTypes", "apMediaTypes", "ppDescriptor"]),
        #
        'MFCreateTrackedSample': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMFTrackedSample"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppMFSample"]),
        #
        'MFCreateMFByteStreamOnStream': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypePointer(SimTypeBottom(label="IMFByteStream"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pStream", "ppByteStream"]),
        #
        'MFCreateStreamOnMFByteStream': SimTypeFunction([SimTypeBottom(label="IMFByteStream"), SimTypePointer(SimTypeBottom(label="IStream"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pByteStream", "ppStream"]),
        #
        'MFCreateMFByteStreamOnStreamEx': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="IMFByteStream"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["punkStream", "ppByteStream"]),
        #
        'MFCreateStreamOnMFByteStreamEx': SimTypeFunction([SimTypeBottom(label="IMFByteStream"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pByteStream", "riid", "ppv"]),
        #
        'MFCreateMediaTypeFromProperties': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="IMFMediaType"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["punkStream", "ppMediaType"]),
        #
        'MFCreatePropertiesFromMediaType': SimTypeFunction([SimTypeBottom(label="IMFMediaType"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMediaType", "riid", "ppv"]),
        #
        'MFCreateContentProtectionDevice': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="IMFContentProtectionDevice"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ProtectionSystemId", "ContentProtectionDevice"]),
        #
        'MFIsContentProtectionDeviceSupported': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ProtectionSystemId", "isSupported"]),
        #
        'MFCreateContentDecryptorContext': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeBottom(label="IMFDXGIDeviceManager"), SimTypeBottom(label="IMFContentProtectionDevice"), SimTypePointer(SimTypeBottom(label="IMFContentDecryptorContext"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["guidMediaProtectionSystemId", "pD3DManager", "pContentProtectionDevice", "ppContentDecryptorContext"]),
        #
        'MFCreateD3D12SynchronizationObject': SimTypeFunction([SimTypeBottom(label="ID3D12Device"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pDevice", "riid", "ppvSyncObject"]),
        #
        'MFStartup': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["Version", "dwFlags"]),
        #
        'MFShutdown': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'MFLockPlatform': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'MFUnlockPlatform': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'MFPutWorkItem': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IMFAsyncCallback"), SimTypeBottom(label="IUnknown")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwQueue", "pCallback", "pState"]),
        #
        'MFPutWorkItem2': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeBottom(label="IMFAsyncCallback"), SimTypeBottom(label="IUnknown")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwQueue", "Priority", "pCallback", "pState"]),
        #
        'MFPutWorkItemEx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IMFAsyncResult")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwQueue", "pResult"]),
        #
        'MFPutWorkItemEx2': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeBottom(label="IMFAsyncResult")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwQueue", "Priority", "pResult"]),
        #
        'MFPutWaitingWorkItem': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeBottom(label="IMFAsyncResult"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hEvent", "Priority", "pResult", "pKey"]),
        #
        'MFAllocateSerialWorkQueue': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwWorkQueue", "pdwWorkQueue"]),
        #
        'MFScheduleWorkItemEx': SimTypeFunction([SimTypeBottom(label="IMFAsyncResult"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pResult", "Timeout", "pKey"]),
        #
        'MFScheduleWorkItem': SimTypeFunction([SimTypeBottom(label="IMFAsyncCallback"), SimTypeBottom(label="IUnknown"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pCallback", "pState", "Timeout", "pKey"]),
        #
        'MFCancelWorkItem': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64")], SimTypeInt(signed=True, label="Int32"), arg_names=["Key"]),
        #
        'MFGetTimerPeriodicity': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Periodicity"]),
        #
        'MFAddPeriodicCallback': SimTypeFunction([SimTypePointer(SimTypeFunction([SimTypeBottom(label="IUnknown")], SimTypeBottom(label="Void"), arg_names=["pContext"]), offset=0), SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Callback", "pContext", "pdwKey"]),
        #
        'MFRemovePeriodicCallback': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwKey"]),
        #
        'MFAllocateWorkQueueEx': SimTypeFunction([SimTypeInt(signed=False, label="MFASYNC_WORKQUEUE_TYPE"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["WorkQueueType", "pdwWorkQueue"]),
        #
        'MFAllocateWorkQueue': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdwWorkQueue"]),
        #
        'MFLockWorkQueue': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwWorkQueue"]),
        #
        'MFUnlockWorkQueue': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwWorkQueue"]),
        #
        'MFBeginRegisterWorkQueueWithMMCSS': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IMFAsyncCallback"), SimTypeBottom(label="IUnknown")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwWorkQueueId", "wszClass", "dwTaskId", "pDoneCallback", "pDoneState"]),
        #
        'MFBeginRegisterWorkQueueWithMMCSSEx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeBottom(label="IMFAsyncCallback"), SimTypeBottom(label="IUnknown")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwWorkQueueId", "wszClass", "dwTaskId", "lPriority", "pDoneCallback", "pDoneState"]),
        #
        'MFEndRegisterWorkQueueWithMMCSS': SimTypeFunction([SimTypeBottom(label="IMFAsyncResult"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pResult", "pdwTaskId"]),
        #
        'MFBeginUnregisterWorkQueueWithMMCSS': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IMFAsyncCallback"), SimTypeBottom(label="IUnknown")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwWorkQueueId", "pDoneCallback", "pDoneState"]),
        #
        'MFEndUnregisterWorkQueueWithMMCSS': SimTypeFunction([SimTypeBottom(label="IMFAsyncResult")], SimTypeInt(signed=True, label="Int32"), arg_names=["pResult"]),
        #
        'MFGetWorkQueueMMCSSClass': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwWorkQueueId", "pwszClass", "pcchClass"]),
        #
        'MFGetWorkQueueMMCSSTaskId': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwWorkQueueId", "pdwTaskId"]),
        #
        'MFRegisterPlatformWithMMCSS': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["wszClass", "pdwTaskId", "lPriority"]),
        #
        'MFUnregisterPlatformFromMMCSS': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'MFLockSharedWorkQueue': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["wszClass", "BasePriority", "pdwTaskId", "pID"]),
        #
        'MFGetWorkQueueMMCSSPriority': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwWorkQueueId", "lPriority"]),
        #
        'MFCreateAsyncResult': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypeBottom(label="IMFAsyncCallback"), SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="IMFAsyncResult"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["punkObject", "pCallback", "punkState", "ppAsyncResult"]),
        #
        'MFInvokeCallback': SimTypeFunction([SimTypeBottom(label="IMFAsyncResult")], SimTypeInt(signed=True, label="Int32"), arg_names=["pAsyncResult"]),
        #
        'MFCreateFile': SimTypeFunction([SimTypeInt(signed=False, label="MF_FILE_ACCESSMODE"), SimTypeInt(signed=False, label="MF_FILE_OPENMODE"), SimTypeInt(signed=False, label="MF_FILE_FLAGS"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="IMFByteStream"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AccessMode", "OpenMode", "fFlags", "pwszFileURL", "ppIByteStream"]),
        #
        'MFCreateTempFile': SimTypeFunction([SimTypeInt(signed=False, label="MF_FILE_ACCESSMODE"), SimTypeInt(signed=False, label="MF_FILE_OPENMODE"), SimTypeInt(signed=False, label="MF_FILE_FLAGS"), SimTypePointer(SimTypeBottom(label="IMFByteStream"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AccessMode", "OpenMode", "fFlags", "ppIByteStream"]),
        #
        'MFBeginCreateFile': SimTypeFunction([SimTypeInt(signed=False, label="MF_FILE_ACCESSMODE"), SimTypeInt(signed=False, label="MF_FILE_OPENMODE"), SimTypeInt(signed=False, label="MF_FILE_FLAGS"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IMFAsyncCallback"), SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="IUnknown"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AccessMode", "OpenMode", "fFlags", "pwszFilePath", "pCallback", "pState", "ppCancelCookie"]),
        #
        'MFEndCreateFile': SimTypeFunction([SimTypeBottom(label="IMFAsyncResult"), SimTypePointer(SimTypeBottom(label="IMFByteStream"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pResult", "ppFile"]),
        #
        'MFCancelCreateFile': SimTypeFunction([SimTypeBottom(label="IUnknown")], SimTypeInt(signed=True, label="Int32"), arg_names=["pCancelCookie"]),
        #
        'MFCreateMemoryBuffer': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IMFMediaBuffer"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cbMaxLength", "ppBuffer"]),
        #
        'MFCreateMediaBufferWrapper': SimTypeFunction([SimTypeBottom(label="IMFMediaBuffer"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IMFMediaBuffer"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pBuffer", "cbOffset", "dwLength", "ppBuffer"]),
        #
        'MFCreateLegacyMediaBufferOnMFMediaBuffer': SimTypeFunction([SimTypeBottom(label="IMFSample"), SimTypeBottom(label="IMFMediaBuffer"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IMediaBuffer"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSample", "pMFMediaBuffer", "cbOffset", "ppMediaBuffer"]),
        #
        'MFMapDX9FormatToDXGIFormat': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="DXGI_FORMAT"), arg_names=["dx9"]),
        #
        'MFMapDXGIFormatToDX9Format': SimTypeFunction([SimTypeInt(signed=False, label="DXGI_FORMAT")], SimTypeInt(signed=False, label="UInt32"), arg_names=["dx11"]),
        #
        'MFLockDXGIDeviceManager': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="IMFDXGIDeviceManager"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pResetToken", "ppManager"]),
        #
        'MFUnlockDXGIDeviceManager': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'MFCreateDXSurfaceBuffer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeBottom(label="IUnknown"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="IMFMediaBuffer"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["riid", "punkSurface", "fBottomUpWhenLinear", "ppBuffer"]),
        #
        'MFCreateWICBitmapBuffer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="IMFMediaBuffer"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["riid", "punkSurface", "ppBuffer"]),
        #
        'MFCreateDXGISurfaceBuffer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeBottom(label="IUnknown"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="IMFMediaBuffer"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["riid", "punkSurface", "uSubresourceIndex", "fBottomUpWhenLinear", "ppBuffer"]),
        #
        'MFCreateVideoSampleAllocatorEx': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["riid", "ppSampleAllocator"]),
        #
        'MFCreateDXGIDeviceManager': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="IMFDXGIDeviceManager"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["resetToken", "ppDeviceManager"]),
        #
        'MFCreateAlignedMemoryBuffer': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IMFMediaBuffer"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cbMaxLength", "cbAligment", "ppBuffer"]),
        #
        'MFCreateMediaEvent': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="IMFMediaEvent"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["met", "guidExtendedType", "hrStatus", "pvValue", "ppEvent"]),
        #
        'MFCreateEventQueue': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMFMediaEventQueue"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppMediaEventQueue"]),
        #
        'MFCreateSample': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMFSample"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppIMFSample"]),
        #
        'MFCreateAttributes': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMFAttributes"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ppMFAttributes", "cInitialSize"]),
        #
        'MFInitAttributesFromBlob': SimTypeFunction([SimTypeBottom(label="IMFAttributes"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pAttributes", "pBuf", "cbBufSize"]),
        #
        'MFGetAttributesAsBlobSize': SimTypeFunction([SimTypeBottom(label="IMFAttributes"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAttributes", "pcbBufSize"]),
        #
        'MFGetAttributesAsBlob': SimTypeFunction([SimTypeBottom(label="IMFAttributes"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pAttributes", "pBuf", "cbBufSize"]),
        #
        'MFTRegister': SimTypeFunction([SimTypeBottom(label="Guid"), SimTypeBottom(label="Guid"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MFT_REGISTER_TYPE_INFO", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MFT_REGISTER_TYPE_INFO", SimStruct), label="LPArray", offset=0), SimTypeBottom(label="IMFAttributes")], SimTypeInt(signed=True, label="Int32"), arg_names=["clsidMFT", "guidCategory", "pszName", "Flags", "cInputTypes", "pInputTypes", "cOutputTypes", "pOutputTypes", "pAttributes"]),
        #
        'MFTUnregister': SimTypeFunction([SimTypeBottom(label="Guid")], SimTypeInt(signed=True, label="Int32"), arg_names=["clsidMFT"]),
        #
        'MFTRegisterLocal': SimTypeFunction([SimTypeBottom(label="IClassFactory"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MFT_REGISTER_TYPE_INFO", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MFT_REGISTER_TYPE_INFO", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pClassFactory", "guidCategory", "pszName", "Flags", "cInputTypes", "pInputTypes", "cOutputTypes", "pOutputTypes"]),
        #
        'MFTUnregisterLocal': SimTypeFunction([SimTypeBottom(label="IClassFactory")], SimTypeInt(signed=True, label="Int32"), arg_names=["pClassFactory"]),
        #
        'MFTRegisterLocalByCLSID': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MFT_REGISTER_TYPE_INFO", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MFT_REGISTER_TYPE_INFO", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["clisdMFT", "guidCategory", "pszName", "Flags", "cInputTypes", "pInputTypes", "cOutputTypes", "pOutputTypes"]),
        #
        'MFTUnregisterLocalByCLSID': SimTypeFunction([SimTypeBottom(label="Guid")], SimTypeInt(signed=True, label="Int32"), arg_names=["clsidMFT"]),
        #
        'MFTEnum': SimTypeFunction([SimTypeBottom(label="Guid"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MFT_REGISTER_TYPE_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("MFT_REGISTER_TYPE_INFO", SimStruct), offset=0), SimTypeBottom(label="IMFAttributes"), SimTypePointer(SimTypePointer(SimTypeBottom(label="Guid"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["guidCategory", "Flags", "pInputType", "pOutputType", "pAttributes", "ppclsidMFT", "pcMFTs"]),
        #
        'MFTEnumEx': SimTypeFunction([SimTypeBottom(label="Guid"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MFT_REGISTER_TYPE_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("MFT_REGISTER_TYPE_INFO", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="IMFActivate"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["guidCategory", "Flags", "pInputType", "pOutputType", "pppMFTActivate", "pnumMFTActivate"]),
        #
        'MFTEnum2': SimTypeFunction([SimTypeBottom(label="Guid"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("MFT_REGISTER_TYPE_INFO", SimStruct), offset=0), SimTypePointer(SimTypeRef("MFT_REGISTER_TYPE_INFO", SimStruct), offset=0), SimTypeBottom(label="IMFAttributes"), SimTypePointer(SimTypePointer(SimTypeBottom(label="IMFActivate"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["guidCategory", "Flags", "pInputType", "pOutputType", "pAttributes", "pppMFTActivate", "pnumMFTActivate"]),
        #
        'MFTGetInfo': SimTypeFunction([SimTypeBottom(label="Guid"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("MFT_REGISTER_TYPE_INFO", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("MFT_REGISTER_TYPE_INFO", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="IMFAttributes"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["clsidMFT", "pszName", "ppInputTypes", "pcInputTypes", "ppOutputTypes", "pcOutputTypes", "ppAttributes"]),
        #
        'MFGetPluginControl': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMFPluginControl"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppPluginControl"]),
        #
        'MFGetMFTMerit': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMFT", "cbVerifier", "verifier", "merit"]),
        #
        'MFRegisterLocalSchemeHandler': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IMFActivate")], SimTypeInt(signed=True, label="Int32"), arg_names=["szScheme", "pActivate"]),
        #
        'MFRegisterLocalByteStreamHandler': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IMFActivate")], SimTypeInt(signed=True, label="Int32"), arg_names=["szFileExtension", "szMimeType", "pActivate"]),
        #
        'MFCreateMFByteStreamWrapper': SimTypeFunction([SimTypeBottom(label="IMFByteStream"), SimTypePointer(SimTypeBottom(label="IMFByteStream"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pStream", "ppStreamWrapper"]),
        #
        'MFCreateMediaExtensionActivate': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["szActivatableClassId", "pConfiguration", "riid", "ppvObject"]),
        #
        'MFCreateMuxStreamAttributes': SimTypeFunction([SimTypeBottom(label="IMFCollection"), SimTypePointer(SimTypeBottom(label="IMFAttributes"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAttributesToMux", "ppMuxAttribs"]),
        #
        'MFCreateMuxStreamMediaType': SimTypeFunction([SimTypeBottom(label="IMFCollection"), SimTypePointer(SimTypeBottom(label="IMFMediaType"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMediaTypesToMux", "ppMuxMediaType"]),
        #
        'MFCreateMuxStreamSample': SimTypeFunction([SimTypeBottom(label="IMFCollection"), SimTypePointer(SimTypeBottom(label="IMFSample"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSamplesToMux", "ppMuxSample"]),
        #
        'MFValidateMediaTypeSize': SimTypeFunction([SimTypeBottom(label="Guid"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["FormatType", "pBlock", "cbSize"]),
        #
        'MFCreateMediaType': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMFMediaType"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppMFType"]),
        #
        'MFCreateMFVideoFormatFromMFMediaType': SimTypeFunction([SimTypeBottom(label="IMFMediaType"), SimTypePointer(SimTypePointer(SimTypeRef("MFVIDEOFORMAT", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMFType", "ppMFVF", "pcbSize"]),
        #
        'MFCreateWaveFormatExFromMFMediaType': SimTypeFunction([SimTypeBottom(label="IMFMediaType"), SimTypePointer(SimTypePointer(SimTypeRef("WAVEFORMATEX", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pMFType", "ppWF", "pcbSize", "Flags"]),
        #
        'MFInitMediaTypeFromVideoInfoHeader': SimTypeFunction([SimTypeBottom(label="IMFMediaType"), SimTypePointer(SimTypeRef("VIDEOINFOHEADER", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMFType", "pVIH", "cbBufSize", "pSubtype"]),
        #
        'MFInitMediaTypeFromVideoInfoHeader2': SimTypeFunction([SimTypeBottom(label="IMFMediaType"), SimTypePointer(SimTypeRef("VIDEOINFOHEADER2", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMFType", "pVIH2", "cbBufSize", "pSubtype"]),
        #
        'MFInitMediaTypeFromMPEG1VideoInfo': SimTypeFunction([SimTypeBottom(label="IMFMediaType"), SimTypePointer(SimTypeRef("MPEG1VIDEOINFO", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMFType", "pMP1VI", "cbBufSize", "pSubtype"]),
        #
        'MFInitMediaTypeFromMPEG2VideoInfo': SimTypeFunction([SimTypeBottom(label="IMFMediaType"), SimTypePointer(SimTypeRef("MPEG2VIDEOINFO", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMFType", "pMP2VI", "cbBufSize", "pSubtype"]),
        #
        'MFCalculateBitmapImageSize': SimTypeFunction([SimTypePointer(SimTypeRef("BITMAPINFOHEADER", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pBMIH", "cbBufSize", "pcbImageSize", "pbKnown"]),
        #
        'MFCalculateImageSize': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["guidSubtype", "unWidth", "unHeight", "pcbImageSize"]),
        #
        'MFFrameRateToAverageTimePerFrame': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["unNumerator", "unDenominator", "punAverageTimePerFrame"]),
        #
        'MFAverageTimePerFrameToFrameRate': SimTypeFunction([SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["unAverageTimePerFrame", "punNumerator", "punDenominator"]),
        #
        'MFInitMediaTypeFromMFVideoFormat': SimTypeFunction([SimTypeBottom(label="IMFMediaType"), SimTypePointer(SimTypeRef("MFVIDEOFORMAT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pMFType", "pMFVF", "cbBufSize"]),
        #
        'MFInitMediaTypeFromWaveFormatEx': SimTypeFunction([SimTypeBottom(label="IMFMediaType"), SimTypePointer(SimTypeRef("WAVEFORMATEX", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pMFType", "pWaveFormat", "cbBufSize"]),
        #
        'MFInitMediaTypeFromAMMediaType': SimTypeFunction([SimTypeBottom(label="IMFMediaType"), SimTypePointer(SimTypeRef("AM_MEDIA_TYPE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMFType", "pAMType"]),
        #
        'MFInitAMMediaTypeFromMFMediaType': SimTypeFunction([SimTypeBottom(label="IMFMediaType"), SimTypeBottom(label="Guid"), SimTypePointer(SimTypeRef("AM_MEDIA_TYPE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMFType", "guidFormatBlockType", "pAMType"]),
        #
        'MFCreateAMMediaTypeFromMFMediaType': SimTypeFunction([SimTypeBottom(label="IMFMediaType"), SimTypeBottom(label="Guid"), SimTypePointer(SimTypePointer(SimTypeRef("AM_MEDIA_TYPE", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMFType", "guidFormatBlockType", "ppAMType"]),
        #
        'MFCompareFullToPartialMediaType': SimTypeFunction([SimTypeBottom(label="IMFMediaType"), SimTypeBottom(label="IMFMediaType")], SimTypeInt(signed=True, label="Int32"), arg_names=["pMFTypeFull", "pMFTypePartial"]),
        #
        'MFWrapMediaType': SimTypeFunction([SimTypeBottom(label="IMFMediaType"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="IMFMediaType"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pOrig", "MajorType", "SubType", "ppWrap"]),
        #
        'MFUnwrapMediaType': SimTypeFunction([SimTypeBottom(label="IMFMediaType"), SimTypePointer(SimTypeBottom(label="IMFMediaType"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pWrap", "ppOrig"]),
        #
        'MFCreateVideoMediaType': SimTypeFunction([SimTypePointer(SimTypeRef("MFVIDEOFORMAT", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="IMFVideoMediaType"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pVideoFormat", "ppIVideoMediaType"]),
        #
        'MFCreateVideoMediaTypeFromSubtype': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="IMFVideoMediaType"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAMSubtype", "ppIVideoMediaType"]),
        #
        'MFCreateVideoMediaTypeFromBitMapInfoHeader': SimTypeFunction([SimTypePointer(SimTypeRef("BITMAPINFOHEADER", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="MFVideoInterlaceMode"), SimTypeLongLong(signed=False, label="UInt64"), SimTypeLongLong(signed=False, label="UInt64"), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IMFVideoMediaType"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pbmihBitMapInfoHeader", "dwPixelAspectRatioX", "dwPixelAspectRatioY", "InterlaceMode", "VideoFlags", "qwFramesPerSecondNumerator", "qwFramesPerSecondDenominator", "dwMaxBitRate", "ppIVideoMediaType"]),
        #
        'MFGetStrideForBitmapInfoHeader': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["format", "dwWidth", "pStride"]),
        #
        'MFCreateVideoMediaTypeFromBitMapInfoHeaderEx': SimTypeFunction([SimTypePointer(SimTypeRef("BITMAPINFOHEADER", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="MFVideoInterlaceMode"), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IMFVideoMediaType"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pbmihBitMapInfoHeader", "cbBitMapInfoHeader", "dwPixelAspectRatioX", "dwPixelAspectRatioY", "InterlaceMode", "VideoFlags", "dwFramesPerSecondNumerator", "dwFramesPerSecondDenominator", "dwMaxBitRate", "ppIVideoMediaType"]),
        #
        'MFCreateMediaTypeFromRepresentation': SimTypeFunction([SimTypeBottom(label="Guid"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="IMFMediaType"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["guidRepresentation", "pvRepresentation", "ppIMediaType"]),
        #
        'MFCreateAudioMediaType': SimTypeFunction([SimTypePointer(SimTypeRef("WAVEFORMATEX", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="IMFAudioMediaType"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAudioFormat", "ppIAudioMediaType"]),
        #
        'MFGetUncompressedVideoFormat': SimTypeFunction([SimTypePointer(SimTypeRef("MFVIDEOFORMAT", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pVideoFormat"]),
        #
        'MFInitVideoFormat': SimTypeFunction([SimTypePointer(SimTypeRef("MFVIDEOFORMAT", SimStruct), offset=0), SimTypeInt(signed=False, label="MFStandardVideoFormat")], SimTypeInt(signed=True, label="Int32"), arg_names=["pVideoFormat", "type"]),
        #
        'MFInitVideoFormat_RGB': SimTypeFunction([SimTypePointer(SimTypeRef("MFVIDEOFORMAT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pVideoFormat", "dwWidth", "dwHeight", "D3Dfmt"]),
        #
        'MFConvertColorInfoToDXVA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("MFVIDEOFORMAT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdwToDXVA", "pFromFormat"]),
        #
        'MFConvertColorInfoFromDXVA': SimTypeFunction([SimTypePointer(SimTypeRef("MFVIDEOFORMAT", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pToFormat", "dwFromDXVA"]),
        #
        'MFCopyImage': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pDest", "lDestStride", "pSrc", "lSrcStride", "dwWidthInBytes", "dwLines"]),
        #
        'MFConvertFromFP16Array': SimTypeFunction([SimTypePointer(SimTypeFloat(size=32), label="LPArray", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pDest", "pSrc", "dwCount"]),
        #
        'MFConvertToFP16Array': SimTypeFunction([SimTypePointer(SimTypeShort(signed=False, label="UInt16"), label="LPArray", offset=0), SimTypePointer(SimTypeFloat(size=32), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pDest", "pSrc", "dwCount"]),
        #
        'MFCreate2DMediaBuffer': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="IMFMediaBuffer"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwWidth", "dwHeight", "dwFourCC", "fBottomUp", "ppBuffer"]),
        #
        'MFCreateMediaBufferFromMediaType': SimTypeFunction([SimTypeBottom(label="IMFMediaType"), SimTypeLongLong(signed=True, label="Int64"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IMFMediaBuffer"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMediaType", "llDuration", "dwMinLength", "dwMinAlignment", "ppBuffer"]),
        #
        'MFCreateCollection': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMFCollection"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppIMFCollection"]),
        #
        'MFHeapAlloc': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="EAllocationType")], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["nSize", "dwFlags", "pszFile", "line", "eat"]),
        #
        'MFHeapFree': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pv"]),
        #
        'MFllMulDiv': SimTypeFunction([SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64"), SimTypeLongLong(signed=True, label="Int64")], SimTypeLongLong(signed=True, label="Int64"), arg_names=["a", "b", "c", "d"]),
        #
        'MFGetContentProtectionSystemCLSID': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["guidProtectionSystemID", "pclsid"]),
        #
        'MFCombineSamples': SimTypeFunction([SimTypeBottom(label="IMFSample"), SimTypeBottom(label="IMFSample"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSample", "pSampleToAdd", "dwMaxMergedDurationInMS", "pMerged"]),
        #
        'MFSplitSample': SimTypeFunction([SimTypeBottom(label="IMFSample"), SimTypePointer(SimTypeBottom(label="IMFSample"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSample", "pOutputSamples", "dwOutputSampleMaxCount", "pdwOutputSampleCount"]),
    }

lib.set_prototypes(prototypes)
