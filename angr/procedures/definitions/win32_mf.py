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
lib.set_library_names("mf.dll")
prototypes = \
    {
        #
        'MFCreateMediaSession': SimTypeFunction([SimTypeBottom(label="IMFAttributes"), SimTypePointer(SimTypeBottom(label="IMFMediaSession"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pConfiguration", "ppMediaSession"]),
        #
        'MFCreatePMPMediaSession': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IMFAttributes"), SimTypePointer(SimTypeBottom(label="IMFMediaSession"), offset=0), SimTypePointer(SimTypeBottom(label="IMFActivate"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwCreationFlags", "pConfiguration", "ppMediaSession", "ppEnablerActivate"]),
        #
        'MFCreateTopology': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMFTopology"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppTopo"]),
        #
        'MFCreateTopologyNode': SimTypeFunction([SimTypeInt(signed=False, label="MF_TOPOLOGY_TYPE"), SimTypePointer(SimTypeBottom(label="IMFTopologyNode"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NodeType", "ppNode"]),
        #
        'MFGetTopoNodeCurrentType': SimTypeFunction([SimTypeBottom(label="IMFTopologyNode"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="IMFMediaType"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pNode", "dwStreamIndex", "fOutput", "ppType"]),
        #
        'MFGetService': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["punkObject", "guidService", "riid", "ppvObject"]),
        #
        'MFCreatePresentationClock': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMFPresentationClock"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppPresentationClock"]),
        #
        'MFRequireProtectedEnvironment': SimTypeFunction([SimTypeBottom(label="IMFPresentationDescriptor")], SimTypeInt(signed=True, label="Int32"), arg_names=["pPresentationDescriptor"]),
        #
        'MFCreateSimpleTypeHandler': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMFMediaTypeHandler"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppHandler"]),
        #
        'MFShutdownObject': SimTypeFunction([SimTypeBottom(label="IUnknown")], SimTypeInt(signed=True, label="Int32"), arg_names=["pUnk"]),
        #
        'MFCreateAudioRenderer': SimTypeFunction([SimTypeBottom(label="IMFAttributes"), SimTypePointer(SimTypeBottom(label="IMFMediaSink"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAudioAttributes", "ppSink"]),
        #
        'MFCreateAudioRendererActivate': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMFActivate"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppActivate"]),
        #
        'MFCreateVideoRendererActivate': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="IMFActivate"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndVideo", "ppActivate"]),
        #
        'MFCreateMPEG4MediaSink': SimTypeFunction([SimTypeBottom(label="IMFByteStream"), SimTypeBottom(label="IMFMediaType"), SimTypeBottom(label="IMFMediaType"), SimTypePointer(SimTypeBottom(label="IMFMediaSink"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pIByteStream", "pVideoMediaType", "pAudioMediaType", "ppIMediaSink"]),
        #
        'MFCreate3GPMediaSink': SimTypeFunction([SimTypeBottom(label="IMFByteStream"), SimTypeBottom(label="IMFMediaType"), SimTypeBottom(label="IMFMediaType"), SimTypePointer(SimTypeBottom(label="IMFMediaSink"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pIByteStream", "pVideoMediaType", "pAudioMediaType", "ppIMediaSink"]),
        #
        'MFCreateMP3MediaSink': SimTypeFunction([SimTypeBottom(label="IMFByteStream"), SimTypePointer(SimTypeBottom(label="IMFMediaSink"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pTargetByteStream", "ppMediaSink"]),
        #
        'MFCreateAC3MediaSink': SimTypeFunction([SimTypeBottom(label="IMFByteStream"), SimTypeBottom(label="IMFMediaType"), SimTypePointer(SimTypeBottom(label="IMFMediaSink"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pTargetByteStream", "pAudioMediaType", "ppMediaSink"]),
        #
        'MFCreateADTSMediaSink': SimTypeFunction([SimTypeBottom(label="IMFByteStream"), SimTypeBottom(label="IMFMediaType"), SimTypePointer(SimTypeBottom(label="IMFMediaSink"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pTargetByteStream", "pAudioMediaType", "ppMediaSink"]),
        #
        'MFCreateMuxSink': SimTypeFunction([SimTypeBottom(label="Guid"), SimTypeBottom(label="IMFAttributes"), SimTypeBottom(label="IMFByteStream"), SimTypePointer(SimTypeBottom(label="IMFMediaSink"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["guidOutputSubType", "pOutputAttributes", "pOutputByteStream", "ppMuxSink"]),
        #
        'MFCreateFMPEG4MediaSink': SimTypeFunction([SimTypeBottom(label="IMFByteStream"), SimTypeBottom(label="IMFMediaType"), SimTypeBottom(label="IMFMediaType"), SimTypePointer(SimTypeBottom(label="IMFMediaSink"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pIByteStream", "pVideoMediaType", "pAudioMediaType", "ppIMediaSink"]),
        #
        'MFCreateTopoLoader': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMFTopoLoader"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppObj"]),
        #
        'MFCreateSampleGrabberSinkActivate': SimTypeFunction([SimTypeBottom(label="IMFMediaType"), SimTypeBottom(label="IMFSampleGrabberSinkCallback"), SimTypePointer(SimTypeBottom(label="IMFActivate"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pIMFMediaType", "pIMFSampleGrabberSinkCallback", "ppIActivate"]),
        #
        'MFCreateStandardQualityManager': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMFQualityManager"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppQualityManager"]),
        #
        'MFCreateSequencerSource': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="IMFSequencerSource"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pReserved", "ppSequencerSource"]),
        #
        'MFCreateSequencerSegmentOffset': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwId", "hnsOffset", "pvarSegmentOffset"]),
        #
        'MFCreateAggregateSource': SimTypeFunction([SimTypeBottom(label="IMFCollection"), SimTypePointer(SimTypeBottom(label="IMFMediaSource"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSourceCollection", "ppAggSource"]),
        #
        'MFCreateCredentialCache': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMFNetCredentialCache"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppCache"]),
        #
        'MFCreateProxyLocator': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IPropertyStore"), SimTypePointer(SimTypeBottom(label="IMFNetProxyLocator"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszProtocol", "pProxyConfig", "ppProxyLocator"]),
        #
        'MFCreateNetSchemePlugin': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["riid", "ppvHandler"]),
        #
        'MFCreatePMPServer': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IMFPMPServer"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwCreationFlags", "ppPMPServer"]),
        #
        'MFCreateRemoteDesktopPlugin': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMFRemoteDesktopPlugin"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppPlugin"]),
        #
        'CreateNamedPropertyStore': SimTypeFunction([SimTypePointer(SimTypeBottom(label="INamedPropertyStore"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppStore"]),
        #
        'MFCreateSampleCopierMFT': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMFTransform"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppCopierMFT"]),
        #
        'MFCreateTranscodeProfile': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMFTranscodeProfile"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppTranscodeProfile"]),
        #
        'MFCreateTranscodeTopology': SimTypeFunction([SimTypeBottom(label="IMFMediaSource"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IMFTranscodeProfile"), SimTypePointer(SimTypeBottom(label="IMFTopology"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrc", "pwszOutputFilePath", "pProfile", "ppTranscodeTopo"]),
        #
        'MFCreateTranscodeTopologyFromByteStream': SimTypeFunction([SimTypeBottom(label="IMFMediaSource"), SimTypeBottom(label="IMFByteStream"), SimTypeBottom(label="IMFTranscodeProfile"), SimTypePointer(SimTypeBottom(label="IMFTopology"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrc", "pOutputStream", "pProfile", "ppTranscodeTopo"]),
        #
        'MFTranscodeGetAudioOutputAvailableTypes': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IMFAttributes"), SimTypePointer(SimTypeBottom(label="IMFCollection"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["guidSubType", "dwMFTFlags", "pCodecConfig", "ppAvailableTypes"]),
        #
        'MFCreateTranscodeSinkActivate': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMFActivate"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppActivate"]),
        #
        'MFEnumDeviceSources': SimTypeFunction([SimTypeBottom(label="IMFAttributes"), SimTypePointer(SimTypePointer(SimTypeBottom(label="IMFActivate"), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAttributes", "pppSourceActivate", "pcSourceActivate"]),
        #
        'MFCreateDeviceSource': SimTypeFunction([SimTypeBottom(label="IMFAttributes"), SimTypePointer(SimTypeBottom(label="IMFMediaSource"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAttributes", "ppSource"]),
        #
        'MFCreateDeviceSourceActivate': SimTypeFunction([SimTypeBottom(label="IMFAttributes"), SimTypePointer(SimTypeBottom(label="IMFActivate"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAttributes", "ppActivate"]),
        #
        'MFCreateProtectedEnvironmentAccess': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMFProtectedEnvironmentAccess"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppAccess"]),
        #
        'MFLoadSignedLibrary': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="IMFSignedLibrary"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszName", "ppLib"]),
        #
        'MFGetSystemId': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMFSystemId"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppId"]),
        #
        'MFGetLocalId': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["verifier", "size", "id"]),
        #
        'MFCreateASFContentInfo': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMFASFContentInfo"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppIContentInfo"]),
        #
        'MFCreateASFIndexer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMFASFIndexer"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppIIndexer"]),
        #
        'MFCreateASFIndexerByteStream': SimTypeFunction([SimTypeBottom(label="IMFByteStream"), SimTypeLongLong(signed=False, label="UInt64"), SimTypePointer(SimTypeBottom(label="IMFByteStream"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pIContentByteStream", "cbIndexStartOffset", "pIIndexByteStream"]),
        #
        'MFCreateASFSplitter': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMFASFSplitter"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppISplitter"]),
        #
        'MFCreateASFProfile': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMFASFProfile"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppIProfile"]),
        #
        'MFCreateASFProfileFromPresentationDescriptor': SimTypeFunction([SimTypeBottom(label="IMFPresentationDescriptor"), SimTypePointer(SimTypeBottom(label="IMFASFProfile"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pIPD", "ppIProfile"]),
        #
        'MFCreatePresentationDescriptorFromASFProfile': SimTypeFunction([SimTypeBottom(label="IMFASFProfile"), SimTypePointer(SimTypeBottom(label="IMFPresentationDescriptor"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pIProfile", "ppIPD"]),
        #
        'MFCreateASFMultiplexer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMFASFMultiplexer"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppIMultiplexer"]),
        #
        'MFCreateASFStreamSelector': SimTypeFunction([SimTypeBottom(label="IMFASFProfile"), SimTypePointer(SimTypeBottom(label="IMFASFStreamSelector"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pIASFProfile", "ppSelector"]),
        #
        'MFCreateASFMediaSink': SimTypeFunction([SimTypeBottom(label="IMFByteStream"), SimTypePointer(SimTypeBottom(label="IMFMediaSink"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pIByteStream", "ppIMediaSink"]),
        #
        'MFCreateASFMediaSinkActivate': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IMFASFContentInfo"), SimTypePointer(SimTypeBottom(label="IMFActivate"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszFileName", "pContentInfo", "ppIActivate"]),
        #
        'MFCreateWMVEncoderActivate': SimTypeFunction([SimTypeBottom(label="IMFMediaType"), SimTypeBottom(label="IPropertyStore"), SimTypePointer(SimTypeBottom(label="IMFActivate"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMediaType", "pEncodingConfigurationProperties", "ppActivate"]),
        #
        'MFCreateWMAEncoderActivate': SimTypeFunction([SimTypeBottom(label="IMFMediaType"), SimTypeBottom(label="IPropertyStore"), SimTypePointer(SimTypeBottom(label="IMFActivate"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMediaType", "pEncodingConfigurationProperties", "ppActivate"]),
        #
        'MFCreateASFStreamingMediaSink': SimTypeFunction([SimTypeBottom(label="IMFByteStream"), SimTypePointer(SimTypeBottom(label="IMFMediaSink"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pIByteStream", "ppIMediaSink"]),
        #
        'MFCreateASFStreamingMediaSinkActivate': SimTypeFunction([SimTypeBottom(label="IMFActivate"), SimTypeBottom(label="IMFASFContentInfo"), SimTypePointer(SimTypeBottom(label="IMFActivate"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pByteStreamActivate", "pContentInfo", "ppIActivate"]),
        #
        'MFCreateVideoRenderer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["riidRenderer", "ppVideoRenderer"]),
        #
        'MFCreateEncryptedMediaExtensionsStoreActivate': SimTypeFunction([SimTypeBottom(label="IMFPMPHostApp"), SimTypeBottom(label="IStream"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="IMFActivate"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pmpHost", "objectStream", "classId", "activate"]),
    }

lib.set_prototypes(prototypes)
