# pylint:disable=line-too-long
import logging

from ...sim_type import SimTypeFunction,     SimTypeShort, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeDouble, SimTypeFloat,     SimTypePointer,     SimTypeChar,     SimStruct,     SimTypeFixedSizeArray,     SimTypeBottom,     SimUnion,     SimTypeBool
from ...calling_conventions import SimCCStdcall, SimCCMicrosoftAMD64
from .. import SIM_PROCEDURES as P
from . import SimLibrary


_l = logging.getLogger(name=__name__)


lib = SimLibrary()
lib.set_default_cc('X86', SimCCStdcall)
lib.set_default_cc('AMD64', SimCCMicrosoftAMD64)
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
        'MFCreateSequencerSegmentOffset': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeLongLong(signed=True, label="Int64"), SimTypePointer(SimStruct({"Anonymous": SimUnion({"Anonymous": SimStruct({"vt": SimTypeShort(signed=False, label="UInt16"), "wReserved1": SimTypeShort(signed=False, label="UInt16"), "wReserved2": SimTypeShort(signed=False, label="UInt16"), "wReserved3": SimTypeShort(signed=False, label="UInt16"), "Anonymous": SimUnion({"cVal": SimTypeBottom(label="CHAR"), "bVal": SimTypeChar(label="Byte"), "iVal": SimTypeShort(signed=True, label="Int16"), "uiVal": SimTypeShort(signed=False, label="UInt16"), "lVal": SimTypeInt(signed=True, label="Int32"), "ulVal": SimTypeInt(signed=False, label="UInt32"), "intVal": SimTypeInt(signed=True, label="Int32"), "uintVal": SimTypeInt(signed=False, label="UInt32"), "hVal": SimTypeBottom(label="LARGE_INTEGER"), "uhVal": SimTypeBottom(label="ULARGE_INTEGER"), "fltVal": SimTypeFloat(size=32), "dblVal": SimTypeFloat(size=64), "boolVal": SimTypeShort(signed=True, label="Int16"), "__OBSOLETE__VARIANT_BOOL": SimTypeShort(signed=True, label="Int16"), "scode": SimTypeInt(signed=True, label="Int32"), "cyVal": SimTypeBottom(label="CY"), "date": SimTypeFloat(size=64), "filetime": SimStruct({"dwLowDateTime": SimTypeInt(signed=False, label="UInt32"), "dwHighDateTime": SimTypeInt(signed=False, label="UInt32")}, name="FILETIME", pack=False, align=None), "puuid": SimTypePointer(SimTypeBottom(label="Guid"), offset=0), "pclipdata": SimTypePointer(SimTypeBottom(label="CLIPDATA"), offset=0), "bstrVal": SimTypePointer(SimTypeChar(label="Char"), offset=0), "bstrblobVal": SimTypeBottom(label="BSTRBLOB"), "blob": SimTypeBottom(label="BLOB"), "pszVal": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "pwszVal": SimTypePointer(SimTypeChar(label="Char"), offset=0), "punkVal": SimTypeBottom(label="IUnknown"), "pdispVal": SimTypeBottom(label="IDispatch"), "pStream": SimTypeBottom(label="IStream"), "pStorage": SimTypeBottom(label="IStorage"), "pVersionedStream": SimTypePointer(SimStruct({"guidVersion": SimTypeBottom(label="Guid"), "pStream": SimTypeBottom(label="IStream")}, name="VERSIONEDSTREAM", pack=False, align=None), offset=0), "parray": SimTypePointer(SimTypeBottom(label="SAFEARRAY"), offset=0), "cac": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="CAC", pack=False, align=None), "caub": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="CAUB", pack=False, align=None), "cai": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)}, name="CAI", pack=False, align=None), "caui": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)}, name="CAUI", pack=False, align=None), "cal": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)}, name="CAL", pack=False, align=None), "caul": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)}, name="CAUL", pack=False, align=None), "cah": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeBottom(label="LARGE_INTEGER"), offset=0)}, name="CAH", pack=False, align=None), "cauh": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeBottom(label="ULARGE_INTEGER"), offset=0)}, name="CAUH", pack=False, align=None), "caflt": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeFloat(size=32), offset=0)}, name="CAFLT", pack=False, align=None), "cadbl": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeFloat(size=64), offset=0)}, name="CADBL", pack=False, align=None), "cabool": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0)}, name="CABOOL", pack=False, align=None), "cascode": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)}, name="CASCODE", pack=False, align=None), "cacy": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeBottom(label="CY"), offset=0)}, name="CACY", pack=False, align=None), "cadate": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeFloat(size=64), offset=0)}, name="CADATE", pack=False, align=None), "cafiletime": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimStruct({"dwLowDateTime": SimTypeInt(signed=False, label="UInt32"), "dwHighDateTime": SimTypeInt(signed=False, label="UInt32")}, name="FILETIME", pack=False, align=None), offset=0)}, name="CAFILETIME", pack=False, align=None), "cauuid": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeBottom(label="Guid"), offset=0)}, name="CACLSID", pack=False, align=None), "caclipdata": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeBottom(label="CLIPDATA"), offset=0)}, name="CACLIPDATA", pack=False, align=None), "cabstr": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)}, name="CABSTR", pack=False, align=None), "cabstrblob": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeBottom(label="BSTRBLOB"), offset=0)}, name="CABSTRBLOB", pack=False, align=None), "calpstr": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)}, name="CALPSTR", pack=False, align=None), "calpwstr": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)}, name="CALPWSTR", pack=False, align=None), "capropvar": SimStruct({"cElems": SimTypeInt(signed=False, label="UInt32"), "pElems": SimTypePointer(SimTypeBottom(label="PROPVARIANT"), offset=0)}, name="CAPROPVARIANT", pack=False, align=None), "pcVal": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "pbVal": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "piVal": SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0), "puiVal": SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), "plVal": SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), "pulVal": SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), "pintVal": SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), "puintVal": SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), "pfltVal": SimTypePointer(SimTypeFloat(size=32), offset=0), "pdblVal": SimTypePointer(SimTypeFloat(size=64), offset=0), "pboolVal": SimTypePointer(SimTypeShort(signed=True, label="Int16"), offset=0), "pdecVal": SimTypePointer(SimTypeBottom(label="DECIMAL"), offset=0), "pscode": SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), "pcyVal": SimTypePointer(SimTypeBottom(label="CY"), offset=0), "pdate": SimTypePointer(SimTypeFloat(size=64), offset=0), "pbstrVal": SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), "ppunkVal": SimTypePointer(SimTypeBottom(label="IUnknown"), offset=0), "ppdispVal": SimTypePointer(SimTypeBottom(label="IDispatch"), offset=0), "pparray": SimTypePointer(SimTypePointer(SimTypeBottom(label="SAFEARRAY"), offset=0), offset=0), "pvarVal": SimTypePointer(SimTypeBottom(label="PROPVARIANT"), offset=0)}, name="<anon>", label="None")}, name="_Anonymous_e__Struct", pack=False, align=None), "decVal": SimTypeBottom(label="DECIMAL")}, name="<anon>", label="None")}, name="PROPVARIANT", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwId", "hnsOffset", "pvarSegmentOffset"]),
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
