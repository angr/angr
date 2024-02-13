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
lib.set_library_names("d3d12.dll")
prototypes = \
    {
        #
        'D3D12SerializeRootSignature': SimTypeFunction([SimTypePointer(SimTypeRef("D3D12_ROOT_SIGNATURE_DESC", SimStruct), offset=0), SimTypeInt(signed=False, label="D3D_ROOT_SIGNATURE_VERSION"), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pRootSignature", "Version", "ppBlob", "ppErrorBlob"]),
        #
        'D3D12CreateRootSignatureDeserializer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrcData", "SrcDataSizeInBytes", "pRootSignatureDeserializerInterface", "ppRootSignatureDeserializer"]),
        #
        'D3D12SerializeVersionedRootSignature': SimTypeFunction([SimTypePointer(SimTypeRef("D3D12_VERSIONED_ROOT_SIGNATURE_DESC", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pRootSignature", "ppBlob", "ppErrorBlob"]),
        #
        'D3D12CreateVersionedRootSignatureDeserializer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrcData", "SrcDataSizeInBytes", "pRootSignatureDeserializerInterface", "ppRootSignatureDeserializer"]),
        #
        'D3D12CreateDevice': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypeInt(signed=False, label="D3D_FEATURE_LEVEL"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAdapter", "MinimumFeatureLevel", "riid", "ppDevice"]),
        #
        'D3D12GetDebugInterface': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["riid", "ppvDebug"]),
        #
        'D3D12EnableExperimentalFeatures': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), label="LPArray", offset=0), SimTypePointer(SimTypeBottom(label="Void"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NumFeatures", "pIIDs", "pConfigurationStructs", "pConfigurationStructSizes"]),
        #
        'D3D12GetInterface': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["rclsid", "riid", "ppvDebug"]),
    }

lib.set_prototypes(prototypes)
