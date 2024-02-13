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
lib.set_library_names("d3d11.dll")
prototypes = \
    {
        #
        'D3D11CreateDevice': SimTypeFunction([SimTypeBottom(label="IDXGIAdapter"), SimTypeInt(signed=False, label="D3D_DRIVER_TYPE"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="D3D11_CREATE_DEVICE_FLAG"), SimTypePointer(SimTypeInt(signed=False, label="D3D_FEATURE_LEVEL"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="ID3D11Device"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="D3D_FEATURE_LEVEL"), offset=0), SimTypePointer(SimTypeBottom(label="ID3D11DeviceContext"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAdapter", "DriverType", "Software", "Flags", "pFeatureLevels", "FeatureLevels", "SDKVersion", "ppDevice", "pFeatureLevel", "ppImmediateContext"]),
        #
        'D3D11CreateDeviceAndSwapChain': SimTypeFunction([SimTypeBottom(label="IDXGIAdapter"), SimTypeInt(signed=False, label="D3D_DRIVER_TYPE"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="D3D11_CREATE_DEVICE_FLAG"), SimTypePointer(SimTypeInt(signed=False, label="D3D_FEATURE_LEVEL"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DXGI_SWAP_CHAIN_DESC", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="IDXGISwapChain"), offset=0), SimTypePointer(SimTypeBottom(label="ID3D11Device"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="D3D_FEATURE_LEVEL"), offset=0), SimTypePointer(SimTypeBottom(label="ID3D11DeviceContext"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAdapter", "DriverType", "Software", "Flags", "pFeatureLevels", "FeatureLevels", "SDKVersion", "pSwapChainDesc", "ppSwapChain", "ppDevice", "pFeatureLevel", "ppImmediateContext"]),
        #
        'D3D11On12CreateDevice': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="D3D_FEATURE_LEVEL"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IUnknown"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="ID3D11Device"), offset=0), SimTypePointer(SimTypeBottom(label="ID3D11DeviceContext"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="D3D_FEATURE_LEVEL"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pDevice", "Flags", "pFeatureLevels", "FeatureLevels", "ppCommandQueues", "NumQueues", "NodeMask", "ppDevice", "ppImmediateContext", "pChosenFeatureLevel"]),
    }

lib.set_prototypes(prototypes)
