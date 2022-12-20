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
lib.set_library_names("d3d11.dll")
prototypes = \
    {
        #
        'D3D11CreateDevice': SimTypeFunction([SimTypeBottom(label="IDXGIAdapter"), SimTypeInt(signed=False, label="D3D_DRIVER_TYPE"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="D3D11_CREATE_DEVICE_FLAG"), SimTypePointer(SimTypeInt(signed=False, label="D3D_FEATURE_LEVEL"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="ID3D11Device"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="D3D_FEATURE_LEVEL"), offset=0), SimTypePointer(SimTypeBottom(label="ID3D11DeviceContext"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAdapter", "DriverType", "Software", "Flags", "pFeatureLevels", "FeatureLevels", "SDKVersion", "ppDevice", "pFeatureLevel", "ppImmediateContext"]),
        #
        'D3D11CreateDeviceAndSwapChain': SimTypeFunction([SimTypeBottom(label="IDXGIAdapter"), SimTypeInt(signed=False, label="D3D_DRIVER_TYPE"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="D3D11_CREATE_DEVICE_FLAG"), SimTypePointer(SimTypeInt(signed=False, label="D3D_FEATURE_LEVEL"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"BufferDesc": SimStruct({"Width": SimTypeInt(signed=False, label="UInt32"), "Height": SimTypeInt(signed=False, label="UInt32"), "RefreshRate": SimStruct({"Numerator": SimTypeInt(signed=False, label="UInt32"), "Denominator": SimTypeInt(signed=False, label="UInt32")}, name="DXGI_RATIONAL", pack=False, align=None), "Format": SimTypeInt(signed=False, label="DXGI_FORMAT"), "ScanlineOrdering": SimTypeInt(signed=False, label="DXGI_MODE_SCANLINE_ORDER"), "Scaling": SimTypeInt(signed=False, label="DXGI_MODE_SCALING")}, name="DXGI_MODE_DESC", pack=False, align=None), "SampleDesc": SimStruct({"Count": SimTypeInt(signed=False, label="UInt32"), "Quality": SimTypeInt(signed=False, label="UInt32")}, name="DXGI_SAMPLE_DESC", pack=False, align=None), "BufferUsage": SimTypeInt(signed=False, label="UInt32"), "BufferCount": SimTypeInt(signed=False, label="UInt32"), "OutputWindow": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "Windowed": SimTypeInt(signed=True, label="Int32"), "SwapEffect": SimTypeInt(signed=False, label="DXGI_SWAP_EFFECT"), "Flags": SimTypeInt(signed=False, label="UInt32")}, name="DXGI_SWAP_CHAIN_DESC", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="IDXGISwapChain"), offset=0), SimTypePointer(SimTypeBottom(label="ID3D11Device"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="D3D_FEATURE_LEVEL"), offset=0), SimTypePointer(SimTypeBottom(label="ID3D11DeviceContext"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAdapter", "DriverType", "Software", "Flags", "pFeatureLevels", "FeatureLevels", "SDKVersion", "pSwapChainDesc", "ppSwapChain", "ppDevice", "pFeatureLevel", "ppImmediateContext"]),
        #
        'D3D11On12CreateDevice': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="D3D_FEATURE_LEVEL"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IUnknown"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="ID3D11Device"), offset=0), SimTypePointer(SimTypeBottom(label="ID3D11DeviceContext"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="D3D_FEATURE_LEVEL"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pDevice", "Flags", "pFeatureLevels", "FeatureLevels", "ppCommandQueues", "NumQueues", "NodeMask", "ppDevice", "ppImmediateContext", "pChosenFeatureLevel"]),
        #
        'CreateDirect3D11DeviceFromDXGIDevice': SimTypeFunction([SimTypeBottom(label="IDXGIDevice"), SimTypePointer(SimTypeBottom(label="IInspectable"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dxgiDevice", "graphicsDevice"]),
        #
        'CreateDirect3D11SurfaceFromDXGISurface': SimTypeFunction([SimTypeBottom(label="IDXGISurface"), SimTypePointer(SimTypeBottom(label="IInspectable"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dgxiSurface", "graphicsSurface"]),
    }

lib.set_prototypes(prototypes)
