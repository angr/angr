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
lib.set_library_names("d3d10_1.dll")
prototypes = \
    {
        # 
        'D3D10CreateDevice1': SimTypeFunction([SimTypeBottom(label="IDXGIAdapter"), SimTypeInt(signed=False, label="D3D10_DRIVER_TYPE"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="D3D10_FEATURE_LEVEL1"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="ID3D10Device1"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAdapter", "DriverType", "Software", "Flags", "HardwareLevel", "SDKVersion", "ppDevice"]),
        # 
        'D3D10CreateDeviceAndSwapChain1': SimTypeFunction([SimTypeBottom(label="IDXGIAdapter"), SimTypeInt(signed=False, label="D3D10_DRIVER_TYPE"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="D3D10_FEATURE_LEVEL1"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"BufferDesc": SimStruct({"Width": SimTypeInt(signed=False, label="UInt32"), "Height": SimTypeInt(signed=False, label="UInt32"), "RefreshRate": SimStruct({"Numerator": SimTypeInt(signed=False, label="UInt32"), "Denominator": SimTypeInt(signed=False, label="UInt32")}, name="DXGI_RATIONAL", pack=False, align=None), "Format": SimTypeInt(signed=False, label="DXGI_FORMAT"), "ScanlineOrdering": SimTypeInt(signed=False, label="DXGI_MODE_SCANLINE_ORDER"), "Scaling": SimTypeInt(signed=False, label="DXGI_MODE_SCALING")}, name="DXGI_MODE_DESC", pack=False, align=None), "SampleDesc": SimStruct({"Count": SimTypeInt(signed=False, label="UInt32"), "Quality": SimTypeInt(signed=False, label="UInt32")}, name="DXGI_SAMPLE_DESC", pack=False, align=None), "BufferUsage": SimTypeInt(signed=False, label="UInt32"), "BufferCount": SimTypeInt(signed=False, label="UInt32"), "OutputWindow": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "Windowed": SimTypeInt(signed=True, label="Int32"), "SwapEffect": SimTypeInt(signed=False, label="DXGI_SWAP_EFFECT"), "Flags": SimTypeInt(signed=False, label="UInt32")}, name="DXGI_SWAP_CHAIN_DESC", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="IDXGISwapChain"), offset=0), SimTypePointer(SimTypeBottom(label="ID3D10Device1"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAdapter", "DriverType", "Software", "Flags", "HardwareLevel", "SDKVersion", "pSwapChainDesc", "ppSwapChain", "ppDevice"]),
    }

lib.set_prototypes(prototypes)
