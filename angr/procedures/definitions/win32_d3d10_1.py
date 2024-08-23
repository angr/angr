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
lib.set_library_names("d3d10_1.dll")
prototypes = \
    {
        #
        'D3D10CreateDevice1': SimTypeFunction([SimTypeBottom(label="IDXGIAdapter"), SimTypeInt(signed=False, label="D3D10_DRIVER_TYPE"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="D3D10_FEATURE_LEVEL1"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="ID3D10Device1"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAdapter", "DriverType", "Software", "Flags", "HardwareLevel", "SDKVersion", "ppDevice"]),
        #
        'D3D10CreateDeviceAndSwapChain1': SimTypeFunction([SimTypeBottom(label="IDXGIAdapter"), SimTypeInt(signed=False, label="D3D10_DRIVER_TYPE"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="D3D10_FEATURE_LEVEL1"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DXGI_SWAP_CHAIN_DESC", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="IDXGISwapChain"), offset=0), SimTypePointer(SimTypeBottom(label="ID3D10Device1"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAdapter", "DriverType", "Software", "Flags", "HardwareLevel", "SDKVersion", "pSwapChainDesc", "ppSwapChain", "ppDevice"]),
    }

lib.set_prototypes(prototypes)
