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
lib.set_library_names("d3d10.dll")
prototypes = \
    {
        #
        'D3D10CreateDevice': SimTypeFunction([SimTypeBottom(label="IDXGIAdapter"), SimTypeInt(signed=False, label="D3D10_DRIVER_TYPE"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="ID3D10Device"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAdapter", "DriverType", "Software", "Flags", "SDKVersion", "ppDevice"]),
        #
        'D3D10CreateDeviceAndSwapChain': SimTypeFunction([SimTypeBottom(label="IDXGIAdapter"), SimTypeInt(signed=False, label="D3D10_DRIVER_TYPE"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("DXGI_SWAP_CHAIN_DESC", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="IDXGISwapChain"), offset=0), SimTypePointer(SimTypeBottom(label="ID3D10Device"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pAdapter", "DriverType", "Software", "Flags", "SDKVersion", "pSwapChainDesc", "ppSwapChain", "ppDevice"]),
        #
        'D3D10CreateBlob': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["NumBytes", "ppBuffer"]),
        #
        'D3D10CompileShader': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("D3D_SHADER_MACRO", SimStruct), offset=0), SimTypeBottom(label="ID3DInclude"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrcData", "SrcDataSize", "pFileName", "pDefines", "pInclude", "pFunctionName", "pProfile", "Flags", "ppShader", "ppErrorMsgs"]),
        #
        'D3D10DisassembleShader': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pShader", "BytecodeLength", "EnableColorCode", "pComments", "ppDisassembly"]),
        #
        'D3D10GetPixelShaderProfile': SimTypeFunction([SimTypeBottom(label="ID3D10Device")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pDevice"]),
        #
        'D3D10GetVertexShaderProfile': SimTypeFunction([SimTypeBottom(label="ID3D10Device")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pDevice"]),
        #
        'D3D10GetGeometryShaderProfile': SimTypeFunction([SimTypeBottom(label="ID3D10Device")], SimTypePointer(SimTypeChar(label="Byte"), offset=0), arg_names=["pDevice"]),
        #
        'D3D10ReflectShader': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="ID3D10ShaderReflection"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pShaderBytecode", "BytecodeLength", "ppReflector"]),
        #
        'D3D10PreprocessShader': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("D3D_SHADER_MACRO", SimStruct), offset=0), SimTypeBottom(label="ID3DInclude"), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrcData", "SrcDataSize", "pFileName", "pDefines", "pInclude", "ppShaderText", "ppErrorMsgs"]),
        #
        'D3D10GetInputSignatureBlob': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pShaderBytecode", "BytecodeLength", "ppSignatureBlob"]),
        #
        'D3D10GetOutputSignatureBlob': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pShaderBytecode", "BytecodeLength", "ppSignatureBlob"]),
        #
        'D3D10GetInputAndOutputSignatureBlob': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pShaderBytecode", "BytecodeLength", "ppSignatureBlob"]),
        #
        'D3D10GetShaderDebugInfo': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pShaderBytecode", "BytecodeLength", "ppDebugInfo"]),
        #
        'D3D10StateBlockMaskUnion': SimTypeFunction([SimTypePointer(SimTypeRef("D3D10_STATE_BLOCK_MASK", SimStruct), offset=0), SimTypePointer(SimTypeRef("D3D10_STATE_BLOCK_MASK", SimStruct), offset=0), SimTypePointer(SimTypeRef("D3D10_STATE_BLOCK_MASK", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pA", "pB", "pResult"]),
        #
        'D3D10StateBlockMaskIntersect': SimTypeFunction([SimTypePointer(SimTypeRef("D3D10_STATE_BLOCK_MASK", SimStruct), offset=0), SimTypePointer(SimTypeRef("D3D10_STATE_BLOCK_MASK", SimStruct), offset=0), SimTypePointer(SimTypeRef("D3D10_STATE_BLOCK_MASK", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pA", "pB", "pResult"]),
        #
        'D3D10StateBlockMaskDifference': SimTypeFunction([SimTypePointer(SimTypeRef("D3D10_STATE_BLOCK_MASK", SimStruct), offset=0), SimTypePointer(SimTypeRef("D3D10_STATE_BLOCK_MASK", SimStruct), offset=0), SimTypePointer(SimTypeRef("D3D10_STATE_BLOCK_MASK", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pA", "pB", "pResult"]),
        #
        'D3D10StateBlockMaskEnableCapture': SimTypeFunction([SimTypePointer(SimTypeRef("D3D10_STATE_BLOCK_MASK", SimStruct), offset=0), SimTypeInt(signed=False, label="D3D10_DEVICE_STATE_TYPES"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pMask", "StateType", "RangeStart", "RangeLength"]),
        #
        'D3D10StateBlockMaskDisableCapture': SimTypeFunction([SimTypePointer(SimTypeRef("D3D10_STATE_BLOCK_MASK", SimStruct), offset=0), SimTypeInt(signed=False, label="D3D10_DEVICE_STATE_TYPES"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pMask", "StateType", "RangeStart", "RangeLength"]),
        #
        'D3D10StateBlockMaskEnableAll': SimTypeFunction([SimTypePointer(SimTypeRef("D3D10_STATE_BLOCK_MASK", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMask"]),
        #
        'D3D10StateBlockMaskDisableAll': SimTypeFunction([SimTypePointer(SimTypeRef("D3D10_STATE_BLOCK_MASK", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMask"]),
        #
        'D3D10StateBlockMaskGetSetting': SimTypeFunction([SimTypePointer(SimTypeRef("D3D10_STATE_BLOCK_MASK", SimStruct), offset=0), SimTypeInt(signed=False, label="D3D10_DEVICE_STATE_TYPES"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pMask", "StateType", "Entry"]),
        #
        'D3D10CreateStateBlock': SimTypeFunction([SimTypeBottom(label="ID3D10Device"), SimTypePointer(SimTypeRef("D3D10_STATE_BLOCK_MASK", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="ID3D10StateBlock"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pDevice", "pStateBlockMask", "ppStateBlock"]),
        #
        'D3D10CompileEffectFromMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("D3D_SHADER_MACRO", SimStruct), offset=0), SimTypeBottom(label="ID3DInclude"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pData", "DataLength", "pSrcFileName", "pDefines", "pInclude", "HLSLFlags", "FXFlags", "ppCompiledEffect", "ppErrors"]),
        #
        'D3D10CreateEffectFromMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="ID3D10Device"), SimTypeBottom(label="ID3D10EffectPool"), SimTypePointer(SimTypeBottom(label="ID3D10Effect"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pData", "DataLength", "FXFlags", "pDevice", "pEffectPool", "ppEffect"]),
        #
        'D3D10CreateEffectPoolFromMemory': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="ID3D10Device"), SimTypePointer(SimTypeBottom(label="ID3D10EffectPool"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pData", "DataLength", "FXFlags", "pDevice", "ppEffectPool"]),
        #
        'D3D10DisassembleEffect': SimTypeFunction([SimTypeBottom(label="ID3D10Effect"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pEffect", "EnableColorCode", "ppDisassembly"]),
    }

lib.set_prototypes(prototypes)
