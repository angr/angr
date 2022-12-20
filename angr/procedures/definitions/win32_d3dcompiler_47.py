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
lib.set_library_names("d3dcompiler_47.dll")
prototypes = \
    {
        #
        'D3DDisassemble11Trace': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeBottom(label="ID3D11ShaderTrace"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrcData", "SrcDataSize", "pTrace", "StartStep", "NumSteps", "Flags", "ppDisassembly"]),
        #
        'D3DReadFileToBlob': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pFileName", "ppContents"]),
        #
        'D3DWriteBlobToFile': SimTypeFunction([SimTypeBottom(label="ID3DBlob"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pBlob", "pFileName", "bOverwrite"]),
        #
        'D3DCompile': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimStruct({"Name": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "Definition": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="D3D_SHADER_MACRO", pack=False, align=None), offset=0), SimTypeBottom(label="ID3DInclude"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrcData", "SrcDataSize", "pSourceName", "pDefines", "pInclude", "pEntrypoint", "pTarget", "Flags1", "Flags2", "ppCode", "ppErrorMsgs"]),
        #
        'D3DCompile2': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimStruct({"Name": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "Definition": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="D3D_SHADER_MACRO", pack=False, align=None), offset=0), SimTypeBottom(label="ID3DInclude"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrcData", "SrcDataSize", "pSourceName", "pDefines", "pInclude", "pEntrypoint", "pTarget", "Flags1", "Flags2", "SecondaryDataFlags", "pSecondaryData", "SecondaryDataSize", "ppCode", "ppErrorMsgs"]),
        #
        'D3DCompileFromFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimStruct({"Name": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "Definition": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="D3D_SHADER_MACRO", pack=False, align=None), offset=0), SimTypeBottom(label="ID3DInclude"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pFileName", "pDefines", "pInclude", "pEntrypoint", "pTarget", "Flags1", "Flags2", "ppCode", "ppErrorMsgs"]),
        #
        'D3DPreprocess': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimStruct({"Name": SimTypePointer(SimTypeChar(label="Byte"), offset=0), "Definition": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="D3D_SHADER_MACRO", pack=False, align=None), offset=0), SimTypeBottom(label="ID3DInclude"), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrcData", "SrcDataSize", "pSourceName", "pDefines", "pInclude", "ppCodeText", "ppErrorMsgs"]),
        #
        'D3DGetDebugInfo': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrcData", "SrcDataSize", "ppDebugInfo"]),
        #
        'D3DReflect': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrcData", "SrcDataSize", "pInterface", "ppReflector"]),
        #
        'D3DReflectLibrary': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrcData", "SrcDataSize", "riid", "ppReflector"]),
        #
        'D3DDisassemble': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrcData", "SrcDataSize", "Flags", "szComments", "ppDisassembly"]),
        #
        'D3DDisassembleRegion': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrcData", "SrcDataSize", "Flags", "szComments", "StartByteOffset", "NumInsts", "pFinishByteOffset", "ppDisassembly"]),
        #
        'D3DCreateLinker': SimTypeFunction([SimTypePointer(SimTypeBottom(label="ID3D11Linker"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppLinker"]),
        #
        'D3DLoadModule': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="ID3D11Module"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrcData", "cbSrcDataSize", "ppModule"]),
        #
        'D3DCreateFunctionLinkingGraph': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="ID3D11FunctionLinkingGraph"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uFlags", "ppFunctionLinkingGraph"]),
        #
        'D3DGetTraceInstructionOffsets': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrcData", "SrcDataSize", "Flags", "StartInstIndex", "NumInsts", "pOffsets", "pTotalInsts"]),
        #
        'D3DGetInputSignatureBlob': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrcData", "SrcDataSize", "ppSignatureBlob"]),
        #
        'D3DGetOutputSignatureBlob': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrcData", "SrcDataSize", "ppSignatureBlob"]),
        #
        'D3DGetInputAndOutputSignatureBlob': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrcData", "SrcDataSize", "ppSignatureBlob"]),
        #
        'D3DStripShader': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pShaderBytecode", "BytecodeLength", "uStripFlags", "ppStrippedBlob"]),
        #
        'D3DGetBlobPart': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="D3D_BLOB_PART"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrcData", "SrcDataSize", "Part", "Flags", "ppPart"]),
        #
        'D3DSetBlobPart': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="D3D_BLOB_PART"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrcData", "SrcDataSize", "Part", "Flags", "pPart", "PartSize", "ppNewShader"]),
        #
        'D3DCreateBlob': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["Size", "ppBlob"]),
        #
        'D3DCompressShaders': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"pBytecode": SimTypePointer(SimTypeBottom(label="Void"), offset=0), "BytecodeLength": SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)}, name="D3D_SHADER_DATA", pack=False, align=None), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["uNumShaders", "pShaderData", "uFlags", "ppCompressedData"]),
        #
        'D3DDecompressShaders': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="ID3DBlob"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pSrcData", "SrcDataSize", "uNumShaders", "uStartIndex", "pIndices", "uFlags", "ppShaders", "pTotalShaders"]),
        #
        'D3DDisassemble10Effect': SimTypeFunction([SimTypeBottom(label="ID3D10Effect"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="ID3DBlob"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pEffect", "Flags", "ppDisassembly"]),
    }

lib.set_prototypes(prototypes)
