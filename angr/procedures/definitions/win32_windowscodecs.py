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
lib.set_library_names("windowscodecs.dll")
prototypes = \
    {
        # 
        'WICConvertBitmapSource': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeBottom(label="IWICBitmapSource"), SimTypePointer(SimTypeBottom(label="IWICBitmapSource"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dstFormat", "pISrc", "ppIDst"]),
        # 
        'WICCreateBitmapFromSection': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IWICBitmap"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["width", "height", "pixelFormat", "hSection", "stride", "offset", "ppIBitmap"]),
        # 
        'WICCreateBitmapFromSectionEx': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="WICSectionAccessLevel"), SimTypePointer(SimTypeBottom(label="IWICBitmap"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["width", "height", "pixelFormat", "hSection", "stride", "offset", "desiredAccessLevel", "ppIBitmap"]),
        # 
        'WICMapGuidToShortName': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["guid", "cchName", "wzName", "pcchActual"]),
        # 
        'WICMapShortNameToGuid': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["wzName", "pguid"]),
        # 
        'WICMapSchemaToName': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["guidMetadataFormat", "pwzSchema", "cchName", "wzName", "pcchActual"]),
        # 
        'WICMatchMetadataContent': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeBottom(label="IStream"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["guidContainerFormat", "pguidVendor", "pIStream", "pguidMetadataFormat"]),
        # 
        'WICSerializeMetadataContent': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeBottom(label="IWICMetadataWriter"), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IStream")], SimTypeInt(signed=True, label="Int32"), arg_names=["guidContainerFormat", "pIWriter", "dwPersistOptions", "pIStream"]),
        # 
        'WICGetMetadataContentSize': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeBottom(label="IWICMetadataWriter"), SimTypePointer(SimUnion({"Anonymous": SimStruct({"LowPart": SimTypeInt(signed=False, label="UInt32"), "HighPart": SimTypeInt(signed=False, label="UInt32")}, name="_Anonymous_e__Struct", pack=False, align=None), "u": SimStruct({"LowPart": SimTypeInt(signed=False, label="UInt32"), "HighPart": SimTypeInt(signed=False, label="UInt32")}, name="_u_e__Struct", pack=False, align=None), "QuadPart": SimTypeLongLong(signed=False, label="UInt64")}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["guidContainerFormat", "pIWriter", "pcbSize"]),
    }

lib.set_prototypes(prototypes)
