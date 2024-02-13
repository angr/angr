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
lib.set_library_names("mscms.dll")
prototypes = \
    {
        #
        'SpoolerCopyFileEvent': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPrinterName", "pszKey", "dwCopyFileEvent"]),
        #
        'GenerateCopyFilePaths': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pszPrinterName", "pszDirectory", "pSplClientInfo", "dwLevel", "pszSourceDir", "pcchSourceDirSize", "pszTargetDir", "pcchTargetDirSize", "dwFlags"]),
        #
        'OpenColorProfileA': SimTypeFunction([SimTypePointer(SimTypeRef("PROFILE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pProfile", "dwDesiredAccess", "dwShareMode", "dwCreationMode"]),
        #
        'OpenColorProfileW': SimTypeFunction([SimTypePointer(SimTypeRef("PROFILE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pProfile", "dwDesiredAccess", "dwShareMode", "dwCreationMode"]),
        #
        'CloseColorProfile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProfile"]),
        #
        'GetColorProfileFromHandle': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProfile", "pProfile", "pcbProfile"]),
        #
        'IsColorProfileValid': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProfile", "pbValid"]),
        #
        'CreateProfileFromLogColorSpaceA': SimTypeFunction([SimTypePointer(SimTypeRef("LOGCOLORSPACEA", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pLogColorSpace", "pProfile"]),
        #
        'CreateProfileFromLogColorSpaceW': SimTypeFunction([SimTypePointer(SimTypeRef("LOGCOLORSPACEW", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pLogColorSpace", "pProfile"]),
        #
        'GetCountColorProfileElements': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProfile", "pnElementCount"]),
        #
        'GetColorProfileHeader': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PROFILEHEADER", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProfile", "pHeader"]),
        #
        'GetColorProfileElementTag': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProfile", "dwIndex", "pTag"]),
        #
        'IsColorProfileTagPresent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProfile", "tag", "pbPresent"]),
        #
        'GetColorProfileElement': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProfile", "tag", "dwOffset", "pcbElement", "pElement", "pbReference"]),
        #
        'SetColorProfileHeader': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("PROFILEHEADER", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProfile", "pHeader"]),
        #
        'SetColorProfileElementSize': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hProfile", "tagType", "pcbElement"]),
        #
        'SetColorProfileElement': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProfile", "tag", "dwOffset", "pcbElement", "pElement"]),
        #
        'SetColorProfileElementReference': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hProfile", "newTag", "refTag"]),
        #
        'GetPS2ColorSpaceArray': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProfile", "dwIntent", "dwCSAType", "pPS2ColorSpaceArray", "pcbPS2ColorSpaceArray", "pbBinary"]),
        #
        'GetPS2ColorRenderingIntent': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProfile", "dwIntent", "pBuffer", "pcbPS2ColorRenderingIntent"]),
        #
        'GetPS2ColorRenderingDictionary': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProfile", "dwIntent", "pPS2ColorRenderingDictionary", "pcbPS2ColorRenderingDictionary", "pbBinary"]),
        #
        'GetNamedProfileInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("NAMED_PROFILE_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProfile", "pNamedProfileInfo"]),
        #
        'ConvertColorNameToIndex': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hProfile", "paColorName", "paIndex", "dwCount"]),
        #
        'ConvertIndexToColorName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hProfile", "paIndex", "paColorName", "dwCount"]),
        #
        'CreateDeviceLinkProfile': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hProfile", "nProfiles", "padwIntent", "nIntents", "dwFlags", "pProfileData", "indexPreferredCMM"]),
        #
        'CreateColorTransformA': SimTypeFunction([SimTypePointer(SimTypeRef("LOGCOLORSPACEA", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pLogColorSpace", "hDestProfile", "hTargetProfile", "dwFlags"]),
        #
        'CreateColorTransformW': SimTypeFunction([SimTypePointer(SimTypeRef("LOGCOLORSPACEW", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pLogColorSpace", "hDestProfile", "hTargetProfile", "dwFlags"]),
        #
        'CreateMultiProfileTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pahProfiles", "nProfiles", "padwIntent", "nIntents", "dwFlags", "indexPreferredCMM"]),
        #
        'DeleteColorTransform': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hxform"]),
        #
        'TranslateBitmapBits': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="BMFORMAT"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="BMFORMAT"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hColorTransform", "pSrcBits", "bmInput", "dwWidth", "dwHeight", "dwInputStride", "pDestBits", "bmOutput", "dwOutputStride", "pfnCallBack", "ulCallbackData"]),
        #
        'CheckBitmapBits': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="BMFORMAT"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hColorTransform", "pSrcBits", "bmInput", "dwWidth", "dwHeight", "dwStride", "paResult", "pfnCallback", "lpCallbackData"]),
        #
        'TranslateColors': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimUnion({"gray": SimTypeRef("GRAYCOLOR", SimStruct), "rgb": SimTypeRef("RGBCOLOR", SimStruct), "cmyk": SimTypeRef("CMYKCOLOR", SimStruct), "XYZ": SimTypeRef("XYZCOLOR", SimStruct), "Yxy": SimTypeRef("YxyCOLOR", SimStruct), "Lab": SimTypeRef("LabCOLOR", SimStruct), "gen3ch": SimTypeRef("GENERIC3CHANNEL", SimStruct), "named": SimTypeRef("NAMEDCOLOR", SimStruct), "hifi": SimTypeRef("HiFiCOLOR", SimStruct), "Anonymous": SimStruct(OrderedDict((("reserved1", SimTypeInt(signed=False, label="UInt32")), ("reserved2", SimTypePointer(SimTypeBottom(label="Void"), offset=0)),)), name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="COLORTYPE"), SimTypePointer(SimUnion({"gray": SimTypeRef("GRAYCOLOR", SimStruct), "rgb": SimTypeRef("RGBCOLOR", SimStruct), "cmyk": SimTypeRef("CMYKCOLOR", SimStruct), "XYZ": SimTypeRef("XYZCOLOR", SimStruct), "Yxy": SimTypeRef("YxyCOLOR", SimStruct), "Lab": SimTypeRef("LabCOLOR", SimStruct), "gen3ch": SimTypeRef("GENERIC3CHANNEL", SimStruct), "named": SimTypeRef("NAMEDCOLOR", SimStruct), "hifi": SimTypeRef("HiFiCOLOR", SimStruct), "Anonymous": SimStruct(OrderedDict((("reserved1", SimTypeInt(signed=False, label="UInt32")), ("reserved2", SimTypePointer(SimTypeBottom(label="Void"), offset=0)),)), name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None"), label="LPArray", offset=0), SimTypeInt(signed=False, label="COLORTYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hColorTransform", "paInputColors", "nColors", "ctInput", "paOutputColors", "ctOutput"]),
        #
        'CheckColors': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimUnion({"gray": SimTypeRef("GRAYCOLOR", SimStruct), "rgb": SimTypeRef("RGBCOLOR", SimStruct), "cmyk": SimTypeRef("CMYKCOLOR", SimStruct), "XYZ": SimTypeRef("XYZCOLOR", SimStruct), "Yxy": SimTypeRef("YxyCOLOR", SimStruct), "Lab": SimTypeRef("LabCOLOR", SimStruct), "gen3ch": SimTypeRef("GENERIC3CHANNEL", SimStruct), "named": SimTypeRef("NAMEDCOLOR", SimStruct), "hifi": SimTypeRef("HiFiCOLOR", SimStruct), "Anonymous": SimStruct(OrderedDict((("reserved1", SimTypeInt(signed=False, label="UInt32")), ("reserved2", SimTypePointer(SimTypeBottom(label="Void"), offset=0)),)), name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="COLORTYPE"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hColorTransform", "paInputColors", "nColors", "ctInput", "paResult"]),
        #
        'GetCMMInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hColorTransform", "param1"]),
        #
        'RegisterCMMA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMachineName", "cmmID", "pCMMdll"]),
        #
        'RegisterCMMW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMachineName", "cmmID", "pCMMdll"]),
        #
        'UnregisterCMMA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pMachineName", "cmmID"]),
        #
        'UnregisterCMMW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pMachineName", "cmmID"]),
        #
        'SelectCMM': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["dwCMMType"]),
        #
        'GetColorDirectoryA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMachineName", "pBuffer", "pdwSize"]),
        #
        'GetColorDirectoryW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMachineName", "pBuffer", "pdwSize"]),
        #
        'InstallColorProfileA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMachineName", "pProfileName"]),
        #
        'InstallColorProfileW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMachineName", "pProfileName"]),
        #
        'UninstallColorProfileA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pMachineName", "pProfileName", "bDelete"]),
        #
        'UninstallColorProfileW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pMachineName", "pProfileName", "bDelete"]),
        #
        'EnumColorProfilesA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("ENUMTYPEA", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMachineName", "pEnumRecord", "pEnumerationBuffer", "pdwSizeOfEnumerationBuffer", "pnProfiles"]),
        #
        'EnumColorProfilesW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("ENUMTYPEW", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMachineName", "pEnumRecord", "pEnumerationBuffer", "pdwSizeOfEnumerationBuffer", "pnProfiles"]),
        #
        'SetStandardColorSpaceProfileA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMachineName", "dwProfileID", "pProfilename"]),
        #
        'SetStandardColorSpaceProfileW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMachineName", "dwProfileID", "pProfileName"]),
        #
        'GetStandardColorSpaceProfileA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMachineName", "dwSCS", "pBuffer", "pcbSize"]),
        #
        'GetStandardColorSpaceProfileW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMachineName", "dwSCS", "pBuffer", "pcbSize"]),
        #
        'AssociateColorProfileWithDeviceA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMachineName", "pProfileName", "pDeviceName"]),
        #
        'AssociateColorProfileWithDeviceW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMachineName", "pProfileName", "pDeviceName"]),
        #
        'DisassociateColorProfileFromDeviceA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMachineName", "pProfileName", "pDeviceName"]),
        #
        'DisassociateColorProfileFromDeviceW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pMachineName", "pProfileName", "pDeviceName"]),
        #
        'WcsAssociateColorProfileWithDevice': SimTypeFunction([SimTypeInt(signed=False, label="WCS_PROFILE_MANAGEMENT_SCOPE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["scope", "pProfileName", "pDeviceName"]),
        #
        'WcsDisassociateColorProfileFromDevice': SimTypeFunction([SimTypeInt(signed=False, label="WCS_PROFILE_MANAGEMENT_SCOPE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["scope", "pProfileName", "pDeviceName"]),
        #
        'WcsEnumColorProfilesSize': SimTypeFunction([SimTypeInt(signed=False, label="WCS_PROFILE_MANAGEMENT_SCOPE"), SimTypePointer(SimTypeRef("ENUMTYPEW", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["scope", "pEnumRecord", "pdwSize"]),
        #
        'WcsEnumColorProfiles': SimTypeFunction([SimTypeInt(signed=False, label="WCS_PROFILE_MANAGEMENT_SCOPE"), SimTypePointer(SimTypeRef("ENUMTYPEW", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["scope", "pEnumRecord", "pBuffer", "dwSize", "pnProfiles"]),
        #
        'WcsGetDefaultColorProfileSize': SimTypeFunction([SimTypeInt(signed=False, label="WCS_PROFILE_MANAGEMENT_SCOPE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="COLORPROFILETYPE"), SimTypeInt(signed=False, label="COLORPROFILESUBTYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["scope", "pDeviceName", "cptColorProfileType", "cpstColorProfileSubType", "dwProfileID", "pcbProfileName"]),
        #
        'WcsGetDefaultColorProfile': SimTypeFunction([SimTypeInt(signed=False, label="WCS_PROFILE_MANAGEMENT_SCOPE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="COLORPROFILETYPE"), SimTypeInt(signed=False, label="COLORPROFILESUBTYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["scope", "pDeviceName", "cptColorProfileType", "cpstColorProfileSubType", "dwProfileID", "cbProfileName", "pProfileName"]),
        #
        'WcsSetDefaultColorProfile': SimTypeFunction([SimTypeInt(signed=False, label="WCS_PROFILE_MANAGEMENT_SCOPE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="COLORPROFILETYPE"), SimTypeInt(signed=False, label="COLORPROFILESUBTYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["scope", "pDeviceName", "cptColorProfileType", "cpstColorProfileSubType", "dwProfileID", "pProfileName"]),
        #
        'WcsSetDefaultRenderingIntent': SimTypeFunction([SimTypeInt(signed=False, label="WCS_PROFILE_MANAGEMENT_SCOPE"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["scope", "dwRenderingIntent"]),
        #
        'WcsGetDefaultRenderingIntent': SimTypeFunction([SimTypeInt(signed=False, label="WCS_PROFILE_MANAGEMENT_SCOPE"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["scope", "pdwRenderingIntent"]),
        #
        'WcsGetUsePerUserProfiles': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pDeviceName", "dwDeviceClass", "pUsePerUserProfiles"]),
        #
        'WcsSetUsePerUserProfiles': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pDeviceName", "dwDeviceClass", "usePerUserProfiles"]),
        #
        'WcsTranslateColors': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="COLORDATATYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="COLORDATATYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hColorTransform", "nColors", "nInputChannels", "cdtInput", "cbInput", "pInputData", "nOutputChannels", "cdtOutput", "cbOutput", "pOutputData"]),
        #
        'WcsCheckColors': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="COLORDATATYPE"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hColorTransform", "nColors", "nInputChannels", "cdtInput", "cbInput", "pInputData", "paResult"]),
        #
        'WcsOpenColorProfileA': SimTypeFunction([SimTypePointer(SimTypeRef("PROFILE", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROFILE", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROFILE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pCDMPProfile", "pCAMPProfile", "pGMMPProfile", "dwDesireAccess", "dwShareMode", "dwCreationMode", "dwFlags"]),
        #
        'WcsOpenColorProfileW': SimTypeFunction([SimTypePointer(SimTypeRef("PROFILE", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROFILE", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROFILE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pCDMPProfile", "pCAMPProfile", "pGMMPProfile", "dwDesireAccess", "dwShareMode", "dwCreationMode", "dwFlags"]),
        #
        'WcsCreateIccProfile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hWcsProfile", "dwOptions"]),
        #
        'WcsGetCalibrationManagementState': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pbIsEnabled"]),
        #
        'WcsSetCalibrationManagementState': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["bIsEnabled"]),
        #
        'ColorProfileAddDisplayAssociation': SimTypeFunction([SimTypeInt(signed=False, label="WCS_PROFILE_MANAGEMENT_SCOPE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeRef("LUID", SimStruct), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["scope", "profileName", "targetAdapterID", "sourceID", "setAsDefault", "associateAsAdvancedColor"]),
        #
        'ColorProfileRemoveDisplayAssociation': SimTypeFunction([SimTypeInt(signed=False, label="WCS_PROFILE_MANAGEMENT_SCOPE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeRef("LUID", SimStruct), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["scope", "profileName", "targetAdapterID", "sourceID", "dissociateAdvancedColor"]),
        #
        'ColorProfileSetDisplayDefaultAssociation': SimTypeFunction([SimTypeInt(signed=False, label="WCS_PROFILE_MANAGEMENT_SCOPE"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="COLORPROFILETYPE"), SimTypeInt(signed=False, label="COLORPROFILESUBTYPE"), SimTypeRef("LUID", SimStruct), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["scope", "profileName", "profileType", "profileSubType", "targetAdapterID", "sourceID"]),
        #
        'ColorProfileGetDisplayList': SimTypeFunction([SimTypeInt(signed=False, label="WCS_PROFILE_MANAGEMENT_SCOPE"), SimTypeRef("LUID", SimStruct), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["scope", "targetAdapterID", "sourceID", "profileList", "profileCount"]),
        #
        'ColorProfileGetDisplayDefault': SimTypeFunction([SimTypeInt(signed=False, label="WCS_PROFILE_MANAGEMENT_SCOPE"), SimTypeRef("LUID", SimStruct), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="COLORPROFILETYPE"), SimTypeInt(signed=False, label="COLORPROFILESUBTYPE"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["scope", "targetAdapterID", "sourceID", "profileType", "profileSubType", "profileName"]),
        #
        'ColorProfileGetDisplayUserScope': SimTypeFunction([SimTypeRef("LUID", SimStruct), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="WCS_PROFILE_MANAGEMENT_SCOPE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["targetAdapterID", "sourceID", "scope"]),
    }

lib.set_prototypes(prototypes)
