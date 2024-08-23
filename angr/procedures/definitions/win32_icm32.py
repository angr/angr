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
lib.set_library_names("icm32.dll")
prototypes = \
    {
        #
        'CMCheckColors': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimUnion({"gray": SimTypeRef("GRAYCOLOR", SimStruct), "rgb": SimTypeRef("RGBCOLOR", SimStruct), "cmyk": SimTypeRef("CMYKCOLOR", SimStruct), "XYZ": SimTypeRef("XYZCOLOR", SimStruct), "Yxy": SimTypeRef("YxyCOLOR", SimStruct), "Lab": SimTypeRef("LabCOLOR", SimStruct), "gen3ch": SimTypeRef("GENERIC3CHANNEL", SimStruct), "named": SimTypeRef("NAMEDCOLOR", SimStruct), "hifi": SimTypeRef("HiFiCOLOR", SimStruct), "Anonymous": SimStruct(OrderedDict((("reserved1", SimTypeInt(signed=False, label="UInt32")), ("reserved2", SimTypePointer(SimTypeBottom(label="Void"), offset=0)),)), name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="COLORTYPE"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hcmTransform", "lpaInputColors", "nColors", "ctInput", "lpaResult"]),
        #
        'CMCheckRGBs': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="BMFORMAT"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hcmTransform", "lpSrcBits", "bmInput", "dwWidth", "dwHeight", "dwStride", "lpaResult", "pfnCallback", "ulCallbackData"]),
        #
        'CMConvertColorNameToIndex': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hProfile", "paColorName", "paIndex", "dwCount"]),
        #
        'CMConvertIndexToColorName': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="SByte"), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hProfile", "paIndex", "paColorName", "dwCount"]),
        #
        'CMCreateDeviceLinkProfile': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeChar(label="Byte"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pahProfiles", "nProfiles", "padwIntents", "nIntents", "dwFlags", "lpProfileData"]),
        #
        'CMCreateMultiProfileTransform': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pahProfiles", "nProfiles", "padwIntents", "nIntents", "dwFlags"]),
        #
        'CMCreateProfileW': SimTypeFunction([SimTypePointer(SimTypeRef("LOGCOLORSPACEW", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpColorSpace", "lpProfileData"]),
        #
        'CMCreateTransform': SimTypeFunction([SimTypePointer(SimTypeRef("LOGCOLORSPACEA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpColorSpace", "lpDevCharacter", "lpTargetDevCharacter"]),
        #
        'CMCreateTransformW': SimTypeFunction([SimTypePointer(SimTypeRef("LOGCOLORSPACEW", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpColorSpace", "lpDevCharacter", "lpTargetDevCharacter"]),
        #
        'CMCreateTransformExt': SimTypeFunction([SimTypePointer(SimTypeRef("LOGCOLORSPACEA", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpColorSpace", "lpDevCharacter", "lpTargetDevCharacter", "dwFlags"]),
        #
        'CMCheckColorsInGamut': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("RGBTRIPLE", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hcmTransform", "lpaRGBTriple", "lpaResult", "nCount"]),
        #
        'CMCreateProfile': SimTypeFunction([SimTypePointer(SimTypeRef("LOGCOLORSPACEA", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpColorSpace", "lpProfileData"]),
        #
        'CMTranslateRGB': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hcmTransform", "ColorRef", "lpColorRef", "dwFlags"]),
        #
        'CMTranslateRGBs': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="BMFORMAT"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="BMFORMAT"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hcmTransform", "lpSrcBits", "bmInput", "dwWidth", "dwHeight", "dwStride", "lpDestBits", "bmOutput", "dwTranslateDirection"]),
        #
        'CMCreateTransformExtW': SimTypeFunction([SimTypePointer(SimTypeRef("LOGCOLORSPACEW", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpColorSpace", "lpDevCharacter", "lpTargetDevCharacter", "dwFlags"]),
        #
        'CMDeleteTransform': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hcmTransform"]),
        #
        'CMGetInfo': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["dwInfo"]),
        #
        'CMGetNamedProfileInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("NAMED_PROFILE_INFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProfile", "pNamedProfileInfo"]),
        #
        'CMIsProfileValid': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hProfile", "lpbValid"]),
        #
        'CMTranslateColors': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimUnion({"gray": SimTypeRef("GRAYCOLOR", SimStruct), "rgb": SimTypeRef("RGBCOLOR", SimStruct), "cmyk": SimTypeRef("CMYKCOLOR", SimStruct), "XYZ": SimTypeRef("XYZCOLOR", SimStruct), "Yxy": SimTypeRef("YxyCOLOR", SimStruct), "Lab": SimTypeRef("LabCOLOR", SimStruct), "gen3ch": SimTypeRef("GENERIC3CHANNEL", SimStruct), "named": SimTypeRef("NAMEDCOLOR", SimStruct), "hifi": SimTypeRef("HiFiCOLOR", SimStruct), "Anonymous": SimStruct(OrderedDict((("reserved1", SimTypeInt(signed=False, label="UInt32")), ("reserved2", SimTypePointer(SimTypeBottom(label="Void"), offset=0)),)), name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="COLORTYPE"), SimTypePointer(SimUnion({"gray": SimTypeRef("GRAYCOLOR", SimStruct), "rgb": SimTypeRef("RGBCOLOR", SimStruct), "cmyk": SimTypeRef("CMYKCOLOR", SimStruct), "XYZ": SimTypeRef("XYZCOLOR", SimStruct), "Yxy": SimTypeRef("YxyCOLOR", SimStruct), "Lab": SimTypeRef("LabCOLOR", SimStruct), "gen3ch": SimTypeRef("GENERIC3CHANNEL", SimStruct), "named": SimTypeRef("NAMEDCOLOR", SimStruct), "hifi": SimTypeRef("HiFiCOLOR", SimStruct), "Anonymous": SimStruct(OrderedDict((("reserved1", SimTypeInt(signed=False, label="UInt32")), ("reserved2", SimTypePointer(SimTypeBottom(label="Void"), offset=0)),)), name="_Anonymous_e__Struct", pack=False, align=None)}, name="<anon>", label="None"), label="LPArray", offset=0), SimTypeInt(signed=False, label="COLORTYPE")], SimTypeInt(signed=True, label="Int32"), arg_names=["hcmTransform", "lpaInputColors", "nColors", "ctInput", "lpaOutputColors", "ctOutput"]),
        #
        'CMTranslateRGBsExt': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="BMFORMAT"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="BMFORMAT"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1", "param2"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hcmTransform", "lpSrcBits", "bmInput", "dwWidth", "dwHeight", "dwInputStride", "lpDestBits", "bmOutput", "dwOutputStride", "lpfnCallback", "ulCallbackData"]),
    }

lib.set_prototypes(prototypes)
