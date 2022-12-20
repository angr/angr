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
lib.set_library_names("msimg32.dll")
prototypes = \
    {
        #
        'AlphaBlend': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimStruct({"BlendOp": SimTypeChar(label="Byte"), "BlendFlags": SimTypeChar(label="Byte"), "SourceConstantAlpha": SimTypeChar(label="Byte"), "AlphaFormat": SimTypeChar(label="Byte")}, name="BLENDFUNCTION", pack=False, align=None)], SimTypeInt(signed=True, label="Int32"), arg_names=["hdcDest", "xoriginDest", "yoriginDest", "wDest", "hDest", "hdcSrc", "xoriginSrc", "yoriginSrc", "wSrc", "hSrc", "ftn"]),
        #
        'TransparentBlt': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdcDest", "xoriginDest", "yoriginDest", "wDest", "hDest", "hdcSrc", "xoriginSrc", "yoriginSrc", "wSrc", "hSrc", "crTransparent"]),
        #
        'GradientFill': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"x": SimTypeInt(signed=True, label="Int32"), "y": SimTypeInt(signed=True, label="Int32"), "Red": SimTypeShort(signed=False, label="UInt16"), "Green": SimTypeShort(signed=False, label="UInt16"), "Blue": SimTypeShort(signed=False, label="UInt16"), "Alpha": SimTypeShort(signed=False, label="UInt16")}, name="TRIVERTEX", pack=False, align=None), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="GRADIENT_FILL")], SimTypeInt(signed=True, label="Int32"), arg_names=["hdc", "pVertex", "nVertex", "pMesh", "nMesh", "ulMode"]),
    }

lib.set_prototypes(prototypes)
