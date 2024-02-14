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
lib.set_library_names("shell32.dll")
prototypes = \
    {
        #
        'FileIconInit': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["fRestoreCache"]),
        #
        'SHSimpleIDListFromPath': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), arg_names=["pszPath"]),
        #
        'SHCreateItemFromIDList': SimTypeFunction([SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pidl", "riid", "ppv"]),
        #
        'SHCreateItemFromParsingName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IBindCtx"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath", "pbc", "riid", "ppv"]),
        #
        'SHCreateItemWithParent': SimTypeFunction([SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypeBottom(label="IShellFolder"), SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pidlParent", "psfParent", "pidl", "riid", "ppvItem"]),
        #
        'SHCreateItemFromRelativeName': SimTypeFunction([SimTypeBottom(label="IShellItem"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IBindCtx"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psiParent", "pszName", "pbc", "riid", "ppv"]),
        #
        'SHCreateItemInKnownFolder': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["kfid", "dwKFFlags", "pszItem", "riid", "ppv"]),
        #
        'SHGetIDListFromObject': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["punk", "ppidl"]),
        #
        'SHGetItemFromObject': SimTypeFunction([SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["punk", "riid", "ppv"]),
        #
        'SHGetNameFromIDList': SimTypeFunction([SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypeInt(signed=False, label="SIGDN"), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pidl", "sigdnName", "ppszName"]),
        #
        'SHGetItemFromDataObject': SimTypeFunction([SimTypeBottom(label="IDataObject"), SimTypeInt(signed=False, label="DATAOBJ_GET_ITEM_FLAGS"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdtobj", "dwFlags", "riid", "ppv"]),
        #
        'SHCreateShellItemArray': SimTypeFunction([SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypeBottom(label="IShellFolder"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeBottom(label="IShellItemArray"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pidlParent", "psf", "cidl", "ppidl", "ppsiItemArray"]),
        #
        'SHCreateShellItemArrayFromDataObject': SimTypeFunction([SimTypeBottom(label="IDataObject"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdo", "riid", "ppv"]),
        #
        'SHCreateShellItemArrayFromIDLists': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeBottom(label="IShellItemArray"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cidl", "rgpidl", "ppsiItemArray"]),
        #
        'SHCreateShellItemArrayFromShellItem': SimTypeFunction([SimTypeBottom(label="IShellItem"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psi", "riid", "ppv"]),
        #
        'SHCreateAssociationRegistration': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["riid", "ppv"]),
        #
        'SHCreateDefaultExtractIcon': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["riid", "ppv"]),
        #
        'SetCurrentProcessExplicitAppUserModelID': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AppID"]),
        #
        'GetCurrentProcessExplicitAppUserModelID': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["AppID"]),
        #
        'SHGetTemporaryPropertyForItem': SimTypeFunction([SimTypeBottom(label="IShellItem"), SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psi", "propkey", "ppropvar"]),
        #
        'SHSetTemporaryPropertyForItem': SimTypeFunction([SimTypeBottom(label="IShellItem"), SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psi", "propkey", "propvar"]),
        #
        'SHShowManageLibraryUI': SimTypeFunction([SimTypeBottom(label="IShellItem"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="LIBRARYMANAGEDIALOGOPTIONS")], SimTypeInt(signed=True, label="Int32"), arg_names=["psiLibrary", "hwndOwner", "pszTitle", "pszInstruction", "lmdOptions"]),
        #
        'SHResolveLibrary': SimTypeFunction([SimTypeBottom(label="IShellItem")], SimTypeInt(signed=True, label="Int32"), arg_names=["psiLibrary"]),
        #
        'SHAssocEnumHandlers': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="ASSOC_FILTER"), SimTypePointer(SimTypeBottom(label="IEnumAssocHandlers"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszExtra", "afFilter", "ppEnumHandler"]),
        #
        'SHAssocEnumHandlersForProtocolByApplication': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["protocol", "riid", "enumHandlers"]),
        #
        'SHCreateDefaultPropertiesOp': SimTypeFunction([SimTypeBottom(label="IShellItem"), SimTypePointer(SimTypeBottom(label="IFileOperation"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psi", "ppFileOp"]),
        #
        'SHSetDefaultProperties': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeBottom(label="IShellItem"), SimTypeInt(signed=False, label="UInt32"), SimTypeBottom(label="IFileOperationProgressSink")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "psi", "dwFileOpFlags", "pfops"]),
        #
        'SHGetMalloc': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMalloc"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppMalloc"]),
        #
        'SHAlloc': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["cb"]),
        #
        'SHFree': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["pv"]),
        #
        'SHGetIconOverlayIndexA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszIconPath", "iIconIndex"]),
        #
        'SHGetIconOverlayIndexW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszIconPath", "iIconIndex"]),
        #
        'ILClone': SimTypeFunction([SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0)], SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), arg_names=["pidl"]),
        #
        'ILCloneFirst': SimTypeFunction([SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0)], SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), arg_names=["pidl"]),
        #
        'ILCombine': SimTypeFunction([SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0)], SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), arg_names=["pidl1", "pidl2"]),
        #
        'ILFree': SimTypeFunction([SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0)], SimTypeBottom(label="Void"), arg_names=["pidl"]),
        #
        'ILGetNext': SimTypeFunction([SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0)], SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), arg_names=["pidl"]),
        #
        'ILGetSize': SimTypeFunction([SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["pidl"]),
        #
        'ILFindChild': SimTypeFunction([SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0)], SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), arg_names=["pidlParent", "pidlChild"]),
        #
        'ILFindLastID': SimTypeFunction([SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0)], SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), arg_names=["pidl"]),
        #
        'ILRemoveLastID': SimTypeFunction([SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pidl"]),
        #
        'ILIsEqual': SimTypeFunction([SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pidl1", "pidl2"]),
        #
        'ILIsParent': SimTypeFunction([SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pidl1", "pidl2", "fImmediate"]),
        #
        'ILSaveToStream': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pstm", "pidl"]),
        #
        'ILLoadFromStreamEx': SimTypeFunction([SimTypeBottom(label="IStream"), SimTypePointer(SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pstm", "pidl"]),
        #
        'ILCreateFromPathA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), arg_names=["pszPath"]),
        #
        'ILCreateFromPathW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), arg_names=["pszPath"]),
        #
        'SHILCreateFromPath': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath", "ppidl", "rgfInOut"]),
        #
        'ILAppendID': SimTypeFunction([SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("SHITEMID", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), arg_names=["pidl", "pmkid", "fAppend"]),
        #
        'SHGetPathFromIDListEx': SimTypeFunction([SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="GPFIDL_FLAGS")], SimTypeInt(signed=True, label="Int32"), arg_names=["pidl", "pszPath", "cchPath", "uOpts"]),
        #
        'SHGetPathFromIDListA': SimTypeFunction([SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pidl", "pszPath"]),
        #
        'SHGetPathFromIDListW': SimTypeFunction([SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pidl", "pszPath"]),
        #
        'SHCreateDirectory': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pszPath"]),
        #
        'SHCreateDirectoryExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pszPath", "psa"]),
        #
        'SHCreateDirectoryExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("SECURITY_ATTRIBUTES", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pszPath", "psa"]),
        #
        'SHOpenFolderAndSelectItems': SimTypeFunction([SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pidlFolder", "cidl", "apidl", "dwFlags"]),
        #
        'SHCreateShellItem': SimTypeFunction([SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypeBottom(label="IShellFolder"), SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="IShellItem"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pidlParent", "psfParent", "pidl", "ppsi"]),
        #
        'SHGetSpecialFolderLocation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "csidl", "ppidl"]),
        #
        'SHCloneSpecialIDList': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), arg_names=["hwnd", "csidl", "fCreate"]),
        #
        'SHGetSpecialFolderPathA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pszPath", "csidl", "fCreate"]),
        #
        'SHGetSpecialFolderPathW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pszPath", "csidl", "fCreate"]),
        #
        'SHFlushSFCache': SimTypeFunction([], SimTypeBottom(label="Void")),
        #
        'SHGetFolderPathA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "csidl", "hToken", "dwFlags", "pszPath"]),
        #
        'SHGetFolderPathW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "csidl", "hToken", "dwFlags", "pszPath"]),
        #
        'SHGetFolderLocation': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "csidl", "hToken", "dwFlags", "ppidl"]),
        #
        'SHSetFolderPathA': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["csidl", "hToken", "dwFlags", "pszPath"]),
        #
        'SHSetFolderPathW': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["csidl", "hToken", "dwFlags", "pszPath"]),
        #
        'SHGetFolderPathAndSubDirA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "csidl", "hToken", "dwFlags", "pszSubDir", "pszPath"]),
        #
        'SHGetFolderPathAndSubDirW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "csidl", "hToken", "dwFlags", "pszSubDir", "pszPath"]),
        #
        'SHGetKnownFolderIDList': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["rfid", "dwFlags", "hToken", "ppidl"]),
        #
        'SHSetKnownFolderPath': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["rfid", "dwFlags", "hToken", "pszPath"]),
        #
        'SHGetKnownFolderPath': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["rfid", "dwFlags", "hToken", "ppszPath"]),
        #
        'SHGetKnownFolderItem': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="KNOWN_FOLDER_FLAG"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["rfid", "flags", "hToken", "riid", "ppv"]),
        #
        'SHGetSetFolderCustomSettings': SimTypeFunction([SimTypePointer(SimTypeRef("SHFOLDERCUSTOMSETTINGS", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pfcs", "pszPath", "dwReadWrite"]),
        #
        'SHBrowseForFolderA': SimTypeFunction([SimTypePointer(SimTypeRef("BROWSEINFOA", SimStruct), offset=0)], SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), arg_names=["lpbi"]),
        #
        'SHBrowseForFolderW': SimTypeFunction([SimTypePointer(SimTypeRef("BROWSEINFOW", SimStruct), offset=0)], SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), arg_names=["lpbi"]),
        #
        'SHLoadInProc': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["rclsid"]),
        #
        'SHGetDesktopFolder': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IShellFolder"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppshf"]),
        #
        'SHChangeNotify': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="SHCNF_FLAGS"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["wEventId", "uFlags", "dwItem1", "dwItem2"]),
        #
        'SHAddToRecentDocs': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["uFlags", "pv"]),
        #
        'SHHandleUpdateImage': SimTypeFunction([SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pidlExtra"]),
        #
        'SHUpdateImageA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["pszHashItem", "iIndex", "uFlags", "iImageIndex"]),
        #
        'SHUpdateImageW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["pszHashItem", "iIndex", "uFlags", "iImageIndex"]),
        #
        'SHChangeNotifyRegister': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="SHCNRF_SOURCE"), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeRef("SHChangeNotifyEntry", SimStruct), offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hwnd", "fSources", "fEvents", "wMsg", "cEntries", "pshcne"]),
        #
        'SHChangeNotifyDeregister': SimTypeFunction([SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["ulID"]),
        #
        'SHChangeNotification_Lock': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), offset=0), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hChange", "dwProcId", "pppidl", "plEvent"]),
        #
        'SHChangeNotification_Unlock': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hLock"]),
        #
        'SHGetRealIDL': SimTypeFunction([SimTypeBottom(label="IShellFolder"), SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psf", "pidlSimple", "ppidlReal"]),
        #
        'SHGetInstanceExplorer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IUnknown"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppunk"]),
        #
        'SHGetDataFromIDListA': SimTypeFunction([SimTypeBottom(label="IShellFolder"), SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypeInt(signed=False, label="SHGDFIL_FORMAT"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["psf", "pidl", "nFormat", "pv", "cb"]),
        #
        'SHGetDataFromIDListW': SimTypeFunction([SimTypeBottom(label="IShellFolder"), SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypeInt(signed=False, label="SHGDFIL_FORMAT"), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["psf", "pidl", "nFormat", "pv", "cb"]),
        #
        'RestartDialog': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pszPrompt", "dwReturn"]),
        #
        'RestartDialogEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pszPrompt", "dwReturn", "dwReasonCode"]),
        #
        'SHCoCreateInstance': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszCLSID", "pclsid", "pUnkOuter", "riid", "ppv"]),
        #
        'SHCreateDataObject': SimTypeFunction([SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), label="LPArray", offset=0), SimTypeBottom(label="IDataObject"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pidlFolder", "cidl", "apidl", "pdtInner", "riid", "ppv"]),
        #
        'CIDLData_CreateFromIDArray': SimTypeFunction([SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeBottom(label="IDataObject"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pidlFolder", "cidl", "apidl", "ppdtobj"]),
        #
        'SHCreateStdEnumFmtEtc': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("FORMATETC", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeBottom(label="IEnumFORMATETC"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["cfmt", "afmt", "ppenumFormatEtc"]),
        #
        'SHDoDragDrop': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeBottom(label="IDataObject"), SimTypeBottom(label="IDropSource"), SimTypeInt(signed=False, label="DROPEFFECT"), SimTypePointer(SimTypeInt(signed=False, label="DROPEFFECT"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pdata", "pdsrc", "dwEffect", "pdwEffect"]),
        #
        'DAD_SetDragImage': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["him", "pptOffset"]),
        #
        'DAD_DragEnterEx': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeRef("POINT", SimStruct)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndTarget", "ptStart"]),
        #
        'DAD_DragEnterEx2': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeRef("POINT", SimStruct), SimTypeBottom(label="IDataObject")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndTarget", "ptStart", "pdtObject"]),
        #
        'DAD_ShowDragImage': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["fShow"]),
        #
        'DAD_DragMove': SimTypeFunction([SimTypeRef("POINT", SimStruct)], SimTypeInt(signed=True, label="Int32"), arg_names=["pt"]),
        #
        'DAD_DragLeave': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'DAD_AutoScroll': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("AUTO_SCROLL_DATA", SimStruct), offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pad", "pptNow"]),
        #
        'ReadCabinetState': SimTypeFunction([SimTypePointer(SimTypeRef("CABINETSTATE", SimStruct), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pcs", "cLength"]),
        #
        'WriteCabinetState': SimTypeFunction([SimTypePointer(SimTypeRef("CABINETSTATE", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcs"]),
        #
        'PathMakeUniqueName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszUniqueName", "cchMax", "pszTemplate", "pszLongPlate", "pszDir"]),
        #
        'PathIsExe': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        #
        'PathCleanupSpec': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszDir", "pszSpec"]),
        #
        'PathResolve': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath", "dirs", "fFlags"]),
        #
        'GetFileNameFromBrowse': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pszFilePath", "cchFilePath", "pszWorkingDir", "pszDefExt", "pszFilters", "pszTitle"]),
        #
        'DriveType': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["iDrive"]),
        #
        'RealDriveType': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["iDrive", "fOKToHitNet"]),
        #
        'IsNetDrive': SimTypeFunction([SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["iDrive"]),
        #
        'Shell_MergeMenus': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="MM_FLAGS")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hmDst", "hmSrc", "uInsert", "uIDAdjust", "uIDAdjustMax", "uFlags"]),
        #
        'SHObjectProperties': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "shopObjectType", "pszObjectName", "pszPropertyPage"]),
        #
        'SHFormatDrive': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="SHFMT_ID"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hwnd", "drive", "fmtID", "options"]),
        #
        'SHDestroyPropSheetExtArray': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["hpsxa"]),
        #
        'SHAddFromPropSheetExtArray': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hpsxa", "lpfnAddPage", "lParam"]),
        #
        'SHReplaceFromPropSheetExtArray': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["param0", "param1"]), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=False, label="UInt32"), arg_names=["hpsxa", "uPageID", "lpfnReplaceWith", "lParam"]),
        #
        'OpenRegStream': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="IStream"), arg_names=["hkey", "pszSubkey", "pszValue", "grfMode"]),
        #
        'SHFindFiles': SimTypeFunction([SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pidlFolder", "pidlSaveFile"]),
        #
        'PathGetShortPath': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypeBottom(label="Void"), arg_names=["pszLongPath"]),
        #
        'PathYetAnotherMakeUniqueName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszUniqueName", "pszPath", "pszShort", "pszFileSpec"]),
        #
        'Win32DeleteFile': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        #
        'SHRestricted': SimTypeFunction([SimTypeInt(signed=False, label="RESTRICTIONS")], SimTypeInt(signed=False, label="UInt32"), arg_names=["rest"]),
        #
        'SignalFileOpen': SimTypeFunction([SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pidl"]),
        #
        'AssocGetDetailsOfPropKey': SimTypeFunction([SimTypeBottom(label="IShellFolder"), SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypePointer(SimTypeRef("PROPERTYKEY", SimStruct), offset=0), SimTypePointer(SimTypeRef("VARIANT", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psf", "pidl", "pkey", "pv", "pfFoundPropKey"]),
        #
        'SHStartNetConnectionDialogW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pszRemoteName", "dwType"]),
        #
        'SHDefExtractIconA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszIconFile", "iIndex", "uFlags", "phiconLarge", "phiconSmall", "nIconSize"]),
        #
        'SHDefExtractIconW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszIconFile", "iIndex", "uFlags", "phiconLarge", "phiconSmall", "nIconSize"]),
        #
        'SHOpenWithDialog': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("OPENASINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndParent", "poainfo"]),
        #
        'Shell_GetImageLists': SimTypeFunction([SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["phiml", "phimlSmall"]),
        #
        'Shell_GetCachedImageIndex': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszIconPath", "iIconIndex", "uIconFlags"]),
        #
        'Shell_GetCachedImageIndexA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszIconPath", "iIconIndex", "uIconFlags"]),
        #
        'Shell_GetCachedImageIndexW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszIconPath", "iIconIndex", "uIconFlags"]),
        #
        'SHValidateUNC': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndOwner", "pszFile", "fConnect"]),
        #
        'SHSetInstanceExplorer': SimTypeFunction([SimTypeBottom(label="IUnknown")], SimTypeBottom(label="Void"), arg_names=["punk"]),
        #
        'IsUserAnAdmin': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'SHShellFolderView_Message': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hwndMain", "uMsg", "lParam"]),
        #
        'SHCreateShellFolderView': SimTypeFunction([SimTypePointer(SimTypeRef("SFV_CREATE", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="IShellView"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcsfv", "ppsv"]),
        #
        'CDefFolderMenu_Create2': SimTypeFunction([SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), label="LPArray", offset=0), SimTypeBottom(label="IShellFolder"), SimTypePointer(SimTypeFunction([SimTypeBottom(label="IShellFolder"), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeBottom(label="IDataObject"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psf", "hwnd", "pdtobj", "uMsg", "wParam", "lParam"]), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0), SimTypePointer(SimTypeBottom(label="IContextMenu"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pidlFolder", "hwnd", "cidl", "apidl", "psf", "pfn", "nKeys", "ahkeys", "ppcm"]),
        #
        'SHCreateDefaultContextMenu': SimTypeFunction([SimTypePointer(SimTypeRef("DEFCONTEXTMENU", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdcm", "riid", "ppv"]),
        #
        'SHFind_InitMenuPopup': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="IContextMenu"), arg_names=["hmenu", "hwndOwner", "idCmdFirst", "idCmdLast"]),
        #
        'SHCreateShellFolderViewEx': SimTypeFunction([SimTypePointer(SimTypeRef("CSFV", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="IShellView"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pcsfv", "ppsv"]),
        #
        'SHGetSetSettings': SimTypeFunction([SimTypePointer(SimTypeRef("SHELLSTATEA", SimStruct), offset=0), SimTypeInt(signed=False, label="SSF_MASK"), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["lpss", "dwMask", "bSet"]),
        #
        'SHGetSettings': SimTypeFunction([SimTypePointer(SimTypeRef("SHELLFLAGSTATE", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeBottom(label="Void"), arg_names=["psfs", "dwMask"]),
        #
        'SHBindToParent': SimTypeFunction([SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pidl", "riid", "ppv", "ppidlLast"]),
        #
        'SHBindToFolderIDListParent': SimTypeFunction([SimTypeBottom(label="IShellFolder"), SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psfRoot", "pidl", "riid", "ppv", "ppidlLast"]),
        #
        'SHBindToFolderIDListParentEx': SimTypeFunction([SimTypeBottom(label="IShellFolder"), SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypeBottom(label="IBindCtx"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psfRoot", "pidl", "ppbc", "riid", "ppv", "ppidlLast"]),
        #
        'SHBindToObject': SimTypeFunction([SimTypeBottom(label="IShellFolder"), SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypeBottom(label="IBindCtx"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psf", "pidl", "pbc", "riid", "ppv"]),
        #
        'SHParseDisplayName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IBindCtx"), SimTypePointer(SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszName", "pbc", "ppidl", "sfgaoIn", "psfgaoOut"]),
        #
        'SHPathPrepareForWriteA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "punkEnableModless", "pszPath", "dwFlags"]),
        #
        'SHPathPrepareForWriteW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeBottom(label="IUnknown"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "punkEnableModless", "pszPath", "dwFlags"]),
        #
        'SHCreateFileExtractIconW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszFile", "dwFileAttributes", "riid", "ppv"]),
        #
        'SHLimitInputEdit': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeBottom(label="IShellFolder")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwndEdit", "psf"]),
        #
        'SHGetAttributesFromDataObject': SimTypeFunction([SimTypeBottom(label="IDataObject"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pdo", "dwAttributeMask", "pdwAttributes", "pcItems"]),
        #
        'SHMapPIDLToSystemImageListIndex': SimTypeFunction([SimTypeBottom(label="IShellFolder"), SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pshf", "pidl", "piIndexSel"]),
        #
        'SHCLSIDFromString': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psz", "pclsid"]),
        #
        'PickIconDlg': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pszIconPath", "cchIconPath", "piIconIndex"]),
        #
        'StgMakeUniqueName': SimTypeFunction([SimTypeBottom(label="IStorage"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pstgParent", "pszFileSpec", "grfMode", "riid", "ppv"]),
        #
        'SHChangeNotifyRegisterThread': SimTypeFunction([SimTypeInt(signed=False, label="SCNRT_STATUS")], SimTypeBottom(label="Void"), arg_names=["status"]),
        #
        'PathQualify': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeBottom(label="Void"), arg_names=["psz"]),
        #
        'PathIsSlowA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszFile", "dwAttr"]),
        #
        'PathIsSlowW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszFile", "dwAttr"]),
        #
        'SHCreatePropSheetExtArray': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hKey", "pszSubKey", "max_iface"]),
        #
        'SHOpenPropSheetW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeBottom(label="IDataObject"), SimTypeBottom(label="IShellBrowser"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszCaption", "ahkeys", "ckeys", "pclsidDefault", "pdtobj", "psb", "pStartPage"]),
        #
        'SHMultiFileProperties': SimTypeFunction([SimTypeBottom(label="IDataObject"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pdtobj", "dwFlags"]),
        #
        'SHCreateQueryCancelAutoPlayMoniker': SimTypeFunction([SimTypePointer(SimTypeBottom(label="IMoniker"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["ppmoniker"]),
        #
        'CommandLineToArgvW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), arg_names=["lpCmdLine", "pNumArgs"]),
        #
        'DragQueryFileA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDrop", "iFile", "lpszFile", "cch"]),
        #
        'DragQueryFileW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["hDrop", "iFile", "lpszFile", "cch"]),
        #
        'DragQueryPoint': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeRef("POINT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hDrop", "ppt"]),
        #
        'DragFinish': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["hDrop"]),
        #
        'DragAcceptFiles': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeBottom(label="Void"), arg_names=["hWnd", "fAccept"]),
        #
        'ShellExecuteA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="SHOW_WINDOW_CMD")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hwnd", "lpOperation", "lpFile", "lpParameters", "lpDirectory", "nShowCmd"]),
        #
        'ShellExecuteW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="SHOW_WINDOW_CMD")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hwnd", "lpOperation", "lpFile", "lpParameters", "lpDirectory", "nShowCmd"]),
        #
        'FindExecutableA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpFile", "lpDirectory", "lpResult"]),
        #
        'FindExecutableW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["lpFile", "lpDirectory", "lpResult"]),
        #
        'ShellAboutA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "szApp", "szOtherStuff", "hIcon"]),
        #
        'ShellAboutW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hWnd", "szApp", "szOtherStuff", "hIcon"]),
        #
        'DuplicateIcon': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hInst", "hIcon"]),
        #
        'ExtractAssociatedIconA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hInst", "pszIconPath", "piIcon"]),
        #
        'ExtractAssociatedIconW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hInst", "pszIconPath", "piIcon"]),
        #
        'ExtractAssociatedIconExA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hInst", "pszIconPath", "piIconIndex", "piIconId"]),
        #
        'ExtractAssociatedIconExW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0), SimTypePointer(SimTypeShort(signed=False, label="UInt16"), offset=0)], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hInst", "pszIconPath", "piIconIndex", "piIconId"]),
        #
        'ExtractIconA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hInst", "pszExeFileName", "nIconIndex"]),
        #
        'ExtractIconW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hInst", "pszExeFileName", "nIconIndex"]),
        #
        'SHAppBarMessage': SimTypeFunction([SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("APPBARDATA", SimStruct), offset=0)], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["dwMessage", "pData"]),
        #
        'DoEnvironmentSubstA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pszSrc", "cchSrc"]),
        #
        'DoEnvironmentSubstW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["pszSrc", "cchSrc"]),
        #
        'ExtractIconExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpszFile", "nIconIndex", "phiconLarge", "phiconSmall", "nIcons"]),
        #
        'ExtractIconExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=False, label="UInt32"), arg_names=["lpszFile", "nIconIndex", "phiconLarge", "phiconSmall", "nIcons"]),
        #
        'SHFileOperationA': SimTypeFunction([SimTypePointer(SimTypeRef("SHFILEOPSTRUCTA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileOp"]),
        #
        'SHFileOperationW': SimTypeFunction([SimTypePointer(SimTypeRef("SHFILEOPSTRUCTW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["lpFileOp"]),
        #
        'SHFreeNameMappings': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["hNameMappings"]),
        #
        'ShellExecuteExA': SimTypeFunction([SimTypePointer(SimTypeRef("SHELLEXECUTEINFOA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pExecInfo"]),
        #
        'ShellExecuteExW': SimTypeFunction([SimTypePointer(SimTypeRef("SHELLEXECUTEINFOW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pExecInfo"]),
        #
        'SHCreateProcessAsUserW': SimTypeFunction([SimTypePointer(SimTypeRef("SHCREATEPROCESSINFOW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pscpi"]),
        #
        'SHEvaluateSystemCommandTemplate': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0), SimTypePointer(SimTypePointer(SimTypeChar(label="Char"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszCmdTemplate", "ppszApplication", "ppszCommandLine", "ppszParameters"]),
        #
        'AssocCreateForClasses': SimTypeFunction([SimTypePointer(SimTypeRef("ASSOCIATIONELEMENT", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["rgClasses", "cClasses", "riid", "ppv"]),
        #
        'SHQueryRecycleBinA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeRef("SHQUERYRBINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszRootPath", "pSHQueryRBInfo"]),
        #
        'SHQueryRecycleBinW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeRef("SHQUERYRBINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszRootPath", "pSHQueryRBInfo"]),
        #
        'SHEmptyRecycleBinA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pszRootPath", "dwFlags"]),
        #
        'SHEmptyRecycleBinW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "pszRootPath", "dwFlags"]),
        #
        'SHQueryUserNotificationState': SimTypeFunction([SimTypePointer(SimTypeInt(signed=False, label="QUERY_USER_NOTIFICATION_STATE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pquns"]),
        #
        'Shell_NotifyIconA': SimTypeFunction([SimTypeInt(signed=False, label="NOTIFY_ICON_MESSAGE"), SimTypePointer(SimTypeRef("NOTIFYICONDATAA", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwMessage", "lpData"]),
        #
        'Shell_NotifyIconW': SimTypeFunction([SimTypeInt(signed=False, label="NOTIFY_ICON_MESSAGE"), SimTypePointer(SimTypeRef("NOTIFYICONDATAW", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dwMessage", "lpData"]),
        #
        'Shell_NotifyIconGetRect': SimTypeFunction([SimTypePointer(SimTypeRef("NOTIFYICONIDENTIFIER", SimStruct), offset=0), SimTypePointer(SimTypeRef("RECT", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["identifier", "iconLocation"]),
        #
        'SHGetFileInfoA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=False, label="FILE_FLAGS_AND_ATTRIBUTES"), SimTypePointer(SimTypeRef("SHFILEINFOA", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="SHGFI_FLAGS")], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["pszPath", "dwFileAttributes", "psfi", "cbFileInfo", "uFlags"]),
        #
        'SHGetFileInfoW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="FILE_FLAGS_AND_ATTRIBUTES"), SimTypePointer(SimTypeRef("SHFILEINFOW", SimStruct), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="SHGFI_FLAGS")], SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0), arg_names=["pszPath", "dwFileAttributes", "psfi", "cbFileInfo", "uFlags"]),
        #
        'SHGetStockIconInfo': SimTypeFunction([SimTypeInt(signed=False, label="SHSTOCKICONID"), SimTypeInt(signed=False, label="SHGSI_FLAGS"), SimTypePointer(SimTypeRef("SHSTOCKICONINFO", SimStruct), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["siid", "uFlags", "psii"]),
        #
        'SHGetDiskFreeSpaceExA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszDirectoryName", "pulFreeBytesAvailableToCaller", "pulTotalNumberOfBytes", "pulTotalNumberOfFreeBytes"]),
        #
        'SHGetDiskFreeSpaceExW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0), SimTypePointer(SimTypeLongLong(signed=False, label="UInt64"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszDirectoryName", "pulFreeBytesAvailableToCaller", "pulTotalNumberOfBytes", "pulTotalNumberOfFreeBytes"]),
        #
        'SHGetNewLinkInfoA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszLinkTo", "pszDir", "pszName", "pfMustCopy", "uFlags"]),
        #
        'SHGetNewLinkInfoW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszLinkTo", "pszDir", "pszName", "pfMustCopy", "uFlags"]),
        #
        'SHInvokePrinterCommandA': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "uAction", "lpBuf1", "lpBuf2", "fModal"]),
        #
        'SHInvokePrinterCommandW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "uAction", "lpBuf1", "lpBuf2", "fModal"]),
        #
        'SHLoadNonloadedIconOverlayIdentifiers': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'SHIsFileAvailableOffline': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pwszPath", "pdwStatus"]),
        #
        'SHSetLocalizedName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath", "pszResModule", "idsRes"]),
        #
        'SHRemoveLocalizedName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        #
        'SHGetLocalizedName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeInt(signed=True, label="Int32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath", "pszResModule", "cch", "pidsRes"]),
        #
        'IsLFNDriveA': SimTypeFunction([SimTypePointer(SimTypeChar(label="Byte"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        #
        'IsLFNDriveW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath"]),
        #
        'SHEnumerateUnreadMailAccountsW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hKeyUser", "dwIndex", "pszMailAddress", "cchMailAddress"]),
        #
        'SHGetUnreadMailCountW': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypePointer(SimTypeRef("FILETIME", SimStruct), offset=0), SimTypePointer(SimTypeChar(label="Char"), label="LPArray", offset=0), SimTypeInt(signed=True, label="Int32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hKeyUser", "pszMailAddress", "pdwCount", "pFileTime", "pszShellExecuteCommand", "cchShellExecuteCommand"]),
        #
        'SHSetUnreadMailCountW': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszMailAddress", "dwCount", "pszShellExecuteCommand"]),
        #
        'SHTestTokenMembership': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hToken", "ulRID"]),
        #
        'SHGetImageList': SimTypeFunction([SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["iImageList", "riid", "ppvObj"]),
        #
        'InitNetworkAddressControl': SimTypeFunction([], SimTypeInt(signed=True, label="Int32")),
        #
        'SHGetDriveMedia': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszDrive", "pdwMediaContent"]),
        #
        'SHGetPropertyStoreFromIDList': SimTypeFunction([SimTypePointer(SimTypeRef("ITEMIDLIST", SimStruct), offset=0), SimTypeInt(signed=False, label="GETPROPERTYSTOREFLAGS"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pidl", "flags", "riid", "ppv"]),
        #
        'SHGetPropertyStoreFromParsingName': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IBindCtx"), SimTypeInt(signed=False, label="GETPROPERTYSTOREFLAGS"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pszPath", "pbc", "flags", "riid", "ppv"]),
        #
        'SHAddDefaultPropertiesByExt': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeBottom(label="IPropertyStore")], SimTypeInt(signed=True, label="Int32"), arg_names=["pszExt", "pPropStore"]),
        #
        'PifMgr_OpenProperties': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["pszApp", "pszPIF", "hInf", "flOpt"]),
        #
        'PifMgr_GetProperties': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hProps", "pszGroup", "lpProps", "cbProps", "flOpt"]),
        #
        'PifMgr_SetProperties': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Byte"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["hProps", "pszGroup", "lpProps", "cbProps", "flOpt"]),
        #
        'PifMgr_CloseProperties': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), arg_names=["hProps", "flOpt"]),
        #
        'SHPropStgCreate': SimTypeFunction([SimTypeBottom(label="IPropertySetStorage"), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeBottom(label="IPropertyStorage"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["psstg", "fmtid", "pclsid", "grfFlags", "grfMode", "dwDisposition", "ppstg", "puCodePage"]),
        #
        'SHPropStgReadMultiple': SimTypeFunction([SimTypeBottom(label="IPropertyStorage"), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PROPSPEC", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), label="LPArray", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["pps", "uCodePage", "cpspec", "rgpspec", "rgvar"]),
        #
        'SHPropStgWriteMultiple': SimTypeFunction([SimTypeBottom(label="IPropertyStorage"), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimTypeRef("PROPSPEC", SimStruct), label="LPArray", offset=0), SimTypePointer(SimTypeRef("PROPVARIANT", SimStruct), label="LPArray", offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["pps", "puCodePage", "cpspec", "rgpspec", "rgvar", "propidNameFirst"]),
        #
        'SHGetPropertyStoreForWindow': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypePointer(SimTypeBottom(label="Void"), offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["hwnd", "riid", "ppv"]),
    }

lib.set_prototypes(prototypes)
