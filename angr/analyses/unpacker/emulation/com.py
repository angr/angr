from __future__ import annotations

import struct
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from angr.errors import SimSegfaultException

from .apis import ApiHandler, GdiObject, api

if TYPE_CHECKING:
    from .environment import WindowsEmulator

S_OK = 0
S_FALSE = 1
E_NOTIMPL = 0x80004001
E_NOINTERFACE = 0x80004002
E_POINTER = 0x80004003
E_FAIL = 0x80004005
E_OUTOFMEMORY = 0x8007000E
STG_E_INVALIDFUNCTION = 0x80030001
STG_E_MEDIUMFULL = 0x80030070
REGDB_E_CLASSNOTREG = 0x80040154
CO_E_CLASSSTRING = 0x800401F3
CO_S_NOTALLINTERFACES = 0x00080012
CTL_E_INVALIDPICTURE = 0x800A01E1
RPC_S_SERVER_UNAVAILABLE = 0x800706BA

SLOT_SIZE = 16
_ARENA_SIZE = 0x10000
# methods of the object handed out for an interface that is not in the table (x64 only)
_GENERIC_METHODS = 125
_X86_SLOTS = {"p": 1, "q": 2, "V": 4}


@dataclass(frozen=True)
class ComInterface:
    """
    An interface whose methods are known: (name, parameters) in vtable order after IUnknown's three, base interfaces
    included. A parameter is "p" (pointer-sized), "q" (64-bit by value) or "V" (16-byte structure by value); on x86
    they take one, two and four stack slots, which is what a method must pop.
    """

    name: str
    iid: str
    bases: tuple[str, ...]
    methods: tuple[tuple[str, str], ...]


IID_IUNKNOWN = "00000000-0000-0000-c000-000000000046"
_UNKNOWN_METHODS = (("QueryInterface", "pp"), ("AddRef", ""), ("Release", ""))
# generated from the IDL files of wine-mirror/wine 97027f879ba9a36dbe594720d4710818536e5433 (unknwn, objidlbase,
# objidl, ocidl, oaidl, shobjidl, wbemcli, mstask, exdisp)
INTERFACES: tuple[ComInterface, ...] = (
    ComInterface("IUnknown", IID_IUNKNOWN, (), ()),
    ComInterface(
        "IClassFactory",
        "00000001-0000-0000-c000-000000000046",
        (),
        (
            ("CreateInstance", "ppp"),
            ("LockServer", "p"),
        ),
    ),
    ComInterface(
        "IMalloc",
        "00000002-0000-0000-c000-000000000046",
        (),
        (
            ("Alloc", "p"),
            ("Realloc", "pp"),
            ("Free", "p"),
            ("GetSize", "p"),
            ("DidAlloc", "p"),
            ("HeapMinimize", ""),
        ),
    ),
    ComInterface(
        "ISequentialStream",
        "0c733a30-2a1c-11ce-ade5-00aa0044773d",
        (),
        (
            ("Read", "ppp"),
            ("Write", "ppp"),
        ),
    ),
    ComInterface(
        "IStream",
        "0000000c-0000-0000-c000-000000000046",
        ("ISequentialStream",),
        (
            ("Read", "ppp"),
            ("Write", "ppp"),
            ("Seek", "qpp"),
            ("SetSize", "q"),
            ("CopyTo", "pqpp"),
            ("Commit", "p"),
            ("Revert", ""),
            ("LockRegion", "qqp"),
            ("UnlockRegion", "qqp"),
            ("Stat", "pp"),
            ("Clone", "p"),
        ),
    ),
    ComInterface(
        "IPicture",
        "7bf80980-bf32-101a-8bbb-00aa00300cab",
        (),
        (
            ("get_Handle", "p"),
            ("get_hPal", "p"),
            ("get_Type", "p"),
            ("get_Width", "p"),
            ("get_Height", "p"),
            ("Render", "pppppppppp"),
            ("set_hPal", "p"),
            ("get_CurDC", "p"),
            ("SelectPicture", "ppp"),
            ("get_KeepOriginalFormat", "p"),
            ("put_KeepOriginalFormat", "p"),
            ("PictureChanged", ""),
            ("SaveAsFile", "ppp"),
            ("get_Attributes", "p"),
        ),
    ),
    ComInterface(
        "IDispatch",
        "00020400-0000-0000-c000-000000000046",
        (),
        (
            ("GetTypeInfoCount", "p"),
            ("GetTypeInfo", "ppp"),
            ("GetIDsOfNames", "ppppp"),
            ("Invoke", "pppppppp"),
        ),
    ),
    ComInterface("IPersist", "0000010c-0000-0000-c000-000000000046", (), (("GetClassID", "p"),)),
    ComInterface(
        "IPersistFile",
        "0000010b-0000-0000-c000-000000000046",
        ("IPersist",),
        (
            ("GetClassID", "p"),
            ("IsDirty", ""),
            ("Load", "pp"),
            ("Save", "pp"),
            ("SaveCompleted", "p"),
            ("GetCurFile", "p"),
        ),
    ),
    ComInterface(
        "IShellLinkA",
        "000214ee-0000-0000-c000-000000000046",
        (),
        (
            ("GetPath", "pppp"),
            ("GetIDList", "p"),
            ("SetIDList", "p"),
            ("GetDescription", "pp"),
            ("SetDescription", "p"),
            ("GetWorkingDirectory", "pp"),
            ("SetWorkingDirectory", "p"),
            ("GetArguments", "pp"),
            ("SetArguments", "p"),
            ("GetHotkey", "p"),
            ("SetHotkey", "p"),
            ("GetShowCmd", "p"),
            ("SetShowCmd", "p"),
            ("GetIconLocation", "ppp"),
            ("SetIconLocation", "pp"),
            ("SetRelativePath", "pp"),
            ("Resolve", "pp"),
            ("SetPath", "p"),
        ),
    ),
    ComInterface(
        "IShellLinkW",
        "000214f9-0000-0000-c000-000000000046",
        (),
        (
            ("GetPath", "pppp"),
            ("GetIDList", "p"),
            ("SetIDList", "p"),
            ("GetDescription", "pp"),
            ("SetDescription", "p"),
            ("GetWorkingDirectory", "pp"),
            ("SetWorkingDirectory", "p"),
            ("GetArguments", "pp"),
            ("SetArguments", "p"),
            ("GetHotkey", "p"),
            ("SetHotkey", "p"),
            ("GetShowCmd", "p"),
            ("SetShowCmd", "p"),
            ("GetIconLocation", "ppp"),
            ("SetIconLocation", "pp"),
            ("SetRelativePath", "pp"),
            ("Resolve", "pp"),
            ("SetPath", "p"),
        ),
    ),
    ComInterface(
        "IShellFolder",
        "000214e6-0000-0000-c000-000000000046",
        (),
        (
            ("ParseDisplayName", "pppppp"),
            ("EnumObjects", "ppp"),
            ("BindToObject", "pppp"),
            ("BindToStorage", "pppp"),
            ("CompareIDs", "ppp"),
            ("CreateViewObject", "ppp"),
            ("GetAttributesOf", "ppp"),
            ("GetUIObjectOf", "pppppp"),
            ("GetDisplayNameOf", "ppp"),
            ("SetNameOf", "ppppp"),
        ),
    ),
    ComInterface("IWbemLocator", "dc12a687-737f-11cf-884d-00aa004b2e24", (), (("ConnectServer", "pppppppp"),)),
    ComInterface(
        "IWbemServices",
        "9556dc99-828c-11cf-a37e-00aa003240c7",
        (),
        (
            ("OpenNamespace", "ppppp"),
            ("CancelAsyncCall", "p"),
            ("QueryObjectSink", "pp"),
            ("GetObject", "ppppp"),
            ("GetObjectAsync", "pppp"),
            ("PutClass", "pppp"),
            ("PutClassAsync", "pppp"),
            ("DeleteClass", "pppp"),
            ("DeleteClassAsync", "pppp"),
            ("CreateClassEnum", "pppp"),
            ("CreateClassEnumAsync", "pppp"),
            ("PutInstance", "pppp"),
            ("PutInstanceAsync", "pppp"),
            ("DeleteInstance", "pppp"),
            ("DeleteInstanceAsync", "pppp"),
            ("CreateInstanceEnum", "pppp"),
            ("CreateInstanceEnumAsync", "pppp"),
            ("ExecQuery", "ppppp"),
            ("ExecQueryAsync", "ppppp"),
            ("ExecNotificationQuery", "ppppp"),
            ("ExecNotificationQueryAsync", "ppppp"),
            ("ExecMethod", "ppppppp"),
            ("ExecMethodAsync", "pppppp"),
        ),
    ),
    ComInterface(
        "ITaskScheduler",
        "148bd527-a2ab-11ce-b11f-00aa00530503",
        (),
        (
            ("SetTargetComputer", "p"),
            ("GetTargetComputer", "p"),
            ("Enum", "p"),
            ("Activate", "ppp"),
            ("Delete", "p"),
            ("NewWorkItem", "pppp"),
            ("AddWorkItem", "pp"),
            ("IsOfType", "pp"),
        ),
    ),
    ComInterface(
        "IWebBrowser",
        "eab22ac1-30c1-11cf-a7eb-0000c05bae0b",
        ("IDispatch",),
        (
            ("GetTypeInfoCount", "p"),
            ("GetTypeInfo", "ppp"),
            ("GetIDsOfNames", "ppppp"),
            ("Invoke", "pppppppp"),
            ("GoBack", ""),
            ("GoForward", ""),
            ("GoHome", ""),
            ("GoSearch", ""),
            ("Navigate", "ppppp"),
            ("Refresh", ""),
            ("Refresh2", "p"),
            ("Stop", ""),
            ("get_Application", "p"),
            ("get_Parent", "p"),
            ("get_Container", "p"),
            ("get_Document", "p"),
            ("get_TopLevelContainer", "p"),
            ("get_Type", "p"),
            ("get_Left", "p"),
            ("put_Left", "p"),
            ("get_Top", "p"),
            ("put_Top", "p"),
            ("get_Width", "p"),
            ("put_Width", "p"),
            ("get_Height", "p"),
            ("put_Height", "p"),
            ("get_LocationName", "p"),
            ("get_LocationURL", "p"),
            ("get_Busy", "p"),
        ),
    ),
    ComInterface(
        "IWebBrowserApp",
        "0002df05-0000-0000-c000-000000000046",
        ("IWebBrowser", "IDispatch"),
        (
            ("GetTypeInfoCount", "p"),
            ("GetTypeInfo", "ppp"),
            ("GetIDsOfNames", "ppppp"),
            ("Invoke", "pppppppp"),
            ("GoBack", ""),
            ("GoForward", ""),
            ("GoHome", ""),
            ("GoSearch", ""),
            ("Navigate", "ppppp"),
            ("Refresh", ""),
            ("Refresh2", "p"),
            ("Stop", ""),
            ("get_Application", "p"),
            ("get_Parent", "p"),
            ("get_Container", "p"),
            ("get_Document", "p"),
            ("get_TopLevelContainer", "p"),
            ("get_Type", "p"),
            ("get_Left", "p"),
            ("put_Left", "p"),
            ("get_Top", "p"),
            ("put_Top", "p"),
            ("get_Width", "p"),
            ("put_Width", "p"),
            ("get_Height", "p"),
            ("put_Height", "p"),
            ("get_LocationName", "p"),
            ("get_LocationURL", "p"),
            ("get_Busy", "p"),
            ("Quit", ""),
            ("ClientToWindow", "pp"),
            ("PutProperty", "pV"),
            ("GetProperty", "pp"),
            ("get_Name", "p"),
            ("get_HWND", "p"),
            ("get_FullName", "p"),
            ("get_Path", "p"),
            ("get_Visible", "p"),
            ("put_Visible", "p"),
            ("get_StatusBar", "p"),
            ("put_StatusBar", "p"),
            ("get_StatusText", "p"),
            ("put_StatusText", "p"),
            ("get_ToolBar", "p"),
            ("put_ToolBar", "p"),
            ("get_MenuBar", "p"),
            ("put_MenuBar", "p"),
            ("get_FullScreen", "p"),
            ("put_FullScreen", "p"),
        ),
    ),
    ComInterface(
        "IWebBrowser2",
        "d30c1661-cdaf-11d0-8a3e-00c04fc9e26e",
        ("IWebBrowserApp", "IWebBrowser", "IDispatch"),
        (
            ("GetTypeInfoCount", "p"),
            ("GetTypeInfo", "ppp"),
            ("GetIDsOfNames", "ppppp"),
            ("Invoke", "pppppppp"),
            ("GoBack", ""),
            ("GoForward", ""),
            ("GoHome", ""),
            ("GoSearch", ""),
            ("Navigate", "ppppp"),
            ("Refresh", ""),
            ("Refresh2", "p"),
            ("Stop", ""),
            ("get_Application", "p"),
            ("get_Parent", "p"),
            ("get_Container", "p"),
            ("get_Document", "p"),
            ("get_TopLevelContainer", "p"),
            ("get_Type", "p"),
            ("get_Left", "p"),
            ("put_Left", "p"),
            ("get_Top", "p"),
            ("put_Top", "p"),
            ("get_Width", "p"),
            ("put_Width", "p"),
            ("get_Height", "p"),
            ("put_Height", "p"),
            ("get_LocationName", "p"),
            ("get_LocationURL", "p"),
            ("get_Busy", "p"),
            ("Quit", ""),
            ("ClientToWindow", "pp"),
            ("PutProperty", "pV"),
            ("GetProperty", "pp"),
            ("get_Name", "p"),
            ("get_HWND", "p"),
            ("get_FullName", "p"),
            ("get_Path", "p"),
            ("get_Visible", "p"),
            ("put_Visible", "p"),
            ("get_StatusBar", "p"),
            ("put_StatusBar", "p"),
            ("get_StatusText", "p"),
            ("put_StatusText", "p"),
            ("get_ToolBar", "p"),
            ("put_ToolBar", "p"),
            ("get_MenuBar", "p"),
            ("put_MenuBar", "p"),
            ("get_FullScreen", "p"),
            ("put_FullScreen", "p"),
            ("Navigate2", "ppppp"),
            ("QueryStatusWB", "pp"),
            ("ExecWB", "pppp"),
            ("ShowBrowserBar", "ppp"),
            ("get_ReadyState", "p"),
            ("get_Offline", "p"),
            ("put_Offline", "p"),
            ("get_Silent", "p"),
            ("put_Silent", "p"),
            ("get_RegisterAsBrowser", "p"),
            ("put_RegisterAsBrowser", "p"),
            ("get_RegisterAsDropTarget", "p"),
            ("put_RegisterAsDropTarget", "p"),
            ("get_TheaterMode", "p"),
            ("put_TheaterMode", "p"),
            ("get_AddressBar", "p"),
            ("put_AddressBar", "p"),
            ("get_Resizable", "p"),
            ("put_Resizable", "p"),
        ),
    ),
)
INTERFACE_BY_NAME = {interface.name: interface for interface in INTERFACES}
INTERFACE_BY_IID = {interface.iid: interface for interface in INTERFACES}
# classes that can be created, and the interfaces their objects answer QueryInterface for
CLASSES: dict[str, tuple[str, ...]] = {
    "00021401-0000-0000-c000-000000000046": ("IShellLinkA", "IShellLinkW", "IPersistFile"),  # ShellLink
    "4590f811-1d3a-11d0-891f-00aa004b2e24": ("IWbemLocator",),  # WbemLocator
    "148bd52a-a2ab-11ce-b11f-00aa00530503": ("ITaskScheduler",),  # CTaskScheduler
    "0002df01-0000-0000-c000-000000000046": ("IWebBrowser2",),  # InternetExplorer
    "8856f961-340a-11d0-a96b-00c04fd705a2": ("IWebBrowser2",),  # WebBrowser
}


@dataclass
class ComObject:
    """
    A stub COM object. `interfaces` are the ones it implements (None: it answers every QueryInterface, which only
    objects of unknown interfaces on x64 do); `pointers` maps each interface handed out so far to its pointer.
    """

    interfaces: tuple[str, ...] | None
    clsid: str = ""
    refs: int = 1
    pointers: dict[str, int] = field(default_factory=dict)
    # IStream: a block of guest memory
    base: int = 0
    size: int = 0
    capacity: int = 0
    pos: int = 0
    # IPicture
    width: int = 0
    height: int = 0
    bitmap: int = 0

    def implements(self, interface: ComInterface) -> bool:
        if self.interfaces is None or interface.name == "IUnknown":
            return True
        return any(
            name == interface.name or interface.name in INTERFACE_BY_NAME[name].bases for name in self.interfaces
        )


ComFunc = Callable[["WindowsEmulator", ComObject, int, list[int]], int]
_IMPLEMENTATIONS: dict[tuple[str, str], ComFunc] = {}


def method(interface: str, name: str) -> Callable[[ComFunc], ComFunc]:
    def register(func: ComFunc) -> ComFunc:
        _IMPLEMENTATIONS[(interface, name)] = func
        return func

    return register


def _not_implemented(emu: WindowsEmulator, obj: ComObject, this: int, args: list[int]) -> int:  # pylint:disable=unused-argument
    return E_NOTIMPL


@dataclass
class ComSlot:
    """
    A trap address in a vtable: the method's name and its handler, which pops what the method takes.
    """

    name: str
    handler: ApiHandler


class ComRuntime:
    """
    The stub COM objects of one emulated process. An object is a pointer to a vtable whose entries are trap
    addresses; calls through them arrive at WindowsEmulator like API calls.
    """

    def __init__(self, emu: WindowsEmulator):
        self._emu = emu
        self.slots: dict[int, ComSlot] = {}
        self.pointers: dict[int, tuple[ComObject, ComInterface | None]] = {}
        # every object-creating call: (API, class, interface, result)
        self.requests: list[tuple[str, str, str, int]] = []
        self._vtables: dict[str, int] = {}
        self._arena = 0
        self._arena_end = 0
        self._malloc = 0

    def _reserve(self, size: int) -> int:
        emu = self._emu
        if self._arena + size > self._arena_end:
            # outside the heap: not an allocation the program made
            self._arena = emu.space.reserve(_ARENA_SIZE, 0x7FF700000000 if emu.is_64bit else 0x6F000000)
            self._arena_end = self._arena + _ARENA_SIZE
            emu.map(self._arena, _ARENA_SIZE, 5)
        addr = self._arena
        self._arena += (size + 15) & ~15
        return addr

    def _slot(self, name: str, params: str, func: ComFunc) -> int:
        emu = self._emu
        # the object, then the parameters: one each on x64, their stack slots on x86
        nargs = 1 + (len(params) if emu.is_64bit else sum(_X86_SLOTS[kind] for kind in params))

        def call(emu: WindowsEmulator, raw: list[int]) -> int:
            entry = self.pointers.get(raw[0])
            if entry is None:
                return E_POINTER
            args: list[int] = []
            pos = 1
            for kind in params:
                if kind == "q" and not emu.is_64bit:
                    args.append(raw[pos] | (raw[pos + 1] << 32))
                    pos += 2
                else:
                    args.append(raw[pos])
                    pos += 4 if kind == "V" and not emu.is_64bit else 1
            try:
                return func(emu, entry[0], raw[0], args)
            except SimSegfaultException:
                return E_POINTER
            except MemoryError:
                return E_OUTOFMEMORY

        addr = self._reserve(SLOT_SIZE)
        # jmp self: only the trap at the slot start matters
        emu.write(addr, b"\xeb\xfe".ljust(SLOT_SIZE, b"\xcc"))
        self.slots[addr] = ComSlot(name, ApiHandler(call, nargs))
        emu.add_stop_point(addr)
        return addr

    def _vtable(self, interface: ComInterface | None) -> int:
        key = interface.name if interface is not None else ""
        vtable = self._vtables.get(key)
        if vtable is not None:
            return vtable
        if interface is None:
            label = "ComObject"
            methods: tuple[tuple[str, str], ...] = tuple((f"method{idx}", "") for idx in range(3, 3 + _GENERIC_METHODS))
        else:
            label, methods = interface.name, interface.methods
        slots = []
        for name, params in (*_UNKNOWN_METHODS, *methods):
            func = _IMPLEMENTATIONS.get(("IUnknown", name))
            for owner in (label, *(interface.bases if interface is not None else ())):
                func = func or _IMPLEMENTATIONS.get((owner, name))
            slots.append(self._slot(f"{label}::{name}", params, func or _not_implemented))
        emu = self._emu
        vtable = self._reserve(emu.ptr_size * len(slots))
        for idx, slot in enumerate(slots):
            emu.write_ptr(vtable + emu.ptr_size * idx, slot)
        self._vtables[key] = vtable
        return vtable

    def pointer(self, obj: ComObject, interface: ComInterface | None) -> int:
        """
        The object's pointer for an interface it implements (None: the generic x64 object).
        """
        key = interface.name if interface is not None else ""
        for name, addr in obj.pointers.items():
            # a derived interface's vtable starts with its bases; IUnknown is the first pointer handed out
            if name == key or key == "IUnknown" or (name and key in INTERFACE_BY_NAME[name].bases):
                return addr
        addr = self._reserve(self._emu.ptr_size)
        self._emu.write_ptr(addr, self._vtable(interface))
        obj.pointers[key] = addr
        self.pointers[addr] = (obj, interface)
        return addr

    def new(self, interface: str, obj: ComObject | None = None) -> int:
        """
        A new object seen through a table interface.
        """
        return self.pointer(obj or ComObject((interface,)), INTERFACE_BY_NAME[interface])

    def query(self, obj: ComObject, iid: str) -> int:
        """
        QueryInterface: the pointer for an interface, 0 if the object does not implement it.
        """
        if obj.interfaces is None:
            return next(iter(obj.pointers.values()))
        interface = INTERFACE_BY_IID.get(iid)
        if interface is None or not obj.implements(interface):
            return 0
        return self.pointer(obj, interface)

    def create(self, api_name: str, clsid: str, iid: str, obj: ComObject | None = None) -> tuple[int, int]:
        """
        Make an object of a class and return (HRESULT, pointer for the interface). The interface must be one whose
        methods are known, because on x86 a method that pops the wrong number of bytes corrupts the caller's stack;
        on x64 the callee pops nothing, so an unknown interface gets an object whose methods all fail.
        """
        interface = INTERFACE_BY_IID.get(iid)
        if obj is None:
            known = CLASSES.get(clsid)
            if known is not None:
                obj = ComObject(known, clsid)
            elif interface is not None:
                obj = ComObject((interface.name,), clsid)
        if obj is not None and interface is not None and obj.implements(interface):
            result = S_OK, self.pointer(obj, interface)
        elif self._emu.is_64bit:
            result = S_OK, self.pointer(ComObject(None, clsid), None)
        else:
            result = (E_NOINTERFACE if obj is not None else REGDB_E_CLASSNOTREG), 0
        self.requests.append((api_name, clsid, iid, result[0]))
        return result

    def malloc(self) -> int:
        """
        The task allocator's IMalloc.
        """
        if not self._malloc:
            self._malloc = self.new("IMalloc")
        self.pointers[self._malloc][0].refs += 1
        return self._malloc


def read_guid(emu: WindowsEmulator, addr: int) -> str:
    first, second, third, rest = struct.unpack("<IHH8s", emu.read(addr, 16))
    return f"{first:08x}-{second:04x}-{third:04x}-{rest[:2].hex()}-{rest[2:].hex()}"


#
# IUnknown
#


@method("IUnknown", "QueryInterface")
def unknown_query_interface(emu: WindowsEmulator, obj: ComObject, this: int, args: list[int]) -> int:  # pylint:disable=unused-argument
    if not args[1]:
        return E_POINTER
    addr = emu.com.query(obj, read_guid(emu, args[0]))
    emu.write_ptr(args[1], addr)
    if not addr:
        return E_NOINTERFACE
    obj.refs += 1
    return S_OK


@method("IUnknown", "AddRef")
def unknown_add_ref(emu: WindowsEmulator, obj: ComObject, this: int, args: list[int]) -> int:  # pylint:disable=unused-argument
    obj.refs += 1
    return obj.refs


@method("IUnknown", "Release")
def unknown_release(emu: WindowsEmulator, obj: ComObject, this: int, args: list[int]) -> int:  # pylint:disable=unused-argument
    obj.refs = max(obj.refs - 1, 0)
    return obj.refs


#
# Creation
#


def _create_into(emu: WindowsEmulator, api_name: str, clsid: str, iid: str, out: int) -> int:
    if not out:
        return E_POINTER
    result, addr = emu.com.create(api_name, clsid, iid)
    emu.write_ptr(out, addr)
    return result


@api("CoCreateInstance", nargs=5)
def co_create_instance(emu: WindowsEmulator, args: list[int]) -> int:
    return _create_into(emu, "CoCreateInstance", read_guid(emu, args[0]), read_guid(emu, args[3]), args[4])


@api("CoCreateInstanceEx", nargs=6)
def co_create_instance_ex(emu: WindowsEmulator, args: list[int]) -> int:
    clsid = read_guid(emu, args[0])
    # MULTI_QI: pIID, pItf, hr
    size = 3 * emu.ptr_size
    results = []
    for idx in range(min(args[4], 64)):
        entry = args[5] + size * idx
        result = _create_into(
            emu, "CoCreateInstanceEx", clsid, read_guid(emu, emu.read_ptr(entry)), entry + emu.ptr_size
        )
        emu.write_u32(entry + 2 * emu.ptr_size, result)
        results.append(result)
    if results and all(result == S_OK for result in results):
        return S_OK
    return CO_S_NOTALLINTERFACES if S_OK in results else E_NOINTERFACE


@api("CoGetClassObject", nargs=5)
def co_get_class_object(emu: WindowsEmulator, args: list[int]) -> int:
    if not args[4]:
        return E_POINTER
    clsid = read_guid(emu, args[0])
    factory = ComObject(("IClassFactory",), clsid)
    result, addr = emu.com.create("CoGetClassObject", clsid, read_guid(emu, args[3]), factory)
    emu.write_ptr(args[4], addr)
    return result


@method("IClassFactory", "CreateInstance")
def class_factory_create_instance(emu: WindowsEmulator, obj: ComObject, this: int, args: list[int]) -> int:  # pylint:disable=unused-argument
    return _create_into(emu, "IClassFactory::CreateInstance", obj.clsid, read_guid(emu, args[1]), args[2])


@method("IClassFactory", "LockServer")
def class_factory_lock_server(emu: WindowsEmulator, obj: ComObject, this: int, args: list[int]) -> int:  # pylint:disable=unused-argument
    return S_OK


@api("SHGetDesktopFolder", nargs=1)
def sh_get_desktop_folder(emu: WindowsEmulator, args: list[int]) -> int:
    emu.write_ptr(args[0], emu.com.new("IShellFolder"))
    emu.com.requests.append(("SHGetDesktopFolder", "", INTERFACE_BY_NAME["IShellFolder"].iid, S_OK))
    return S_OK


@api("CLSIDFromProgID", "CLSIDFromProgIDEx", nargs=2)
def clsid_from_prog_id(emu: WindowsEmulator, args: list[int]) -> int:
    # no program identifiers are registered
    emu.write(args[1], bytes(16))
    return CO_E_CLASSSTRING


def _succeed(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    return S_OK


api("CoInitialize", "OleInitialize", nargs=1)(_succeed)
api("CoInitializeEx", nargs=2)(_succeed)
api("CoUninitialize", "OleUninitialize", nargs=0)(_succeed)

#
# The task allocator
#


# blocks come from the process heap, as CoTaskMemAlloc's do: a region of their own each would cost 64 KB of
# address space per block


def _task_alloc(emu: WindowsEmulator, size: int) -> int:
    return emu.heap_alloc(size)


def _task_realloc(emu: WindowsEmulator, block: int, size: int) -> int:
    if not block:
        return _task_alloc(emu, size)
    if not size:
        emu.heap_free(block)
        return 0
    return emu.heap_realloc(block, size)


@api("CoTaskMemAlloc", nargs=1)
def co_task_mem_alloc(emu: WindowsEmulator, args: list[int]) -> int:
    return _task_alloc(emu, args[0])


@api("CoTaskMemRealloc", nargs=2)
def co_task_mem_realloc(emu: WindowsEmulator, args: list[int]) -> int:
    return _task_realloc(emu, args[0], args[1])


@api("CoTaskMemFree", nargs=1)
def co_task_mem_free(emu: WindowsEmulator, args: list[int]) -> int:
    emu.heap_free(args[0])
    return 0


@api("CoGetMalloc", nargs=2)
def co_get_malloc(emu: WindowsEmulator, args: list[int]) -> int:
    emu.write_ptr(args[1], emu.com.malloc())
    return S_OK


@api("SHGetMalloc", nargs=1)
def sh_get_malloc(emu: WindowsEmulator, args: list[int]) -> int:
    emu.write_ptr(args[0], emu.com.malloc())
    return S_OK


@method("IMalloc", "Alloc")
def malloc_alloc(emu: WindowsEmulator, obj: ComObject, this: int, args: list[int]) -> int:  # pylint:disable=unused-argument
    return _task_alloc(emu, args[0])


@method("IMalloc", "Realloc")
def malloc_realloc(emu: WindowsEmulator, obj: ComObject, this: int, args: list[int]) -> int:  # pylint:disable=unused-argument
    return _task_realloc(emu, args[0], args[1])


@method("IMalloc", "Free")
def malloc_free(emu: WindowsEmulator, obj: ComObject, this: int, args: list[int]) -> int:  # pylint:disable=unused-argument
    emu.heap_free(args[0])
    return 0


@method("IMalloc", "GetSize")
def malloc_get_size(emu: WindowsEmulator, obj: ComObject, this: int, args: list[int]) -> int:  # pylint:disable=unused-argument
    return emu.allocations.get(args[0], -1)


@method("IMalloc", "DidAlloc")
def malloc_did_alloc(emu: WindowsEmulator, obj: ComObject, this: int, args: list[int]) -> int:  # pylint:disable=unused-argument
    return int(args[0] in emu.allocations)


@method("IMalloc", "HeapMinimize")
def malloc_heap_minimize(emu: WindowsEmulator, obj: ComObject, this: int, args: list[int]) -> int:  # pylint:disable=unused-argument
    return 0


#
# IStream on global memory
#


_MAX_STREAM_SIZE = 1 << 26


def _stream_reserve(emu: WindowsEmulator, obj: ComObject, size: int) -> None:
    if size > _MAX_STREAM_SIZE:
        raise MemoryError("Stream too large")
    if size > obj.capacity:
        capacity = max(size, 2 * obj.capacity, 0x1000)
        base = emu.alloc(capacity)
        emu.write(base, emu.read(obj.base, obj.size))
        obj.base, obj.capacity = base, emu.allocations[base]


@api("CreateStreamOnHGlobal", nargs=3)
def create_stream_on_hglobal(emu: WindowsEmulator, args: list[int]) -> int:
    if not args[2]:
        return E_POINTER
    # a given block is the stream's contents, at its whole size
    size = emu.allocations.get(args[0], 0)
    stream = ComObject(("IStream",), base=args[0] if size else 0, size=size, capacity=size)
    emu.write_ptr(args[2], emu.com.new("IStream", stream))
    emu.com.requests.append(("CreateStreamOnHGlobal", "", INTERFACE_BY_NAME["IStream"].iid, S_OK))
    return S_OK


@api("GetHGlobalFromStream", nargs=2)
def get_hglobal_from_stream(emu: WindowsEmulator, args: list[int]) -> int:
    entry = emu.com.pointers.get(args[0])
    if entry is None or entry[0].interfaces != ("IStream",):
        emu.write_ptr(args[1], 0)
        return E_FAIL
    _stream_reserve(emu, entry[0], 1)
    emu.write_ptr(args[1], entry[0].base)
    return S_OK


@method("ISequentialStream", "Read")
def stream_read(emu: WindowsEmulator, obj: ComObject, this: int, args: list[int]) -> int:  # pylint:disable=unused-argument
    count = max(min(args[1], obj.size - obj.pos), 0)
    emu.write(args[0], emu.read(obj.base + obj.pos, count))
    obj.pos += count
    if args[2]:
        emu.write_u32(args[2], count)
    return S_OK if count == args[1] else S_FALSE


@method("ISequentialStream", "Write")
def stream_write(emu: WindowsEmulator, obj: ComObject, this: int, args: list[int]) -> int:  # pylint:disable=unused-argument
    count = args[1]
    if obj.pos + count > _MAX_STREAM_SIZE:
        return STG_E_MEDIUMFULL
    _stream_reserve(emu, obj, obj.pos + count)
    emu.write(obj.base + obj.pos, emu.read(args[0], count))
    obj.pos += count
    obj.size = max(obj.size, obj.pos)
    if args[2]:
        emu.write_u32(args[2], count)
    return S_OK


@method("IStream", "Seek")
def stream_seek(emu: WindowsEmulator, obj: ComObject, this: int, args: list[int]) -> int:  # pylint:disable=unused-argument
    move = args[0] - (1 << 64) if args[0] >> 63 else args[0]
    if args[1] > 2 or (0, obj.pos, obj.size)[args[1]] + move < 0:
        return STG_E_INVALIDFUNCTION
    obj.pos = (0, obj.pos, obj.size)[args[1]] + move
    if args[2]:
        emu.write(args[2], struct.pack("<Q", obj.pos))
    return S_OK


@method("IStream", "SetSize")
def stream_set_size(emu: WindowsEmulator, obj: ComObject, this: int, args: list[int]) -> int:  # pylint:disable=unused-argument
    size = args[0]
    if size > _MAX_STREAM_SIZE:
        return STG_E_MEDIUMFULL
    _stream_reserve(emu, obj, size)
    if size > obj.size:
        emu.write(obj.base + obj.size, bytes(size - obj.size))
    obj.size = size
    return S_OK


@method("IStream", "Stat")
def stream_stat(emu: WindowsEmulator, obj: ComObject, this: int, args: list[int]) -> int:  # pylint:disable=unused-argument
    # STATSTG: pwcsName, type (STGTY_STREAM), cbSize, three times, grfMode, grfLocksSupported, clsid, two more
    head = struct.pack("<QI4xQ", 0, 2, obj.size) if emu.is_64bit else struct.pack("<IIQ", 0, 2, obj.size)
    emu.write(args[0], head + bytes(56))
    return S_OK


@method("IStream", "Commit")
def stream_commit(emu: WindowsEmulator, obj: ComObject, this: int, args: list[int]) -> int:  # pylint:disable=unused-argument
    return S_OK


@method("IStream", "Revert")
def stream_revert(emu: WindowsEmulator, obj: ComObject, this: int, args: list[int]) -> int:  # pylint:disable=unused-argument
    return S_OK


#
# IPicture from OleLoadPicture
#


def _image_size(data: bytes) -> tuple[int, int]:
    """
    Pixel size of a BMP, JPEG, GIF or PNG image; (0, 0) if it is none of these.
    """
    if data[:2] == b"BM" and len(data) >= 26:
        width, height = struct.unpack_from("<ii", data, 18)
        return width, abs(height)
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return struct.unpack_from("<HH", data, 6)
    if data[:8] == b"\x89PNG\r\n\x1a\n" and len(data) >= 24:
        return struct.unpack_from(">II", data, 16)
    pos = 2 if data[:2] == b"\xff\xd8" else len(data)
    while pos + 9 <= len(data) and data[pos] == 0xFF:
        marker, length = data[pos + 1], struct.unpack_from(">H", data, pos + 2)[0]
        if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            height, width = struct.unpack_from(">HH", data, pos + 5)
            return width, height
        pos += 2 + length
    return 0, 0


def _load_picture(emu: WindowsEmulator, stream_ptr: int, size: int, iid_ptr: int, out: int) -> int:
    if not out:
        return E_POINTER
    emu.write_ptr(out, 0)
    entry = emu.com.pointers.get(stream_ptr)
    if entry is None or entry[0].interfaces != ("IStream",):
        return E_FAIL
    stream = entry[0]
    available = stream.size - stream.pos
    data = emu.read(stream.base + stream.pos, min(size, available) if size > 0 else available)
    width, height = _image_size(data)
    if width <= 0 or height <= 0:
        return CTL_E_INVALIDPICTURE
    picture = ComObject(("IPicture",), width=width, height=height)
    result, addr = emu.com.create("OleLoadPicture", "", read_guid(emu, iid_ptr), picture)
    emu.write_ptr(out, addr)
    return result


@api("OleLoadPicture", nargs=5)
def ole_load_picture(emu: WindowsEmulator, args: list[int]) -> int:
    return _load_picture(emu, args[0], args[1], args[3], args[4])


@api("OleLoadPictureEx", nargs=8)
def ole_load_picture_ex(emu: WindowsEmulator, args: list[int]) -> int:
    return _load_picture(emu, args[0], args[1], args[3], args[7])


def _himetric(pixels: int) -> int:
    return (pixels * 2540 + 48) // 96


@method("IPicture", "get_Handle")
def picture_get_handle(emu: WindowsEmulator, obj: ComObject, this: int, args: list[int]) -> int:  # pylint:disable=unused-argument
    if not obj.bitmap:
        obj.bitmap = emu.new_handle(GdiObject("bitmap"))
    emu.write_u32(args[0], obj.bitmap)
    return S_OK


@method("IPicture", "get_Type")
def picture_get_type(emu: WindowsEmulator, obj: ComObject, this: int, args: list[int]) -> int:  # pylint:disable=unused-argument
    emu.write(args[0], struct.pack("<H", 1))  # PICTYPE_BITMAP
    return S_OK


@method("IPicture", "get_Width")
def picture_get_width(emu: WindowsEmulator, obj: ComObject, this: int, args: list[int]) -> int:  # pylint:disable=unused-argument
    emu.write_u32(args[0], _himetric(obj.width))
    return S_OK


@method("IPicture", "get_Height")
def picture_get_height(emu: WindowsEmulator, obj: ComObject, this: int, args: list[int]) -> int:  # pylint:disable=unused-argument
    emu.write_u32(args[0], _himetric(obj.height))
    return S_OK


@method("IPicture", "get_Attributes")
def picture_get_attributes(emu: WindowsEmulator, obj: ComObject, this: int, args: list[int]) -> int:  # pylint:disable=unused-argument
    emu.write_u32(args[0], 0)
    return S_OK


@method("IPicture", "Render")
def picture_render(emu: WindowsEmulator, obj: ComObject, this: int, args: list[int]) -> int:  # pylint:disable=unused-argument
    return S_OK


#
# WMI: the locator exists, the service cannot be reached
#


@method("IWbemLocator", "ConnectServer")
def wbem_locator_connect_server(emu: WindowsEmulator, obj: ComObject, this: int, args: list[int]) -> int:  # pylint:disable=unused-argument
    if args[7]:
        emu.write_ptr(args[7], 0)
    return RPC_S_SERVER_UNAVAILABLE
