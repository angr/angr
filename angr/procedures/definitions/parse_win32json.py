# Based on https://github.com/dfraze/binja_winmd/blob/main/main.py. Thank you, Dustin Fraze!

from typing import Set
import json
import codecs
import sys
import logging
from collections import OrderedDict, defaultdict
from argparse import ArgumentParser
from pathlib import Path

import angr
from angr.sim_type import SimTypeFunction, SimTypeLong
from angr.utils.library import parsedcprotos2py
from angr.procedures.definitions import SimTypeCollection
from angr.errors import AngrMissingTypeError


api_namespaces = {}
altnames = set()


typelib = SimTypeCollection()
typelib.names = ["win32"]
known_struct_names: set[str] = set()


def is_anonymous_struct(s_name: str) -> bool:
    return "anonymous" in s_name.lower()


def get_angr_type_from_name(name):
    if name == "Byte":
        return angr.types.SimTypeChar(signed=False, label="Byte")
    elif name == "SByte":
        return angr.types.SimTypeChar(signed=True, label="SByte")
    elif name == "Char":
        return angr.types.SimTypeChar(signed=True, label="Char")
    elif name == "UInt16":
        return angr.types.SimTypeShort(signed=False, label="UInt16")
    elif name == "Int16":
        return angr.types.SimTypeShort(signed=True, label="Int16")
    elif name == "Int64":
        return angr.types.SimTypeLongLong(signed=True, label="Int64")
    elif name == "UInt32":
        return angr.types.SimTypeInt(signed=False, label="UInt32")
    elif name == "UInt64":
        return angr.types.SimTypeLongLong(signed=False, label="UInt64")
    elif name == "Int32":
        return angr.types.SimTypeInt(signed=True, label="Int32")
    elif name == "Single":
        return angr.types.SimTypeFloat(size=32)
    elif name == "Double":
        return angr.types.SimTypeFloat(size=64)
    elif name == "UIntPtr":
        return angr.types.SimTypePointer(angr.types.SimTypeInt(signed=False, label="UInt"), label="UIntPtr")
    elif name == "IntPtr":
        return angr.types.SimTypePointer(angr.types.SimTypeInt(signed=True, label="Int"), label="IntPtr")
    elif name == "Void":
        return angr.types.SimTypeBottom(label="Void")
    elif name == "Boolean":
        return angr.types.SimTypeBool(label="Boolean")
    elif name == "Guid":
        # FIXME
        return angr.types.SimTypeBottom(label="Guid")
    else:
        print(f"Unhandled Native Type: {name}")
        sys.exit(-1)


def get_typeref_from_struct_type(t: angr.types.SimType) -> angr.types.SimType:
    if isinstance(t, angr.types.SimStruct):
        if t.name and not is_anonymous_struct(t.name):
            # replace it with a SimTypeRef to avoid duplicate definition
            t = angr.types.SimTypeRef(t.name, angr.types.SimStruct)
    return t


def handle_json_type(t, create_missing: bool = False):
    if t["Kind"] == "Native":
        return get_angr_type_from_name(t["Name"])
    if t["Kind"] == "PointerTo":
        pts_to = get_typeref_from_struct_type(handle_json_type(t["Child"], create_missing=create_missing))
        return angr.types.SimTypePointer(pts_to)
    if t["Kind"] == "Array":
        elem = get_typeref_from_struct_type(handle_json_type(t["Child"], create_missing=create_missing))
        if t["Shape"]:
            return angr.types.SimTypeFixedSizeArray(elem, length=int(t["Shape"]["Size"]))
        else:
            return angr.types.SimTypePointer(elem)
    if t["Kind"] == "ApiRef":
        try:
            named_type = typelib.get(t["Name"], bottom_on_missing=create_missing)
        except AngrMissingTypeError:
            if t["Name"] in known_struct_names:
                return angr.types.SimTypeRef(t["Name"], angr.types.SimStruct)
            raise
        return get_typeref_from_struct_type(named_type)
    if t["Kind"] == "Struct":
        for nested_type in t["NestedTypes"]:
            typelib.add(nested_type["Name"], handle_json_type(nested_type, create_missing=create_missing))
        fields = OrderedDict()
        for field in t["Fields"]:
            child_type = get_typeref_from_struct_type(handle_json_type(field["Type"], create_missing=create_missing))
            fields[field["Name"]] = child_type
        return angr.types.SimStruct(fields, name=t["Name"])
    if t["Kind"] == "LPArray":
        pts_to = get_typeref_from_struct_type(handle_json_type(t["Child"], create_missing=create_missing))
        return angr.types.SimTypePointer(pts_to, label="LPArray")
    if t["Kind"] == "Union":
        for nested_type in t["NestedTypes"]:
            typelib.add(nested_type["Name"], handle_json_type(nested_type, create_missing=create_missing))
        members = {}
        for field in t["Fields"]:
            child_type = get_typeref_from_struct_type(handle_json_type(field["Type"], create_missing=create_missing))
            members[field["Name"]] = child_type
        return angr.types.SimUnion(members)
    if t["Kind"] == "MissingClrType":
        return angr.types.SimTypeBottom(label="MissingClrType")
    else:
        print(f"Unhandled type: {t}")
        sys.exit(0)


def create_angr_type_from_json(t):
    if t["Kind"] == "NativeTypedef":
        new_typedef = handle_json_type(t["Def"])
        typelib.add(t["Name"], new_typedef)
    elif t["Kind"] == "Enum":
        # TODO: Handle Enums
        ty = angr.types.SimTypeInt(signed=False, label=t["Name"])
        typelib.add(t["Name"], ty)
    elif t["Kind"] == "Struct":
        known_struct_names.add(t["Name"])
        real_new_type = handle_json_type(t)
        typelib.add(t["Name"], real_new_type)
    elif t["Kind"] == "FunctionPointer":
        ret_type = handle_json_type(t["ReturnType"])
        args = []
        arg_names = []
        for param in t["Params"]:
            new_param = handle_json_type(param["Type"])
            args.append(new_param)
            arg_names.append(param["Name"])
        typelib.add(
            t["Name"], angr.types.SimTypePointer(angr.types.SimTypeFunction(args, ret_type, arg_names=arg_names))
        )
    elif t["Kind"] == "Com":
        # TODO: Handle Com
        typelib.add(t["Name"], angr.types.SimTypeBottom(label=t["Name"]))
    elif t["Kind"] == "ComClassID":
        return None
    elif t["Kind"] == "Union":
        real_new_type = handle_json_type(t)
        typelib.add(t["Name"], real_new_type)
        return None
    else:
        print(f"Found unknown type kind: {t['Kind']}")


def do_it(in_dir, out_file):
    p = Path(in_dir)

    files = p.glob("*.json")

    for file in files:
        logging.info("Found file %s", file)
        api_namespaces[file.stem] = json.load(codecs.open(file, "r", "utf-8-sig"))

    logging.info("Making a bunch of types...")
    missing_types_last_round = set()
    while True:
        nosuchtype = 0
        missing_types = set()
        for namespace in api_namespaces:
            metadata = api_namespaces[namespace]
            types = metadata["Types"]
            for t in types:
                try:
                    create_angr_type_from_json(t)
                except AngrMissingTypeError:
                    # skip this type for now
                    nosuchtype += 1
                    missing_types.add(t["Name"])
        logging.info("... missing %d types", nosuchtype)
        if nosuchtype == 0 or missing_types == missing_types_last_round:
            break
        missing_types_last_round = missing_types

    if missing_types_last_round:
        logging.info("Missing types: %s", missing_types_last_round)
    else:
        logging.info("All referenced types have been created")
    logging.info("Alright, now let's do some functions")

    i = 1
    func_count = 0
    parsed_cprotos = defaultdict(list)
    for namespace in api_namespaces:
        metadata = api_namespaces[namespace]
        logging.debug(f"+++ Processing namespace {namespace} ({i} of {len(api_namespaces)})")
        i += 1
        funcs = metadata["Functions"]
        if namespace.startswith("Windows.Win32"):
            prefix = "win32"
        elif namespace.startswith("Windows.Wdk"):
            prefix = "wdk"
        else:
            raise NotImplementedError(f"Unsupported namespace {namespace}")
        for f in funcs:
            libname = f["DllImport"].lower()
            suffix = ""
            if libname.endswith(".dll") or libname.endswith(".exe") or libname.endswith(".sys"):
                suffix = libname[-3:]
                libname = libname[:-4]
            # special case: put all wdk_ntdll.dll APIs under ntoskrnl.exe to avoid conflict with user-space ntdll.dll
            if prefix == "wdk" and libname == "ntdll" and suffix == "dll":
                libname = "ntoskrnl"
                suffix = "exe"
            ret_type = handle_json_type(f["ReturnType"], create_missing=True)
            args = []
            arg_names = []
            for param in f["Params"]:
                new_param = handle_json_type(param["Type"], create_missing=True)
                assert new_param is not None, "This should not happen, please report this."
                args.append(new_param)
                arg_names.append(param["Name"])
            new_func = angr.types.SimTypeFunction(args, ret_type, arg_names=arg_names)
            new_func_name = f["Name"]
            parsed_cprotos[(prefix, libname, suffix)].append((new_func_name, new_func, ""))
            func_count += 1

    # Some missing function declarations
    missing_declarations = defaultdict(dict)

    missing_declarations[("win32", "kernel32", "dll")] = {
        "InterlockedCompareExchange": SimTypeFunction((SimTypeLong(),) * 3, SimTypeLong()),
        "InterlockedCompareExchange64": SimTypeFunction((SimTypeLong(),) * 5, SimTypeLong()),
        "InterlockedDecrement": SimTypeFunction((SimTypeLong(),) * 1, SimTypeLong()),
        "InterlockedExchange": SimTypeFunction((SimTypeLong(),) * 2, SimTypeLong()),
        "InterlockedExchangeAdd": SimTypeFunction((SimTypeLong(),) * 2, SimTypeLong()),
        "InterlockedIncrement": SimTypeFunction((SimTypeLong(),) * 1, SimTypeLong()),
        "UTRegister": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "RegisterConsoleVDM": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "RegOpenUserClassesRoot": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "SortCloseHandle": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "WriteConsoleInputVDMW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "RegEnumValueW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "BaseDllReadWriteIniFile": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "NlsCheckPolicy": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "RegGetKeySecurity": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "lstrlen": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "NlsGetCacheUpdateCount": SimTypeFunction([], SimTypeLong(signed=True)),
        "OpenThreadToken": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "SetTermsrvAppInstallMode": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "GetConsoleFontInfo": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "GetCalendarMonthsInYear": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "WerpNotifyLoadStringResourceEx": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "RemoveLocalAlternateComputerNameW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SetVDMCurrentDirectories": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SetConsoleInputExeNameA": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "RegDisablePredefinedCacheEx": SimTypeFunction([], SimTypeLong(signed=True)),
        "IdnToAscii": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "LoadAppInitDlls": SimTypeFunction([], SimTypeLong(signed=True)),
        "OpenConsoleW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "ExitVDM": SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "RegNotifyChangeKeyValue": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "AddLocalAlternateComputerNameW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "RegOpenKeyExA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "RtlMoveMemory": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "RegFlushKey": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "RegUnLoadKeyA": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "RegisterConsoleIME": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "RegLoadMUIStringA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "RegCreateKeyExW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "CheckForReadOnlyResource": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "RegRestoreKeyW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "lstrcpy": SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "RegEnumKeyExW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "CreateProcessAsUserW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "RtlZeroMemory": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "GetConsoleNlsMode": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "RegGetValueA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "AdjustCalendarDate": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "BaseSetLastNTError": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "ShowConsoleCursor": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "BasepCheckWinSaferRestrictions": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "ReadConsoleInputExA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "RegSetValueExW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "RegQueryValueExW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "RegDeleteValueA": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "RegOpenCurrentUser": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "CtrlRoutine": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "RtlFillMemory": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "VerifyConsoleIoHandle": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "EnumerateLocalComputerNamesW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "CloseProfileUserMapping": SimTypeFunction([], SimTypeLong(signed=True)),
        "GetEraNameCountedString": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "RegisterWaitForSingleObjectEx": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "DosPathToSessionPathW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "RegSaveKeyExA": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "CreateProcessInternalW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "OpenProfileUserMapping": SimTypeFunction([], SimTypeLong(signed=True)),
        "GetConsoleHardwareState": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SetConsoleNlsMode": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "AddLocalAlternateComputerNameA": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "BasepCheckBadapp": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "GetConsoleKeyboardLayoutNameA": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "lstrcmpi": SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "BaseFormatObjectAttributes": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "LZCloseFile": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "GetNamedPipeAttribute": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "BasepMapModuleHandle": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SetNamedPipeAttribute": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "RegCreateKeyExA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "SetConsoleOS2OemFormat": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "TermsrvAppInstallMode": SimTypeFunction([], SimTypeLong(signed=True)),
        "RemoveLocalAlternateComputerNameA": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "LZCreateFileW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "NlsUpdateLocale": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "RegisterWowBaseHandlers": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "SetClientTimeZoneInformation": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "BaseCheckRunApp": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "BaseThreadInitThunk": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "UpdateCalendarDayOfWeek": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "SetConsoleMaximumWindowSize": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "ConvertNLSDayOfWeekToWin32DayOfWeek": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "ConvertCalDateTimeToSystemTime": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "RegDeleteKeyExW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "ReplaceFile": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "GetConsoleCharType": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "GetConsoleInputWaitHandle": SimTypeFunction([], SimTypeLong(signed=True)),
        "RestoreLastError": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "CompareCalendarDates": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "RegLoadKeyA": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SetLocalPrimaryComputerNameW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "UnregisterConsoleIME": SimTypeFunction([], SimTypeLong(signed=True)),
        "lstrcat": SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "BaseInitAppcompatCacheSupport": SimTypeFunction([], SimTypeLong(signed=True)),
        "InterlockedPushListSList": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "GetEnvironmentStringsA": SimTypeFunction([], SimTypeLong(signed=True)),
        "CreateSocketHandle": SimTypeFunction([], SimTypeLong(signed=True)),
        "RegSetKeySecurity": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SetThreadToken": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "RegQueryInfoKeyW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "GetNumberOfConsoleFonts": SimTypeFunction([], SimTypeLong(signed=True)),
        "GetCalendarSupportedDateRange": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "RegOpenKeyExW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "RegKrnGetGlobalState": SimTypeFunction([], SimTypeLong(signed=True)),
        "WerpNotifyUseStringResource": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "SetConsoleFont": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "BaseGetNamedObjectDirectory": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "IsCalendarLeapMonth": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "RegDeleteTreeW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "IsValidCalDateTime": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "RegQueryValueExA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "SetConsoleCursor": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "RegDeleteTreeA": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SortGetHandle": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "WerpInitiateRemoteRecovery": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "VDMOperationStarted": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "OpenProcessToken": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "VDMConsoleOperation": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "BaseVerifyUnicodeString": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "RegUnLoadKeyW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "GetProcessUserModeExceptionPolicy": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "GetNextVDMCommand": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "LoadStringBaseW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "DuplicateConsoleHandle": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "BaseCheckAppcompatCache": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "WerpStringLookup": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "BaseDumpAppcompatCache": SimTypeFunction([], SimTypeLong(signed=True)),
        "CreateProcessInternalA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "NlsEventDataDescCreate": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "RegRestoreKeyA": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "NlsWriteEtwEvent": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "RegCloseKey": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "NotifyMountMgr": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "IsCalendarLeapYear": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "DosPathToSessionPathA": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "BasepAnsiStringToDynamicUnicodeString": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SetLocalPrimaryComputerNameA": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "lstrcpyn": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SetConsoleLocalEUDC": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "PrivCopyFileExW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "SetConsoleCursorMode": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "RegisterConsoleOS2": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "SetConsoleIcon": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "RegDeleteValueW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SetConsoleInputExeNameW": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "SetConsoleHardwareState": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "GetConsoleCursorMode": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "ReadConsoleInputExW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "WerpNotifyLoadStringResource": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "BaseCheckAppcompatCacheEx": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "PrivMoveFileIdentityW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "CmdBatNotification": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "BaseFormatTimeOut": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "InvalidateConsoleDIBits": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "RegSaveKeyExW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "IsCalendarLeapDay": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "BaseCleanupAppcompatCacheSupport": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "BasepAllocateActivationContextActivationBlock": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "DelayLoadFailureHook": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "WriteConsoleInputVDMA": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "RegLoadKeyW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "lstrcmp": SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "ConsoleMenuControl": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "BaseQueryModuleData": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "RegDeleteKeyExA": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "RegLoadMUIStringW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "SetHandleContext": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "IdnToUnicode": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "RegKrnInitialize": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "BaseFlushAppcompatCache": SimTypeFunction([], SimTypeLong(signed=True)),
        "GetCalendarWeekNumber": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "NlsUpdateSystemLocale": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "GetComPlusPackageInstallStatus": SimTypeFunction([], SimTypeLong(signed=True)),
        "BaseIsAppcompatInfrastructureDisabled": SimTypeFunction([], SimTypeLong(signed=True)),
        "WerpCleanupMessageMapping": SimTypeFunction([], SimTypeLong(signed=True)),
        "RegisterWowExec": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "BasepCheckAppCompat": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "SetConsoleMenuClose": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "GetCalendarDifferenceInDays": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "LoadStringBaseExW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "GetConsoleInputExeNameA": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SetConsolePalette": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "GetCalendarDaysInMonth": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "BaseGenerateAppCompatData": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "SetLastConsoleEventActive": SimTypeFunction([], SimTypeLong(signed=True)),
        "GetConsoleInputExeNameW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "RegGetValueW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "GetHandleContext": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "SetConsoleKeyShortcuts": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "BaseUpdateAppcompatCache": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "BasepFreeActivationContextActivationBlock": SimTypeFunction(
            [SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "GetBinaryType": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "Basep8BitStringToDynamicUnicodeString": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "RegQueryInfoKeyA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "BasepFreeAppCompatData": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "RegEnumKeyExA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "CheckElevationEnabled": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "GetCalendarDateFormatEx": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "RegSetValueExA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "RegEnumValueA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "GetConsoleKeyboardLayoutNameW": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "SetComPlusPackageInstallStatus": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "GetVDMCurrentDirectories": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "CloseConsoleHandle": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "EnumerateLocalComputerNamesA": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "UTUnRegister": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "GetCalendarDateFormat": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "SetProcessUserModeExceptionPolicy": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "CheckElevation": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "RegisterWaitForInputIdle": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "ConvertSystemTimeToCalDateTime": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "IsTimeZoneRedirectionEnabled": SimTypeFunction([], SimTypeLong(signed=True)),
    }

    missing_declarations[("win32", "advapi32", "dll")] = {
        "GetInformationCodeAuthzLevelW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "WmiFreeBuffer": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "GetNamedSecurityInfoExW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "WmiQuerySingleInstanceMultipleA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "ConvertSecurityDescriptorToAccessA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "CredProfileLoaded": SimTypeFunction([], SimTypeLong(signed=True)),
        "WmiExecuteMethodW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "ProcessIdleTasksW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "MD4Final": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "SystemFunction013": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "CredpConvertOneCredentialSize": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "EncryptedFileKeyInfo": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "ElfBackupEventLogFileW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "MD4Update": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "CloseCodeAuthzLevel": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "EnumServiceGroupW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "GetSecurityInfoExA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "ElfReportEventA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "SystemFunction027": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "LsaEnumeratePrivilegesOfAccount": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SystemFunction024": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "ConvertAccessToSecurityDescriptorW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "WmiDevInstToInstanceNameA": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "WmiEnumerateGuids": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SaferiRegisterExtensionDll": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "LsaCreateSecret": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "ElfOpenEventLogW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "ElfOpenEventLogA": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "LsaGetUserName": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "A_SHAInit": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "LsaOpenPolicySce": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "ElfChangeNotify": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "I_ScSetServiceBitsA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "WmiOpenBlock": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "GetAccessPermissionsForObjectA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "LsaICLookupNames": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "UnregisterIdleTask": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SystemFunction025": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "ElfRegisterEventSourceA": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SystemFunction010": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "WmiMofEnumerateResourcesA": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "ConvertSDToStringSDRootDomainW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "A_SHAFinal": SimTypeFunction([SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "LsaSetSecurityObject": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "LsaSetSystemAccessAccount": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "WmiFileHandleToInstanceNameA": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "FreeEncryptedFileKeyInfo": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "LsaGetRemoteUserName": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "EventWriteStartScenario": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "SystemFunction014": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "AddUsersToEncryptedFileEx": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "ElfRegisterEventSourceW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "CredEncryptAndMarshalBinaryBlob": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SaferiPopulateDefaultsInRegistry": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SaferiSearchMatchingHashRules": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "LsaGetSystemAccessAccount": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "ElfReadEventLogW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "WmiExecuteMethodA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "WmiSetSingleInstanceA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "LsaLookupPrivilegeValue": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "WmiSetSingleItemW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "WmiQueryAllDataA": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "CredBackupCredentials": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "ConvertStringSDToSDRootDomainW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "LsaCreateTrustedDomain": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "GetAccessPermissionsForObjectW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "ElfReportEventW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "SetSecurityInfoExW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "SystemFunction015": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "ElfCloseEventLog": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "UsePinForEncryptedFilesW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "LsaManageSidNameMapping": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "CredProfileUnloaded": SimTypeFunction([], SimTypeLong(signed=True)),
        "SystemFunction007": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "WmiSetSingleItemA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "GetNamedSecurityInfoExA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "WmiFileHandleToInstanceNameW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "SaferiChangeRegistryScope": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "MD5Init": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "I_ScPnPGetServiceName": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "CredpConvertTargetInfo": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "GetSecurityInfoExW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "IsValidRelativeSecurityDescriptor": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "CredpDecodeCredential": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "I_ScSetServiceBitsW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "RegisterIdleTask": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "SystemFunction017": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SystemFunction033": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "CancelOverlappedAccess": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "TrusteeAccessToObjectW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "LsaOpenSecret": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "EventWriteEndScenario": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "ComputeAccessTokenFromCodeAuthzLevel": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "LsaGetQuotasForAccount": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "I_ScIsSecurityProcess": SimTypeFunction([], SimTypeLong(signed=True)),
        "SetNamedSecurityInfoExA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "SystemFunction019": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "WmiQueryAllDataMultipleW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "ElfDeregisterEventSource": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "ElfClearEventLogFileA": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "ConvertAccessToSecurityDescriptorA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "SystemFunction016": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "WmiMofEnumerateResourcesW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "WmiNotificationRegistrationA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "LsaAddPrivilegesToAccount": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SystemFunction003": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SystemFunction020": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SystemFunction006": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "ConvertStringSDToSDRootDomainA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "ConvertStringSDToSDDomainW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "ConvertSecurityDescriptorToAccessNamedA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "LsaRemovePrivilegesFromAccount": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "WmiQuerySingleInstanceW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "ProcessIdleTasks": SimTypeFunction([], SimTypeLong(signed=True)),
        "ConvertStringSDToSDDomainA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "SetEntriesInAuditListA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "NotifyServiceStatusChange": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "LsaQuerySecurityObject": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "ElfBackupEventLogFileA": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SystemFunction018": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SaferiIsDllAllowed": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "WmiCloseBlock": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "SystemFunction035": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "WmiSetSingleInstanceW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "CredpEncodeCredential": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "WmiQueryAllDataMultipleA": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "SystemFunction030": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "LsaOpenTrustedDomain": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "SystemFunction005": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SystemFunction012": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SystemFunction031": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SetEntriesInAuditListW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "I_ScGetCurrentGroupStateW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SetNamedSecurityInfoExW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "ElfNumberOfRecords": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "LsaClearAuditLog": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "CreateCodeAuthzLevel": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "MD5Update": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "ElfFlushEventLog": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "MakeAbsoluteSD2": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SaferiCompareTokenLevels": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SetEntriesInAccessListA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "SystemFunction008": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "FlushEfsCache": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "ConvertSecurityDescriptorToAccessNamedW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "LsaCreateAccount": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "LsaEnumerateAccounts": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "WmiQueryGuidInformation": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "I_QueryTagInformation": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SetInformationCodeAuthzLevelW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "LsaQueryInfoTrustedDomain": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SystemFunction028": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "WmiQuerySingleInstanceMultipleW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "WmiReceiveNotificationsW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "LsaSetInformationTrustedDomain": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "I_ScValidatePnPService": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "ElfReportEventAndSourceW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "ConvertSDToStringSDRootDomainA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "TrusteeAccessToObjectA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "MD4Init": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "GetOverlappedAccessResults": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "LogonUserExExW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "LsaLookupPrivilegeName": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "LsaOpenAccount": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "CredRestoreCredentials": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "I_ScSendTSMessage": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "LsaLookupPrivilegeDisplayName": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "I_ScSendPnPMessage": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "LsaICLookupSids": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "SystemFunction034": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SaferiRecordEventLogEntry": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SystemFunction026": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "ElfOpenBackupEventLogA": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SystemFunction029": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "LsaSetSecret": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "ElfReadEventLogA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "CredpConvertCredential": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "ConvertSecurityDescriptorToAccessW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "LsaICLookupSidsWithCreds": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "SetSecurityInfoExA": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "SystemFunction001": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "UsePinForEncryptedFilesA": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "LsaQuerySecret": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "LsaEnumeratePrivileges": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "SystemFunction032": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "GetInformationCodeAuthzPolicyW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "CredpEncodeSecret": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "ElfOpenBackupEventLogW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "IdentifyCodeAuthzLevelW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "SystemFunction009": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "A_SHAUpdate": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "LsaDelete": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
        "ElfClearEventLogFileW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SetInformationCodeAuthzPolicyW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "I_ScQueryServiceConfig": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "WmiDevInstToInstanceNameW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "SystemFunction022": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "WmiQueryAllDataW": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "WmiQuerySingleInstanceA": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "ElfOldestRecord": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SystemFunction002": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SetEntriesInAccessListW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "LsaSetQuotasForAccount": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "CredReadByTokenHandle": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "SystemFunction004": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "LsaICLookupNamesWithCreds": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "SystemFunction023": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "SystemFunction011": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "WmiNotificationRegistrationW": SimTypeFunction(
            [
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
                SimTypeLong(signed=True),
            ],
            SimTypeLong(signed=True),
        ),
        "SystemFunction021": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)], SimTypeLong(signed=True)
        ),
        "WmiReceiveNotificationsA": SimTypeFunction(
            [SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True), SimTypeLong(signed=True)],
            SimTypeLong(signed=True),
        ),
        "MD5Final": SimTypeFunction([SimTypeLong(signed=True)], SimTypeLong(signed=True)),
    }

    for (prefix, lib, suffix), decls in missing_declarations.items():
        for func, proto in decls.items():
            parsed_cprotos[(prefix, lib, suffix)].append((func, proto, ""))

    # Write to files

    header = """# pylint:disable=line-too-long
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
"""
    footer = """    }

lib.set_prototypes(prototypes)
"""

    # Dump function prototypes

    for (prefix, libname, suffix), parsed_cprotos_per_lib in parsed_cprotos.items():
        filename = prefix + "_" + libname.replace(".", "_") + ".py"
        logging.debug("Writing to file %s...", filename)
        with open(filename, "w") as f:
            f.write(header)
            if (prefix, libname) == ("win32", "kernel32"):
                f.write(
                    """lib.add_all_from_dict(P['win32'])
lib.add_alias('EncodePointer', 'DecodePointer')
lib.add_alias('GlobalAlloc', 'LocalAlloc')

lib.add('lstrcatA', P['libc']['strcat'])
lib.add('lstrcmpA', P['libc']['strcmp'])
lib.add('lstrcpyA', P['libc']['strcpy'])
lib.add('lstrcpynA', P['libc']['strncpy'])
lib.add('lstrlenA', P['libc']['strlen'])
lib.add('lstrcmpW', P['libc']['wcscmp'])
lib.add('lstrcmpiW', P['libc']['wcscasecmp'])
"""
                )
            elif (prefix, libname) == ("win32", "ntdll"):
                f.write(
                    """lib.add('RtlEncodePointer', P['win32']['EncodePointer'])
lib.add('RtlDecodePointer', P['win32']['EncodePointer'])
lib.add('RtlAllocateHeap', P['win32']['HeapAlloc'])
"""
                )
            elif (prefix, libname) == ("win32", "user32"):
                f.write(
                    """import archinfo
from ...calling_conventions import SimCCCdecl

lib.add_all_from_dict(P['win_user32'])
lib.add('wsprintfA', P['libc']['sprintf'], cc=SimCCCdecl(archinfo.ArchX86()))
"""
                )
            elif (prefix, libname) == ("wdk", "ntoskrnl"):
                f.write(
                    """lib.add_all_from_dict(P["win32_kernel"])
"""
                )

            if suffix:
                f.write(f'lib.set_library_names("{libname}.{suffix}")\n')
            else:
                f.write(f'lib.set_library_names("{libname}")\n')
            f.write("prototypes = \\\n    {\n")
            f.write(parsedcprotos2py(parsed_cprotos_per_lib))
            f.write(footer)

    # Dump the type collection
    with open("types_win32.py", "w") as f:
        f.write(
            """# pylint:disable=line-too-long
from collections import OrderedDict

from angr.procedures.definitions import SimTypeCollection
from angr.sim_type import SimTypeFunction, \
    SimTypeShort, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeDouble, SimTypeFloat, \
    SimTypePointer, \
    SimTypeChar, \
    SimStruct, \
    SimTypeArray, \
    SimTypeBottom, \
    SimUnion, \
    SimTypeBool, \
    SimTypeRef

"""
        )
        f.write(typelib.init_str())


def main():
    _args = ArgumentParser(description="Build a typelib from win32json project")
    _args.add_argument("win32json_api_directory")
    _args.add_argument("-v", action="count", help="Increase logging verbosity. Can specify multiple times.")
    args = _args.parse_args()
    if args.v is not None:
        logging.root.setLevel(level=max(30 - (args.v * 10), 0))
    do_it(args.win32json_api_directory, None)


if __name__ == "__main__":
    main()
