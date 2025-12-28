from __future__ import annotations

import logging
import sys
import os
import json
from collections import OrderedDict

from angr.sim_type import SimTypePointer, parse_file, ALL_TYPES, PointerDisposition

l = logging.getLogger(name="parse_glibc")

# some of these are technically incorrect - should say OUTMAYBE. that gives us worse results most of the time though...
DISPOSITIONS: dict[tuple[str, int], PointerDisposition] = {
    ("memset", 0): PointerDisposition.OUT,
    ("memcpy", 0): PointerDisposition.OUT,
    ("memcpy", 1): PointerDisposition.IN,
    ("sprintf", 0): PointerDisposition.OUT,
    ("sprintf", 1): PointerDisposition.IN,
    ("snprintf", 0): PointerDisposition.OUT,
    ("snprintf", 2): PointerDisposition.IN,
    ("vsprintf", 0): PointerDisposition.OUT,
    ("vsprintf", 1): PointerDisposition.IN,
    ("vsnprintf", 0): PointerDisposition.OUT,
    ("vsnprintf", 2): PointerDisposition.IN,
    ("strcpy", 0): PointerDisposition.OUT,
    ("strcpy", 1): PointerDisposition.IN,
    ("strcat", 0): PointerDisposition.IN_OUT,
    ("strcat", 1): PointerDisposition.IN,
    ("stpcpy", 0): PointerDisposition.OUT,
    ("stpcpy", 1): PointerDisposition.IN,
    ("readlink", 0): PointerDisposition.IN,
    ("readlink", 1): PointerDisposition.OUT,
    ("readlinkat", 1): PointerDisposition.IN,
    ("readlinkat", 2): PointerDisposition.OUT,
    ("stat", 0): PointerDisposition.IN,
    ("stat", 1): PointerDisposition.OUT,
    ("lstat", 0): PointerDisposition.IN,
    ("lstat", 1): PointerDisposition.OUT,
    ("fstat", 1): PointerDisposition.OUT,
}


def main():

    with open(sys.argv[1], encoding="utf-8") as f:
        glibc_decls = f.readlines()

    protos = {}
    for c_decl in glibc_decls:
        c_decl = c_decl.strip("\n")

        # preprocessing
        c_decl = c_decl.replace("const ", "")
        c_decl = c_decl.replace("*restrict ", "* ")

        try:
            parsed = parse_file(c_decl, predefined_types=ALL_TYPES)
        except Exception as ex:  # pylint: disable=broad-exception-caught
            l.warning("Cannot parse the function prototype for %s: %s.", c_decl, str(ex))
            continue
        parsed_decl = parsed[0]
        if not parsed_decl:
            l.warning("Cannot parse the function prototype for %s.", c_decl)
            continue

        func_name, func_proto = next(iter(parsed_decl.items()))
        protos[func_name] = func_proto

        for i, ty in enumerate(func_proto.args):
            disp = DISPOSITIONS.get((func_name, i), None)
            if disp is not None:
                assert isinstance(ty, SimTypePointer)
                ty.disposition = disp

    # build the dictionary
    d = {
        "_t": "lib",
        "library_names": [
            "libc.so.0",
            "libc.so.1",
            "libc.so.2",
            "libc.so.3",
            "libc.so.4",
            "libc.so.5",
            "libc.so.6",
            "libc.so.7",
            "libc.so",
        ],
        "non_returning": [
            "exit_group",
            "exit",
            "abort",
            "pthread_exit",
            "__assert_fail",
            "longjmp",
            "siglongjmp",
            "__longjmp_chk",
            "__siglongjmp_chk",
        ],
        "functions": OrderedDict(),
    }
    for func_name in sorted(protos):
        proto = protos[func_name]
        d["functions"][func_name] = {"proto": json.dumps(proto.to_json()).replace('"', "'")}

    os.makedirs("common", exist_ok=True)
    with open(os.path.join(os.path.dirname(__file__), "common/glibc.json"), "w", encoding="utf-8") as f:
        f.write(json.dumps(d, indent="\t"))


if __name__ == "__main__":
    main()
