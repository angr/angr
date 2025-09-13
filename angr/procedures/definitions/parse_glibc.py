from __future__ import annotations

import logging
import sys
import os
import json
from collections import OrderedDict

from angr.sim_type import parse_file, ALL_TYPES

l = logging.getLogger(name="parse_glibc")


def main():

    with open(sys.argv[1], encoding="utf-8") as f:
        glibc_decls = f.readlines()

    protos = {}
    for c_decl in glibc_decls:
        c_decl = c_decl.strip("\n")

        # preprocessing
        c_decl = c_decl.replace("FILE *", "FILE_t *")
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
    with open("common/glibc.json", "w", encoding="utf-8") as f:
        f.write(json.dumps(d, indent="\t"))


if __name__ == "__main__":
    main()
