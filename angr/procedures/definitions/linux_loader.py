from __future__ import annotations
from . import SimLibrary
from angr.procedures import SIM_PROCEDURES as P

lib = SimLibrary()
lib.set_library_names(
    "ld.so",
    "ld-linux.so",
    "ld.so.2",
    "ld-linux.so.2",
    "ld-linux-x86-64.so.2",
    # https://git.musl-libc.org/cgit/musl/tree/configure?id=1b76ff0767d01df72f692806ee5adee13c67ef88#n322
    *[
        f"ld-musl-{arch}.so.1"
        for arch in [
            "arm",
            "aarch64",
            "nt32",
            "i386",
            "x32",
            "nt64",
            "x86_64",
            "loongarch64",
            "m68k",
            "mips64",
            "mips",
            "microblaze",
            "or1k",
            "powerpc64",
            "powerpc",
            "riscv64",
            "riscv32",
            "sh",
            "s390x",
        ]
    ],
)
lib.add_all_from_dict(P["linux_loader"])
