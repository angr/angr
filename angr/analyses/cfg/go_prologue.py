"""
Recognition of the Go (gc) goroutine stack-growth preamble.

Every non-nosplit Go function starts with a check of the current stack pointer (or of the
prospective frame bottom) against ``g.stackguard0``, followed by a forward branch to a
``runtime.morestack`` trampoline appended after the function body. The conventional prologue the
architecture's ``function_prologs`` describe only comes *after* that check, so a plain prologue scan
reports function starts several instructions past the real entry.

The byte patterns live in Rust (``angr.rustylib.cfg_scan``, ``native/angr/src/cfg_scan.rs``); the
documentation of the encodings per architecture and Go release is kept there.
"""

from __future__ import annotations

from collections.abc import Iterator

from angr.rustylib import cfg_scan


def go_preamble_supported(arch_name: str) -> bool:
    """
    Whether the Go stack-growth preamble is recognized on the named architecture.
    """

    return cfg_scan.go_preamble_supported(arch_name)


def find_go_stack_check_preambles(blob: bytes, arch_name: str, base: int = 0) -> Iterator[tuple[int, int, int]]:
    """
    Find every Go goroutine stack-growth preamble in ``blob``.

    :param blob:        A blob of machine code.
    :param arch_name:   ``archinfo`` name of the architecture ``blob`` is code for.
    :param base:        The address ``blob`` starts at, used to enforce instruction alignment.
    :return:            An iterator of ``(start, end, branch_target)`` offsets into ``blob``. Only
                        preambles whose stack-growth branch goes forward are reported; the caller
                        must still check that ``branch_target`` lies in the same executable region.
    """

    return iter(cfg_scan.find_go_stack_check_preambles(bytes(blob), arch_name, base))
