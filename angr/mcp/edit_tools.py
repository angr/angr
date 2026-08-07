"""
Batch edit tools: rename, set_type, and set_comments.

Every tool takes a list of items and returns one result per item. Per-item failures are reported as
data rather than raised, so one bad item does not discard the work done by its siblings -- that is
the point of batching. Only whole-call problems (an unknown project, a malformed request) raise.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import TYPE_CHECKING, Any

from angr.analyses.decompiler.edits import (
    DecompilationEditError,
    get_cache,
    parse_address,
    reflow_types,
    rename_function,
    rename_global,
    rename_variable,
    resolve_function,
    resolve_variable,
    restore_user_edits,
    set_comment,
    set_function_prototype,
    set_global_type,
    set_variable_type,
)

from .errors import InvalidArgumentError
from .server import _as_tool_error, _get_session, _require_cfg, _serialized, mcp

if TYPE_CHECKING:
    from collections.abc import Callable

    from angr.knowledge_plugins.functions import Function

    from .session import ProjectSession

l = logging.getLogger(__name__)

RENAME_KINDS = ("function", "variable", "global")
TYPE_KINDS = ("function", "variable", "global", "return")
COMMENT_KINDS = ("address", "function")


def _require_items(items: Any) -> list[dict[str, Any]]:
    if isinstance(items, dict):
        items = [items]
    if not isinstance(items, list) or not items:
        raise InvalidArgumentError("'items' must be a non-empty list of objects.")
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise InvalidArgumentError(f"items[{index}] must be an object, got {type(item).__name__}.")
    return items


def _kind_of(item: dict[str, Any], index: int, allowed: tuple[str, ...]) -> str:
    kind = item.get("kind")
    if kind not in allowed:
        raise InvalidArgumentError(
            f"items[{index}]: 'kind' is required and must be one of {', '.join(allowed)}; got {kind!r}."
        )
    return kind


def _required(item: dict[str, Any], index: int, field: str) -> Any:
    value = item.get(field)
    if value is None or value == "":
        raise InvalidArgumentError(f"items[{index}]: {field!r} is required.")
    return value


def _function_of(session: ProjectSession, item: dict[str, Any], index: int, field: str = "function") -> Function:
    target = _required(item, index, field)
    kb = session.project.kb
    if isinstance(target, int):
        return resolve_function(kb, address=target)
    text = str(target)
    if text.startswith("0x") or text.isdigit():
        return resolve_function(kb, address=text)
    return resolve_function(kb, name=text)


def _function_from(session: ProjectSession, item: dict[str, Any], index: int) -> Function:
    """
    Identify a function-scoped item.

    "function" wins when present; otherwise the item's own "name"/"address" identify it. Variable
    items must not use this: there "name" is the variable's name, not the function's.
    """
    if item.get("function") is not None:
        return _function_of(session, item, index)
    kb = session.project.kb
    if item.get("address") is not None:
        return resolve_function(kb, address=item["address"])
    name = item.get("name")
    if not name:
        raise InvalidArgumentError(f"items[{index}]: needs a 'function', a 'name', or an 'address'.")
    return resolve_function(kb, name=str(name))


def _global_addr_of(session: ProjectSession, item: dict[str, Any], index: int) -> int:
    kb = session.project.kb
    if item.get("address") is not None:
        return parse_address(item["address"])
    name = item.get("name")
    if not name:
        raise InvalidArgumentError(f"items[{index}]: kind 'global' needs an 'address' or a 'name'.")
    addr = kb.labels.lookup(str(name), None)
    if addr is None:
        raise InvalidArgumentError(f"items[{index}]: no global named {name!r}.")
    return addr


def _ensure_decompiled(session: ProjectSession, func: Function, auto_decompile: bool) -> None:
    """Variable edits need a codegen. Decompiling on demand keeps callers from a two-step dance."""
    if get_cache(session.project.kb, func.addr) is not None:
        return
    if not auto_decompile:
        raise InvalidArgumentError(
            f"{func.name} has not been decompiled. Call decompile_function first, or pass auto_decompile=True."
        )
    session.project.analyses.Decompiler(func)


def _entry(index: int, kind: str, **fields: Any) -> dict[str, Any]:
    entry = {
        "index": index,
        "kind": kind,
        "status": "ok",
        "function_address": None,
        "function_name": None,
        "target": None,
        "old": None,
        "new": None,
        "detail": {},
        "error": None,
        "error_kind": None,
        "candidates": None,
    }
    entry.update(fields)
    return entry


def _error_entry(index: int, kind: str | None, target: Any, exc: Exception) -> dict[str, Any]:
    return _entry(
        index,
        kind or "unknown",
        status="error",
        target=None if target is None else str(target),
        error=str(exc),
        error_kind=type(exc).__name__,
        candidates=getattr(exc, "candidates", None) or None,
    )


def _run(
    project_id: str,
    items: Any,
    allowed_kinds: tuple[str, ...],
    apply_item: Callable[[ProjectSession, int, str, dict[str, Any]], dict[str, Any]],
    *,
    dry_run: bool,
    stop_on_error: bool,
    post: Callable[[ProjectSession, set[int]], None] | None = None,
) -> dict[str, Any]:
    session = _get_session(project_id)
    _require_cfg(session)
    items = _require_items(items)

    results: list[dict[str, Any]] = []
    touched: set[int] = set()
    halted = False

    for index, item in enumerate(items):
        if halted:
            results.append(
                _entry(index, item.get("kind") or "unknown", status="skipped", error="stopped by an earlier failure")
            )
            continue
        kind = None
        try:
            kind = _kind_of(item, index, allowed_kinds)
            entry = apply_item(session, index, kind, item)
        except (DecompilationEditError, InvalidArgumentError, ValueError) as e:
            entry = _error_entry(index, kind, item.get("name") or item.get("function"), e)
            if stop_on_error:
                halted = True
        results.append(entry)
        if entry["status"] == "ok" and entry["function_address"]:
            touched.add(int(entry["function_address"], 16))

    if post is not None and not dry_run:
        post(session, touched)

    counts = Counter(entry["status"] for entry in results)
    return {
        "project_id": project_id,
        "dry_run": dry_run,
        "total": len(results),
        "succeeded": counts.get("ok", 0),
        "unchanged": counts.get("unchanged", 0),
        "failed": counts.get("error", 0),
        "skipped": counts.get("skipped", 0),
        "results": results,
        "functions_affected": sorted(hex(addr) for addr in touched),
    }


@mcp.tool()
@_as_tool_error
@_serialized
def rename(
    project_id: str,
    items: list[dict[str, Any]],
    dry_run: bool = False,
    stop_on_error: bool = False,
    allow_overwrite: bool = False,
    auto_decompile: bool = True,
) -> dict[str, Any]:
    """
    Rename functions, decompilation variables, and globals in one call.

    Each item needs a "kind" and a "new_name":

    - kind "function": identify it with "name" or "address".
    - kind "variable": "function" (name or address) plus "name", the variable's current name as it
      appears in the pseudocode. Covers locals, arguments, and stack slots -- angr routes them
      through one path, so the item does not say which; the result reports the resolved storage.
    - kind "global": "address", or "name" if the global already has a label.

    Renames persist across re-decompilation. Renaming a variable requires the function to have been
    decompiled; with auto_decompile it is decompiled on demand.

    Args:
        project_id: The project ID
        items: The rename requests
        dry_run: Resolve and validate without changing anything. Not side-effect free: resolving a
            variable name may decompile the function.
        stop_on_error: Stop at the first failure and mark the rest skipped. Edits already applied
            are NOT rolled back; use dry_run as a pre-flight.
        allow_overwrite: Permit a name already bound to something else (default: False)
        auto_decompile: Decompile a function on demand when a variable rename needs it

    Returns:
        A per-item result list plus counts of succeeded/unchanged/failed/skipped
    """

    def apply_item(session: ProjectSession, index: int, kind: str, item: dict[str, Any]) -> dict[str, Any]:
        proj = session.project
        new_name = _required(item, index, "new_name")

        if kind == "function":
            func = _function_from(session, item, index)
            if dry_run:
                status = "unchanged" if func.name == new_name else "ok"
                return _entry(
                    index,
                    kind,
                    status=status,
                    function_address=hex(func.addr),
                    function_name=func.name,
                    target=func.name,
                    old=func.name,
                    new=new_name,
                )
            result = rename_function(proj, func, new_name, allow_overwrite=allow_overwrite)
            return _entry(
                index,
                kind,
                status="ok" if result.changed else "unchanged",
                function_address=hex(func.addr),
                function_name=func.name,
                target=result.old,
                old=result.old,
                new=result.new,
            )

        if kind == "global":
            addr = _global_addr_of(session, item, index)
            if dry_run:
                return _entry(index, kind, target=hex(addr), new=new_name, detail={"global_address": hex(addr)})
            result = rename_global(proj, addr, new_name, allow_overwrite=allow_overwrite)
            return _entry(
                index,
                kind,
                status="ok" if result.changed else "unchanged",
                target=result.old,
                old=result.old,
                new=result.new,
                detail=result.detail,
            )

        func = _function_of(session, item, index)
        _ensure_decompiled(session, func, auto_decompile)
        current = _required(item, index, "name")
        if dry_run:
            rv = resolve_variable(proj.kb, func.addr, str(current))
            return _entry(
                index,
                kind,
                status="unchanged" if rv.name == new_name else "ok",
                function_address=hex(func.addr),
                function_name=func.name,
                target=rv.name,
                old=rv.name,
                new=new_name,
                detail=rv.detail(),
            )
        result = rename_variable(proj, func, str(current), new_name, allow_overwrite=allow_overwrite)
        return _entry(
            index,
            kind,
            status="ok" if result.changed else "unchanged",
            function_address=hex(func.addr),
            function_name=func.name,
            target=result.old,
            old=result.old,
            new=result.new,
            detail=result.detail,
        )

    return _run(project_id, items, RENAME_KINDS, apply_item, dry_run=dry_run, stop_on_error=stop_on_error)


@mcp.tool()
@_as_tool_error
@_serialized
def set_type(
    project_id: str,
    items: list[dict[str, Any]],
    dry_run: bool = False,
    stop_on_error: bool = False,
    redecompile: bool = False,
    auto_decompile: bool = True,
) -> dict[str, Any]:
    """
    Set types on decompilation variables, globals, and function prototypes in one call.

    Each item needs a "kind" and a "type":

    - kind "variable": "function" plus "name". Retyping an argument rewrites the function's
      prototype, which forces that function to be re-decompiled.
    - kind "function": identify it with "function", "name", or "address"; "type" is a full
      signature, e.g. "int parse(char *buf, int len)". The name inside the signature is ignored --
      use rename for that. This discards the function's cached decompilation and variables; earlier
      renames and manual types, including ones set by earlier items in the same batch, are restored
      afterwards.
    - kind "return": same identifiers, replaces only the return type and keeps the arguments.
    - kind "global": "address" or "name", plus "type".

    Types are re-inferred through the cached constraints once per affected function rather than per
    item. That reflow does NOT rebuild the syntax tree, so a retype that should change how an access
    renders -- a struct field, an array index -- needs redecompile=True.

    Args:
        project_id: The project ID
        items: The type requests
        dry_run: Validate and resolve without changing anything
        stop_on_error: Stop at the first failure; already-applied edits are NOT rolled back
        redecompile: Fully re-decompile each affected function instead of reflowing types
        auto_decompile: Decompile a function on demand when an item needs it

    Returns:
        A per-item result list plus counts of succeeded/unchanged/failed/skipped
    """

    # A prototype change drops the function's cached decompilation and its variables, which would
    # discard the manual types set by earlier items in this same batch. set_function_prototype hands
    # back a snapshot of them; the post-pass re-decompiles and restores it.
    pending_restores: dict[int, dict] = {}

    def apply_item(session: ProjectSession, index: int, kind: str, item: dict[str, Any]) -> dict[str, Any]:
        proj = session.project
        type_text = _required(item, index, "type")

        if kind == "global":
            addr = _global_addr_of(session, item, index)
            if dry_run:
                return _entry(index, kind, target=hex(addr), new=str(type_text))
            result = set_global_type(proj, addr, str(type_text))
            return _entry(index, kind, target=hex(addr), old=result.old, new=result.new, detail=result.detail)

        func = (
            _function_from(session, item, index)
            if kind in ("function", "return")
            else _function_of(session, item, index)
        )

        if kind in ("function", "return"):
            signature = str(type_text)
            if kind == "return" and func.prototype is None:
                raise InvalidArgumentError(
                    f"items[{index}]: {func.name} has no prototype yet; "
                    "run recover_calling_conventions first, or set a full signature with kind 'function'."
                )
            if dry_run:
                return _entry(
                    index,
                    kind,
                    function_address=hex(func.addr),
                    function_name=func.name,
                    old=None if func.prototype is None else str(func.prototype),
                    new=signature,
                )
            if kind == "return":
                result = _set_return_type(proj, func, signature)
            else:
                result = set_function_prototype(proj, func, signature, redecompile=redecompile)
            snapshot = result.detail.get("user_edits")
            if snapshot:
                pending_restores.setdefault(func.addr, {}).update(snapshot)
            return _entry(
                index,
                kind,
                function_address=hex(func.addr),
                function_name=func.name,
                old=result.old,
                new=result.new,
                detail={k: v for k, v in result.detail.items() if k not in ("user_edits", "code")},
            )

        _ensure_decompiled(session, func, auto_decompile)
        current = _required(item, index, "name")
        if dry_run:
            rv = resolve_variable(proj.kb, func.addr, str(current))
            return _entry(
                index,
                kind,
                function_address=hex(func.addr),
                function_name=func.name,
                target=rv.name,
                new=str(type_text),
                detail=rv.detail(),
            )
        # reflow once per function afterwards instead of per item: Typehoon is expensive
        result = set_variable_type(proj, func, str(current), str(type_text), reflow=False)
        return _entry(
            index,
            kind,
            function_address=hex(func.addr),
            function_name=func.name,
            target=str(current),
            old=result.old,
            new=result.new,
            detail=result.detail,
        )

    def post(session: ProjectSession, touched: set[int]) -> None:
        proj, kb = session.project, session.project.kb
        for addr in sorted(touched):
            func = kb.functions.get(addr)
            if func is None:
                continue

            snapshot = pending_restores.get(addr)
            if get_cache(kb, addr) is None:
                # a prototype change discarded the cache: rebuild it, then put back the renames and
                # manual types that came with it
                proj.analyses.Decompiler(func)
                if snapshot:
                    restored, _ = restore_user_edits(kb, addr, snapshot)
                    if restored:
                        reflow_types(proj, func)
                continue

            if redecompile:
                proj.analyses.Decompiler(func, regen_clinic=True)
            else:
                reflow_types(proj, func)

    return _run(project_id, items, TYPE_KINDS, apply_item, dry_run=dry_run, stop_on_error=stop_on_error, post=post)


def _set_return_type(proj, func: Function, type_text: str):
    """Replace only the return type, keeping the argument list."""
    from angr.analyses.decompiler.edits.ops import _parse_type

    proto = func.prototype
    if proto is None:
        raise InvalidArgumentError(f"{func.name} has no prototype to modify.")
    new_proto = proto.copy()
    new_proto.returnty = _parse_type(type_text, proj.arch)
    return set_function_prototype(proj, func, new_proto)


@mcp.tool()
@_as_tool_error
@_serialized
def set_comments(
    project_id: str,
    items: list[dict[str, Any]],
    dry_run: bool = False,
    stop_on_error: bool = False,
) -> dict[str, Any]:
    """
    Set or clear comments at addresses in one call.

    Each item needs a "kind" and a "comment"; an empty comment clears it.

    - kind "address": "address" is any address in the binary.
    - kind "function": identify it with "function", "name", or "address"; comments its header.

    A comment is written to the knowledge base -- where the disassembly and the function header read
    it -- and mirrored next to the matching pseudocode statement. Because pseudocode comments are
    keyed by instruction address, an address that is not a statement boundary is snapped down to the
    nearest one; each result reports "snapped_from" and whether the comment actually
    rendered inline ("rendered_inline") rather than in the orphaned-comments block.

    Args:
        project_id: The project ID
        items: The comment requests
        dry_run: Resolve addresses without changing anything
        stop_on_error: Stop at the first failure; already-applied edits are NOT rolled back

    Returns:
        A per-item result list plus counts of succeeded/unchanged/failed/skipped
    """

    def apply_item(session: ProjectSession, index: int, kind: str, item: dict[str, Any]) -> dict[str, Any]:
        proj = session.project
        comment = item.get("comment") or ""

        if kind == "function":
            addr = _function_from(session, item, index).addr
        else:
            addr = parse_address(_required(item, index, "address"))

        if dry_run:
            return _entry(index, kind, target=hex(addr), new=comment)

        result = set_comment(proj, addr, comment)
        return _entry(
            index,
            kind,
            status="ok" if result.changed else "unchanged",
            function_address=None if result.func_addr is None else hex(result.func_addr),
            target=hex(addr),
            old=result.old,
            new=result.new,
            detail=result.detail,
        )

    return _run(project_id, items, COMMENT_KINDS, apply_item, dry_run=dry_run, stop_on_error=stop_on_error)
