"""
The mutating operations of the edit layer.

Every operation re-fetches the decompilation cache by key at the point of mutation rather than
holding a reference: see the note in :mod:`.cache`.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .cache import DEFAULT_FLAVOR, get_cache, require_cache
from .errors import NameCollisionError, UnsupportedEditError
from .hooks import coerce_hooks
from .resolve import list_variable_names, resolve_variable, validate_name
from .results import EditResult, Refresh

if TYPE_CHECKING:
    from angr.knowledge_base import KnowledgeBase
    from angr.knowledge_plugins.functions import Function
    from angr.project import Project

    from .hooks import EditHooks

l = logging.getLogger(name=__name__)


def _require_free_function_name(kb: KnowledgeBase, name: str, own_addr: int) -> None:
    for other in kb.functions.get_by_name(name):
        if other is not None and other.addr != own_addr:
            raise NameCollisionError(
                f"A function named {name!r} already exists at {other.addr:#x}.", existing=other.addr
            )
    existing = kb.labels.lookup(name, None)
    if existing is not None and existing != own_addr:
        raise NameCollisionError(f"The label {name!r} is already bound to {existing:#x}.", existing=existing)


def _set_arg_name(codegen, arg_index: int, new_name: str) -> None:
    """
    Rewrite an argument's name in the rendered signature.

    ``cfunc.functy`` *is* ``func.prototype``, so this single write also updates the stored
    prototype -- do not write both.
    """
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None or cfunc.functy is None or not cfunc.functy.arg_names:
        return
    arg_names = list(cfunc.functy.arg_names)
    if 0 <= arg_index < len(arg_names):
        arg_names[arg_index] = new_name
        cfunc.functy.arg_names = tuple(arg_names)


def rename_function(
    project: Project,
    func: Function,
    new_name: str,
    *,
    kb: KnowledgeBase | None = None,
    hooks: EditHooks | None = None,
    flavor: str = DEFAULT_FLAVOR,
    allow_overwrite: bool = True,
    strict_names: bool = True,
    rerender: bool = True,
) -> EditResult:
    """
    Rename a function.

    Nothing is invalidated: other functions' cached ASTs reference the same Function object, so only
    their rendered text goes stale. That is reported through ``Refresh.text_stale_all`` for the
    caller to act on lazily.
    """
    kb = project.kb if kb is None else kb
    hooks = coerce_hooks(hooks)
    validate_name(new_name, strict=strict_names)

    old_name = func.name
    if old_name == new_name:
        return EditResult(changed=False, kind="function_name", func_addr=func.addr, old=old_name, new=new_name)

    if not allow_overwrite:
        _require_free_function_name(kb, new_name, func.addr)

    hooks.before_function_renamed(func, old_name, new_name)

    kb.functions.get_by_addr(func.addr).name = new_name
    # the name setter does not clear this, and leaving it set makes the default-naming machinery
    # treat the function as still auto-named
    func.is_default_name = False

    cache = get_cache(kb, func.addr, flavor)
    if cache is not None and cache.codegen is not None and getattr(cache.codegen, "cfunc", None) is not None:
        cache.codegen.cfunc.name = new_name
        cache.codegen.cfunc.demangled_name = new_name
        if rerender:
            cache.codegen.regenerate_text()

    return EditResult(
        changed=True,
        kind="function_name",
        func_addr=func.addr,
        old=old_name,
        new=new_name,
        refresh=Refresh(
            text_stale=frozenset({func.addr}),
            text_stale_all=True,
            function_list_dirty=True,
            disassembly_dirty=True,
        ),
    )


def rename_variable(
    project: Project,
    func: Function,
    variable_name: str,
    new_name: str,
    *,
    kb: KnowledgeBase | None = None,
    hooks: EditHooks | None = None,
    flavor: str = DEFAULT_FLAVOR,
    allow_overwrite: bool = True,
    strict_names: bool = True,
    rerender: bool = True,
    codegen=None,
) -> EditResult:
    """
    Rename a local, an argument, or a global as it appears in a function's decompilation.

    Sets ``renamed`` on the variable, without which a later re-decompilation overwrites the name.
    """
    kb = project.kb if kb is None else kb
    hooks = coerce_hooks(hooks)
    validate_name(new_name, strict=strict_names)

    cache = require_cache(kb, func.addr, flavor)
    if codegen is None:
        codegen = cache.codegen

    rv = resolve_variable(kb, func.addr, variable_name, codegen=codegen, flavor=flavor)
    old_name = rv.name

    if old_name == new_name:
        return EditResult(
            changed=False,
            kind="variable_name",
            func_addr=func.addr,
            old=old_name,
            new=new_name,
            detail=rv.detail(),
        )

    if not allow_overwrite and new_name in list_variable_names(codegen, kb, func.addr):
        raise NameCollisionError(f"A variable named {new_name!r} already exists in {func.name}.", existing=new_name)

    # dispatch order matches the GUI's: a stack-backed argument fires the stack hook, not the
    # argument hook
    if rv.kind == "global":
        addr = rv.global_addr
        if addr is not None and addr in kb.functions:
            raise UnsupportedEditError(
                f"{variable_name!r} is the entry point of a function at {addr:#x}; "
                "rename it with rename_function instead."
            )
        hooks.before_global_var_renamed(addr, old_name, new_name)
        target = rv.variable
    elif rv.stack_offset is not None:
        hooks.before_stack_var_renamed(func, rv.stack_offset, old_name, new_name)
        target = rv.unified
    elif rv.kind == "argument":
        hooks.before_func_arg_renamed(func, rv.arg_index, old_name, new_name)
        target = rv.unified
    else:
        target = rv.unified

    target.name = new_name
    target.renamed = True
    target.clear_hash()

    if rv.kind == "global" and rv.global_addr is not None:
        kb.labels[rv.global_addr] = new_name
    if rv.kind == "argument" and rv.arg_index is not None:
        _set_arg_name(codegen, rv.arg_index, new_name)

    if rerender:
        codegen.regenerate_text()

    return EditResult(
        changed=True,
        kind="variable_name",
        func_addr=func.addr,
        old=old_name,
        new=new_name,
        refresh=Refresh(
            text_stale=frozenset({func.addr}),
            disassembly_dirty=rv.kind == "global",
        ),
        detail=rv.detail(),
    )
