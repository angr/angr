"""
The mutating operations of the edit layer.

Every operation re-fetches the decompilation cache by key at the point of mutation rather than
holding a reference: see the note in :mod:`.cache`.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import parse_signature, parse_type

from .cache import DEFAULT_FLAVOR, get_cache, invalidate, require_cache, restore_user_edits, snapshot_user_edits
from .errors import NameCollisionError, TypeParseError, UnsupportedEditError
from .hooks import coerce_hooks
from .resolve import concrete_variables, list_variable_names, resolve_variable, validate_name
from .results import EditResult, Refresh

if TYPE_CHECKING:
    from angr.knowledge_base import KnowledgeBase
    from angr.knowledge_plugins.functions import Function
    from angr.project import Project
    from angr.sim_type import SimType, SimTypeFunction

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


def _parse_type(c_type: str | SimType, arch) -> SimType:
    if not isinstance(c_type, str):
        return c_type.with_arch(arch)
    try:
        return parse_type(c_type).with_arch(arch)
    except Exception as ex:  # pylint:disable=broad-exception-caught
        raise TypeParseError(f"Could not parse C type {c_type!r}: {ex}") from ex


def _parse_prototype(prototype: str | SimTypeFunction, arch) -> SimTypeFunction:
    if not isinstance(prototype, str):
        return prototype.with_arch(arch)
    try:
        return parse_signature(prototype).with_arch(arch)
    except Exception as ex:  # pylint:disable=broad-exception-caught
        raise TypeParseError(f"Could not parse C prototype {prototype!r}: {ex}") from ex


def reflow_types(
    project: Project,
    func: Function,
    *,
    kb: KnowledgeBase | None = None,
    flavor: str = DEFAULT_FLAVOR,
    rerender: bool = True,
):
    """
    Re-run type inference over the cached constraints and refresh the rendered code.

    Separate from :func:`set_variable_type` so a batch can retype many variables and reflow once;
    per-variable reflow would re-run Typehoon N times.

    This is not a re-decompilation: the AST is untouched, so a retype that should change how an
    access renders (a struct field, an array index) needs a full re-decompilation instead.
    """
    kb = project.kb if kb is None else kb

    dec = project.analyses.Decompiler(func, decompile=False, use_cache=True, flavor=flavor)
    cache = require_cache(kb, func.addr, flavor)
    new_codegen = dec.reflow_variable_types(cache)
    if new_codegen is None:
        return None

    cache.codegen = new_codegen
    if rerender:
        # reflow_variable_types ends at reload_variable_types(), which refreshes CVariable types but
        # does not re-render; without this the text stays stale
        new_codegen.regenerate_text()
    return new_codegen


def _set_argument_type(
    project: Project,
    func: Function,
    rv,
    new_type: SimType,
    *,
    hooks: EditHooks,
) -> EditResult:
    """Retyping an argument means rewriting the prototype; the variable's own type is not enough."""
    proto = func.prototype
    if proto is None or rv.arg_index is None or rv.arg_index >= len(proto.args):
        raise UnsupportedEditError(
            f"Cannot retype argument {rv.name!r}: {func.name} has no prototype covering argument "
            f"index {rv.arg_index}. Set the whole prototype instead."
        )

    old_type = proto.args[rv.arg_index]
    hooks.before_func_arg_retyped(func, rv.arg_index, old_type, new_type)

    new_proto = proto.copy()
    args = list(new_proto.args)
    args[rv.arg_index] = new_type
    new_proto.args = tuple(args)
    func.prototype = new_proto.with_arch(project.arch)
    func.prototype_source = PrototypeSource.USER
    func.ran_cca = True

    return EditResult(
        changed=True,
        kind="variable_type",
        func_addr=func.addr,
        old=str(old_type),
        new=str(new_type),
        refresh=Refresh(redecompile=frozenset({func.addr})),
        detail=rv.detail(),
    )


def set_variable_type(
    project: Project,
    func: Function,
    variable_name: str,
    c_type: str | SimType,
    *,
    kb: KnowledgeBase | None = None,
    hooks: EditHooks | None = None,
    flavor: str = DEFAULT_FLAVOR,
    reflow: bool = True,
    rerender: bool = True,
    allow_prototype_change: bool = True,
    codegen=None,
) -> EditResult:
    """
    Change the type of a local, an argument, or a global.

    Arguments are retyped by rewriting the function prototype, which requires a re-decompilation --
    the returned Refresh says so. Pass ``allow_prototype_change=False`` to refuse instead.
    """
    kb = project.kb if kb is None else kb
    hooks = coerce_hooks(hooks)
    new_type = _parse_type(c_type, project.arch)

    cache = require_cache(kb, func.addr, flavor)
    if codegen is None:
        codegen = cache.codegen

    rv = resolve_variable(kb, func.addr, variable_name, codegen=codegen, flavor=flavor)

    if rv.kind == "argument":
        if not allow_prototype_change:
            raise UnsupportedEditError(
                f"{variable_name!r} is an argument of {func.name}; change it by setting the whole prototype."
            )
        return _set_argument_type(project, func, rv, new_type, hooks=hooks)

    if rv.kind == "global":
        varman = kb.dec_variables["global"]
        old_type = varman.get_variable_type(rv.variable)
        hooks.before_global_var_retyped(rv.global_addr, old_type, new_type)
        varman.set_variable_type(rv.variable, new_type, all_unified=False, mark_manual=True)
    else:
        varman = kb.dec_variables[func.addr]
        old_type = varman.get_variable_type(rv.variable)
        if rv.stack_offset is not None:
            hooks.before_stack_var_retyped(func, rv.stack_offset, old_type, new_type)
        else:
            hooks.before_other_var_retyped(rv.variable, old_type, new_type)
        # mark_manual is what makes the type survive re-inference: reflow reads
        # variables_with_manual_types as its ground truth
        for var in concrete_variables(varman, rv):
            varman.set_variable_type(var, new_type, all_unified=True, mark_manual=True)

    if reflow:
        reflow_types(project, func, kb=kb, flavor=flavor, rerender=rerender)

    return EditResult(
        changed=True,
        kind="variable_type",
        func_addr=func.addr,
        old=None if old_type is None else str(old_type),
        new=str(new_type),
        refresh=Refresh(text_stale=frozenset({func.addr})),
        detail=rv.detail(),
    )


def set_function_prototype(
    project: Project,
    func: Function,
    prototype: str | SimTypeFunction,
    *,
    kb: KnowledgeBase | None = None,
    hooks: EditHooks | None = None,
    flavor: str = DEFAULT_FLAVOR,
    invalidate_cache: bool = True,
    preserve_user_edits: bool = True,
    redecompile: bool = False,
) -> EditResult:
    """
    Set a function's prototype.

    The function name inside the signature is ignored; use :func:`rename_function` to rename.

    Dropping kb.dec_variables is what makes new argument names take effect, but it also discards
    every rename and manual type for the function. Those are snapshotted and, when this function
    re-decompiles, restored. Otherwise the snapshot is returned in ``detail["user_edits"]`` so a
    caller that decompiles asynchronously can restore it once its own job finishes.
    """
    kb = project.kb if kb is None else kb
    hooks = coerce_hooks(hooks)
    new_proto = _parse_prototype(prototype, project.arch)

    old_proto = func.prototype
    hooks.before_function_retyped(func, old_proto, new_proto)

    snapshot = snapshot_user_edits(kb, func.addr) if preserve_user_edits else {}

    func.prototype = new_proto
    func.prototype_source = PrototypeSource.USER
    # keep CompleteCallingConventions from overwriting a user-supplied prototype
    func.ran_cca = True

    if invalidate_cache:
        invalidate(kb, func.addr, flavors=None, drop_variables=True)

    detail: dict = {"user_edits": snapshot}
    code = None
    if redecompile:
        dec = project.analyses.Decompiler(func, flavor=flavor)
        if snapshot:
            restored, missing = restore_user_edits(kb, func.addr, snapshot)
            detail.update({"restored_user_edits": restored, "unrestored_user_edits": missing})
            detail["user_edits"] = {}
            if restored and dec.codegen is not None:
                dec.codegen.regenerate_text()
        code = dec.codegen.text if dec.codegen is not None else None
    detail["code"] = code

    return EditResult(
        changed=True,
        kind="prototype",
        func_addr=func.addr,
        old=None if old_proto is None else str(old_proto),
        new=str(new_proto),
        refresh=Refresh(redecompile=frozenset({func.addr}), function_list_dirty=True),
        detail=detail,
    )
