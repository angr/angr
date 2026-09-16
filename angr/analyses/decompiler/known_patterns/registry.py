"""The template registry: every :class:`KnownPatternTemplate` the package
defines, keyed by call name and by human name, plus the helpers that turn a
user's selection or a target's gates into the list of templates to match with.

Kept apart from the package ``__init__`` so that the finder and the call-info
helpers can import it at module load without a cycle.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

    from .context import PatternContext
    from .gating import GateContext
    from .pattern import KnownPattern
    from .templates import KnownPatternTemplate

ALL_KNOWN_PATTERN_TEMPLATES: list[KnownPatternTemplate] = []
TEMPLATE_BY_CALL_NAME: dict[str, KnownPatternTemplate] = {}
TEMPLATE_BY_NAME: dict[str, KnownPatternTemplate] = {}

#: Value of the ``known_patterns`` decompilation option that force-enables every
#: registered template, opt-in ones included.
ALL_PATTERNS = "all"


class UnknownPatternError(ValueError):
    """Raised when a pattern selection names a template that is not registered."""


def register_pattern_template(template: KnownPatternTemplate) -> None:
    """Register a KnownPatternTemplate. Call names are unique across templates
    (the architecture / runtime conditionals live inside each template's
    ``build``)."""
    if template.call_name in TEMPLATE_BY_CALL_NAME:
        raise ValueError(f"a pattern template with call name {template.call_name!r} is already registered")
    ALL_KNOWN_PATTERN_TEMPLATES.append(template)
    TEMPLATE_BY_CALL_NAME[template.call_name] = template
    # a template's human name defaults to its call name; register the second spelling only when it differs and
    # does not shadow some other template's call name
    if template.name not in TEMPLATE_BY_CALL_NAME:
        TEMPLATE_BY_NAME[template.name] = template


def patterns_for(
    ctx: PatternContext,
    templates: Iterable[KnownPatternTemplate] | None = None,
    *,
    enabled_only: bool = False,
) -> list[KnownPattern]:
    """Instantiate the applicable templates for ``ctx`` into concrete
    KnownPatterns. ``templates`` defaults to the whole registry; with
    ``enabled_only`` only default-enabled templates are used."""
    if templates is None:
        templates = ALL_KNOWN_PATTERN_TEMPLATES
    out: list[KnownPattern] = []
    for t in templates:
        if enabled_only and not t.default_enabled:
            continue
        p = t.instantiate(ctx)
        if p is not None:
            out.append(p)
    return out


def resolve_pattern_selection(selection: str | Iterable[str] | None) -> list[KnownPatternTemplate]:
    """Resolve a user's force-enable selection into templates.

    ``selection`` is one of:

    * ``None`` / empty: nothing is force-enabled (returns an empty list);
    * ``"all"``: every registered template, opt-in ones included;
    * an iterable of template ``name``s and/or ``call_name``s (a comma-separated
      string is accepted too, for the string-valued decompilation option).

    An unrecognized name raises :class:`UnknownPatternError` rather than
    silently selecting nothing.
    """
    if selection is None:
        return []
    if isinstance(selection, str):
        if selection.strip().lower() == ALL_PATTERNS:
            return list(ALL_KNOWN_PATTERN_TEMPLATES)
        names = [n.strip() for n in selection.split(",")]
    else:
        names = [str(n).strip() for n in selection]
    names = [n for n in names if n]
    if not names:
        return []
    if len(names) == 1 and names[0].lower() == ALL_PATTERNS:
        return list(ALL_KNOWN_PATTERN_TEMPLATES)

    out: list[KnownPatternTemplate] = []
    seen: set[int] = set()
    for name in names:
        template = TEMPLATE_BY_CALL_NAME.get(name) or TEMPLATE_BY_NAME.get(name)
        if template is None:
            raise UnknownPatternError(
                f"unknown known-pattern {name!r}. Valid names are the template call names "
                f"({', '.join(sorted(TEMPLATE_BY_CALL_NAME)[:3])}, ...) or their short names; pass "
                f'"all" to force-enable every pattern.'
            )
        if id(template) not in seen:
            seen.add(id(template))
            out.append(template)
    return out


def partition_templates(
    gate_ctx: GateContext,
    forced: Iterable[KnownPatternTemplate] = (),
    templates: Iterable[KnownPatternTemplate] | None = None,
) -> tuple[list[KnownPatternTemplate], list[KnownPatternTemplate]]:
    """Split templates into ``(enabled, deferred)`` for one target.

    ``enabled`` are the templates to match with right away: default-on ones,
    ones the caller force-enabled, and ones whose gate already opens on target
    evidence alone. ``deferred`` are the ones whose gate needs per-function
    evidence (see :class:`~.gating.CorroboratedBy`) and must be re-evaluated by
    the finder once the first matching stage has run.
    """
    if templates is None:
        templates = [t for t in ALL_KNOWN_PATTERN_TEMPLATES if t.default_enabled]
    forced_ids = {id(t) for t in forced}
    enabled: list[KnownPatternTemplate] = []
    deferred: list[KnownPatternTemplate] = []
    for t in templates:
        if id(t) in forced_ids or t.enabled_for(gate_ctx):
            enabled.append(t)
        elif t.gate is not None and t.gate.requires_evidence:
            deferred.append(t)
    return enabled, deferred
