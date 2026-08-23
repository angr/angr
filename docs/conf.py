# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html
from __future__ import annotations

import datetime
import importlib
import inspect

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "angr"
project_copyright = f"{datetime.datetime.now().year}, The angr Project contributors"
author = "The angr Project"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosectionlabel",
    "sphinx.ext.autosummary",
    "sphinx.ext.coverage",
    "sphinx.ext.intersphinx",
    "sphinx.ext.napoleon",
    "sphinx.ext.todo",
    "sphinx_autodoc_typehints",
    "myst_parser",
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# -- Options for autosectionlabel --------------------------------------------
# Prefix every auto-generated section label with the document path so labels
# in different files (e.g. "Core Concepts" appearing in two docs) don't
# collide. References must spell out the document path:
# ``:ref:`text <path/to/doc:Heading>```.
autosectionlabel_prefix_document = True

# -- Options for autodoc -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/extensions/autodoc.html#configuration
autoclass_content = "class"
autodoc_class_signature = "separated"
autodoc_default_options = {
    "members": True,
    "member-order": "bysource",
    "show-inheritance": True,
    "special-members": "__init__",
    "undoc-members": True,
}
autodoc_inherit_docstrings = True
autodoc_typehints = "both"

# -- Options for coverage ----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/extensions/coverage.html
coverage_write_headline = False

coverage_ignore_pyobjects = [
    "angr.analyses.decompiler.structured_codegen.c.StructuredCodeGenerator",  # Alias to CStructuredCodeGenerator
    "angr.sim_type.SimTypeFixedSizeArray",  # Alias to SimTypeArray
]

# -- Options for intersphinx -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/extensions/intersphinx.html
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "archinfo": ("https://docs.angr.io/projects/archinfo/en/latest/", None),
    "claripy": ("https://docs.angr.io/projects/claripy/en/latest/", None),
    "cle": ("https://docs.angr.io/projects/cle/en/latest/", None),
    "pypcode": ("https://docs.angr.io/projects/pypcode/en/latest/", None),
    "pyvex": ("https://docs.angr.io/projects/pyvex/en/latest/", None),
}

# -- Options for todos -------------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/extensions/todo.html
todo_include_todos = True

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "furo"
html_static_path = ["_static"]


# -- Inherited / overridden member handling ----------------------------------
# A member that exists on a subclass but lacks its own docstring (whether it
# is a plain inheritance pulled in by ``inherited-members`` or a silent
# override) gets its docstring resolved up the MRO by Sphinx, which results in
# the parent's full documentation being duplicated onto every descendant. That
# is both noisy and misleading when the override actually behaves differently.
#
# Instead, skip these members entirely. The parent class's page remains the
# single source of truth and is reachable via the rendered "Bases: ..." link
# at the top of the subclass's entry. Members the subclass author documented
# explicitly are untouched.


def _own_docstring(member: object) -> str | None:
    """Return ``member.__doc__`` directly (no MRO walk), unwrapping descriptors."""
    if isinstance(member, (staticmethod, classmethod)):
        member = member.__func__
    return getattr(member, "__doc__", None)


def _has_documented_ancestor(cls: type, member_name: str) -> bool:
    for base in cls.__mro__[1:]:
        if base is object:
            continue
        member = base.__dict__.get(member_name)
        if member is None:
            continue
        doc = _own_docstring(member)
        if doc and doc.strip():
            return True
    return False


def _is_class_member_kind(obj: object) -> bool:
    """Return True if ``obj`` is the sort of class member whose docstring may be inherited."""
    if isinstance(obj, (staticmethod, classmethod, property)):
        return True
    return inspect.isfunction(obj) or inspect.ismethod(obj) or inspect.ismethoddescriptor(obj)


def skip_inherited_undocumented(app, what, name, obj, skip, options):
    """Skip class members whose only docstring comes from an ancestor.

    Autodoc fires this event with ``what`` set to the *parent's* object type
    (``"class"`` for class members), so we inspect ``obj`` itself to decide
    whether it is the sort of member that can inherit a docstring.
    """
    if skip:
        return skip
    if not _is_class_member_kind(obj):
        return skip

    cls = _enclosing_class(obj, name)
    if cls is None:
        return skip

    member_name = name.rpartition(".")[2] or name
    own = cls.__dict__.get(member_name)
    if own is None:
        # Pure inheritance (only reached if ``inherited-members`` is enabled).
        return True if _has_documented_ancestor(cls, member_name) else skip

    own_doc = _own_docstring(own)
    if own_doc and own_doc.strip():
        return skip
    return True if _has_documented_ancestor(cls, member_name) else skip


def _enclosing_class(obj: object, name: str) -> type | None:
    """Best-effort lookup of the class that owns ``obj`` during an autodoc pass."""
    qualname = getattr(obj, "__qualname__", "")
    module_name = getattr(obj, "__module__", None)
    if module_name and qualname and "." in qualname:
        class_path = qualname.rsplit(".", 1)[0]
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            module = None
        if module is not None:
            target: object | None = module
            for attr in class_path.split("."):
                target = getattr(target, attr, None)
                if target is None:
                    break
            if inspect.isclass(target):
                return target

    # Fall back to the fully-qualified ``name`` autodoc passes us
    # (e.g. ``angr.engines.procedure.ProcedureEngine.process_successors``).
    parts = name.split(".")
    for split in range(len(parts) - 1, 0, -1):
        try:
            module = importlib.import_module(".".join(parts[:split]))
        except ImportError:
            continue
        candidate: object | None = module
        for attr in parts[split:-1]:
            candidate = getattr(candidate, attr, None)
            if candidate is None:
                break
        if inspect.isclass(candidate):
            return candidate
    return None


# -- Re-exported objects: mark the duplicate copy as :no-index: -------------
# `angr/__init__.py` re-exports many symbols (e.g. ``from .sim_state import
# SimState``). Autodoc, with the package's ``__all__`` listing them, documents
# the same class on both the package page and the defining-module page.
# Sphinx then emits "duplicate object description" warnings and every
# cross-reference (``:class:`SimState```) has two valid targets.
#
# We want the canonical entry to live at the module where the symbol is
# actually *defined* (``angr.sim_state.SimState``), and the re-export to remain
# rendered on the parent page for discoverability while being excluded from the
# index/xref resolution. The hook below adds ``:no-index:`` to the directive
# header whenever the object's ``__module__`` differs from the module currently
# being autodoc'd.


def _patch_directive_header_for_reexports() -> None:
    """Inject ``:no-index:`` into autodoc directive headers for re-exported members.

    Sphinx 9 uses a dataclass-based renderer (``_directive_header_lines``) rather
    than the legacy ``Documenter.add_directive_header`` method, so we wrap the
    renderer and set ``options.no_index = True`` whenever the props' documenting
    module differs from the object's canonical ``__module__``.
    """
    from sphinx.ext.autodoc import _generate, _renderer

    original = _renderer._directive_header_lines

    def wrapped(*, autodoc_typehints, directive_name, is_final, options, props):
        canonical_module = getattr(props, "_obj___module__", None)
        documenting_module = getattr(props, "module_name", None)
        is_reexport = (
            directive_name
            in {
                "py:class",
                "py:function",
                "py:exception",
                "py:data",
                "py:type",
                "py:method",
                "py:property",
                "py:attribute",
            }
            and canonical_module
            and documenting_module
            and canonical_module != documenting_module
        )
        if is_reexport and not options.no_index:
            options.no_index = True
            try:
                yield from original(
                    autodoc_typehints=autodoc_typehints,
                    directive_name=directive_name,
                    is_final=is_final,
                    options=options,
                    props=props,
                )
            finally:
                options.no_index = False
            return
        yield from original(
            autodoc_typehints=autodoc_typehints,
            directive_name=directive_name,
            is_final=is_final,
            options=options,
            props=props,
        )

    _renderer._directive_header_lines = wrapped
    _generate._directive_header_lines = wrapped


_patch_directive_header_for_reexports()


# -- Global navigation sidebar ----------------------------------------------
# ``index.rst`` declares ``:maxdepth: 2``, but furo asks for the global toctree
# with an explicit ``maxdepth=-1``, and Sphinx lets an explicit argument
# override the option written in the directive. The full recursive API tree is
# therefore expanded into the sidebar of every one of the roughly 1,250 pages,
# which accounts for most of the build's wall clock and pushes Read the Docs
# past its build timeout on slower builders.
#
# Wrapping the context callable puts that choice back in this file. ``collapse``
# is the part that saves the time: bounding the depth alone still resolves and
# deep-copies the whole tree before pruning it, whereas collapsing stops sibling
# packages from being expanded at all. The depth is left unbounded on purpose,
# so the branch the reader is in is still shown in full. Page bodies, the search
# index and the object inventory are unaffected; only the sidebar changes.
#
# The priority has to be below furo's, which connects at the default of 500, so
# that the wrapper is installed before the theme reads it.


def limit_global_toctree(_app, pagename, _templatename, context, _doctree):
    """Bound the global toctree that the theme renders into the sidebar.

    Rendering the fully expanded tree into all 1245 pages dominates the build.
    The 1192 pages under api/ are the reason, so they keep a collapsed tree,
    which still expands the branch the reader is in. The 53 narrative pages are
    cheap enough to show every section's children.
    """
    original = context.get("toctree")
    if original is None:
        return

    is_api = pagename == "api" or pagename.startswith("api/")

    def bounded(**kwargs):
        if is_api:
            kwargs["maxdepth"] = -1
            kwargs["collapse"] = True
        else:
            kwargs["maxdepth"] = 2
            kwargs["collapse"] = False
        return original(**kwargs)

    context["toctree"] = bounded


def setup(app):
    app.connect("autodoc-skip-member", skip_inherited_undocumented)
    app.connect("html-page-context", limit_global_toctree, priority=400)
