from __future__ import annotations

from angr.errors import AngrError


class DecompilationEditError(AngrError):
    """Base class for every failure raised by the decompilation edit layer."""


class FunctionNotFoundError(DecompilationEditError):
    """No function matches the given address or name."""


class AmbiguousFunctionError(DecompilationEditError):
    """More than one function matches the given name. Renames make this reachable."""

    def __init__(self, message: str, addresses: list[int] | None = None):
        super().__init__(message)
        self.addresses: list[int] = addresses if addresses is not None else []


class VariableNotFoundError(DecompilationEditError):
    """
    No variable in the decompilation matches the given display name.

    ``candidates`` carries the names that *are* available, so a caller that failed can correct
    itself without a second round trip.
    """

    def __init__(self, message: str, candidates: list[str] | None = None):
        super().__init__(message)
        self.candidates: list[str] = candidates if candidates is not None else []


class NotDecompiledError(DecompilationEditError):
    """The function has no cached decompilation, so there is nothing to edit."""


class InvalidNameError(DecompilationEditError):
    """The requested name is not a usable identifier."""


class NameCollisionError(DecompilationEditError):
    """The requested name is already bound to a different function, variable, or label."""

    def __init__(self, message: str, existing: int | str | None = None):
        super().__init__(message)
        self.existing = existing


class TypeParseError(DecompilationEditError):
    """A C type declaration or function signature could not be parsed."""


class UnsupportedEditError(DecompilationEditError):
    """The requested edit is not supported for this kind of target."""
