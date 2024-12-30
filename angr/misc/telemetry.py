from __future__ import annotations
from typing import TYPE_CHECKING
import enum

try:
    from opentelemetry.trace import get_current_span, Status, StatusCode, Tracer, get_tracer as _get_tracer
except ImportError:
    if TYPE_CHECKING:
        raise

    # pylint: disable=missing-class-docstring,unused-argument
    class Status:
        def __init__(self, *args, **kwargs):
            pass

    class StatusCode(enum.Enum):
        OK = 0
        UNSET = 1
        ERROR = 2

    class Tracer:
        @staticmethod
        def start_as_current_span(*args, **kwargs):
            def inner(f):
                return f

            return inner

        @staticmethod
        def get_current_span(*args, **kwargs):
            return Span()

    def _get_tracer(*args, **kwargs):
        return Tracer()

    class Span:
        @staticmethod
        def set_attribute(*args, **kwargs):
            pass

        @staticmethod
        def add_event(*args, **kwargs):
            pass

    get_current_span = Tracer.get_current_span


from angr import __version__

__all__ = ["Status", "StatusCode", "get_current_span", "get_tracer"]


def get_tracer(name: str) -> Tracer:
    return _get_tracer(name, __version__)
