# ruff: noqa: F401
from __future__ import annotations
import functools
import sys
import contextlib
from collections import defaultdict
from inspect import Signature
from typing import TYPE_CHECKING, TypeVar, Type, Generic, Optional
from collections.abc import Callable

import logging
import time
import typing

from rich import progress

from ..misc.plugins import PluginVendor, VendorPreset
from ..misc.ux import deprecated

if TYPE_CHECKING:
    from ..knowledge_base import KnowledgeBase
    from ..project import Project
    from typing_extensions import ParamSpec
    from .identifier import Identifier
    from .callee_cleanup_finder import CalleeCleanupFinder
    from .vsa_ddg import VSA_DDG
    from .cdg import CDG
    from .bindiff import BinDiff
    from .cfg import CFGEmulated
    from .cfg import CFBlanket
    from .cfg import CFG
    from .cfg import CFGFast
    from .static_hooker import StaticHooker
    from .ddg import DDG
    from .congruency_check import CongruencyCheck
    from .reassembler import Reassembler
    from .backward_slice import BackwardSlice
    from .binary_optimizer import BinaryOptimizer
    from .vfg import VFG
    from .loopfinder import LoopFinder
    from .disassembly import Disassembly
    from .veritesting import Veritesting
    from .code_tagging import CodeTagging
    from .boyscout import BoyScout
    from .variable_recovery import VariableRecoveryFast
    from .variable_recovery import VariableRecovery
    from .reaching_definitions import ReachingDefinitionsAnalysis
    from .complete_calling_conventions import CompleteCallingConventionsAnalysis
    from .decompiler.clinic import Clinic
    from .propagator import PropagatorAnalysis
    from .calling_convention import CallingConventionAnalysis
    from .decompiler.decompiler import Decompiler
    from .xrefs import XRefsAnalysis

    AnalysisParams = ParamSpec("AnalysisParams")

l = logging.getLogger(name=__name__)


class AnalysisLogEntry:
    def __init__(self, message, exc_info=False):
        if exc_info:
            (e_type, value, traceback) = sys.exc_info()
            self.exc_type = e_type
            self.exc_value = value
            self.exc_traceback = traceback
        else:
            self.exc_type = None
            self.exc_value = None
            self.exc_traceback = None

        self.message = message

    def __getstate__(self):
        return (
            str(self.__dict__.get("exc_type")),
            str(self.__dict__.get("exc_value")),
            str(self.__dict__.get("exc_traceback")),
            self.message,
        )

    def __setstate__(self, s):
        self.exc_type, self.exc_value, self.exc_traceback, self.message = s

    def __repr__(self):
        if self.exc_type is None:
            msg_str = repr(self.message)
            if len(msg_str) > 70:
                msg_str = msg_str[:66] + "..."
                if msg_str[0] in ('"', "'"):
                    msg_str += msg_str[0]
            return f"<AnalysisLogEntry {msg_str}>"
        msg_str = repr(self.message)
        if len(msg_str) > 40:
            msg_str = msg_str[:36] + "..."
            if msg_str[0] in ('"', "'"):
                msg_str += msg_str[0]
        return f"<AnalysisLogEntry {msg_str} with {self.exc_type.__name__}: {self.exc_value}>"


A = TypeVar("A", bound="Analysis")


class AnalysesHub(PluginVendor[A]):
    """
    This class contains functions for all the registered and runnable analyses,
    """

    def __init__(self, project):
        super().__init__()
        self.project = project

    @deprecated()
    def reload_analyses(self):  # pylint: disable=no-self-use
        return

    def _init_plugin(self, plugin_cls: type[A]) -> AnalysisFactory[A]:
        return AnalysisFactory(self.project, plugin_cls)

    def __getstate__(self):
        s = super().__getstate__()
        return (s, self.project)

    def __setstate__(self, sd):
        s, self.project = sd
        super().__setstate__(s)

    def __getitem__(self, plugin_cls: type[A]) -> AnalysisFactory[A]:
        return AnalysisFactory(self.project, plugin_cls)


class KnownAnalysesPlugin(typing.Protocol):
    Identifier: type[Identifier]
    CalleeCleanupFinder: type[CalleeCleanupFinder]
    VSA_DDG: type[VSA_DDG]
    CDG: type[CDG]
    BinDiff: type[BinDiff]
    CFGEmulated: type[CFGEmulated]
    CFB: type[CFBlanket]
    CFBlanket: type[CFBlanket]
    CFG: type[CFG]
    CFGFast: type[CFGFast]
    StaticHooker: type[StaticHooker]
    DDG: type[DDG]
    CongruencyCheck: type[CongruencyCheck]
    Reassembler: type[Reassembler]
    BackwardSlice: type[BackwardSlice]
    BinaryOptimizer: type[BinaryOptimizer]
    VFG: type[VFG]
    LoopFinder: type[LoopFinder]
    Disassembly: type[Disassembly]
    Veritesting: type[Veritesting]
    CodeTagging: type[CodeTagging]
    BoyScout: type[BoyScout]
    VariableRecoveryFast: type[VariableRecoveryFast]
    VariableRecovery: type[VariableRecovery]
    ReachingDefinitions: type[ReachingDefinitionsAnalysis]
    CompleteCallingConventions: type[CompleteCallingConventionsAnalysis]
    Clinic: type[Clinic]
    Propagator: type[PropagatorAnalysis]
    CallingConvention: type[CallingConventionAnalysis]
    Decompiler: type[Decompiler]
    XRefs: type[XRefsAnalysis]


class AnalysesHubWithDefault(AnalysesHub, KnownAnalysesPlugin):
    """
    This class has type-hinting for all built-in analyses plugin
    """


class AnalysisFactory(Generic[A]):
    def __init__(self, project: Project, analysis_cls: type[A]):
        self._project = project
        self._analysis_cls = analysis_cls
        self.__doc__ = ""
        self.__doc__ += analysis_cls.__doc__ or ""
        self.__doc__ += analysis_cls.__init__.__doc__ or ""
        self.__call__.__func__.__signature__ = Signature.from_callable(analysis_cls.__init__)

    def prep(
        self,
        fail_fast=False,
        kb: KnowledgeBase | None = None,
        progress_callback: Callable | None = None,
        show_progressbar: bool = False,
    ) -> type[A]:
        @functools.wraps(self._analysis_cls.__init__)
        def wrapper(*args, **kwargs):
            oself = object.__new__(self._analysis_cls)
            oself.named_errors = defaultdict(list)
            oself.errors = []
            oself.log = []

            oself._fail_fast = fail_fast
            oself._name = self._analysis_cls.__name__
            oself.project = self._project
            oself.kb = kb or self._project.kb
            oself._progress_callback = progress_callback

            oself._show_progressbar = show_progressbar
            oself.__init__(*args, **kwargs)
            return oself

        return wrapper  # type: ignore

    def __call__(self, *args, **kwargs) -> A:
        fail_fast = kwargs.pop("fail_fast", False)
        kb = kwargs.pop("kb", self._project.kb)
        progress_callback = kwargs.pop("progress_callback", None)
        show_progressbar = kwargs.pop("show_progressbar", False)

        w = self.prep(
            fail_fast=fail_fast, kb=kb, progress_callback=progress_callback, show_progressbar=show_progressbar
        )

        r = w(*args, **kwargs)
        # clean up so that it's always pickleable
        r._progressbar = None
        return r


class Analysis:
    """
    This class represents an analysis on the program.

    :ivar project:  The project for this analysis.
    :type project:  angr.Project
    :ivar KnowledgeBase kb: The knowledgebase object.
    :ivar _progress_callback: A callback function for receiving the progress of this analysis. It only takes
                                        one argument, which is a float number from 0.0 to 100.0 indicating the current
                                        progress.
    :ivar bool _show_progressbar: If a progressbar should be shown during the analysis. It's independent from
                                    _progress_callback.
    :ivar progress.Progress _progressbar: The progress bar object.
    """

    project: Project
    kb: KnowledgeBase
    _fail_fast: bool
    _name: str
    errors = []
    named_errors = defaultdict(list)
    _progress_callback = None
    _show_progressbar = False
    _progressbar = None
    _task = None

    _PROGRESS_WIDGETS = [
        progress.TaskProgressColumn(),
        progress.BarColumn(),
        progress.TextColumn("Elapsed Time:"),
        progress.TimeElapsedColumn(),
        progress.TextColumn("Time:"),
        progress.TimeRemainingColumn(),
        progress.TextColumn("{task.description}"),
    ]

    @contextlib.contextmanager
    def _resilience(self, name=None, exception=Exception):
        try:
            yield
        except exception:  # pylint:disable=broad-except
            if self._fail_fast:
                raise
            else:
                error = AnalysisLogEntry("exception occurred", exc_info=True)
                l.error("Caught and logged %s with resilience: %s", error.exc_type.__name__, error.exc_value)
                if name is None:
                    self.errors.append(error)
                else:
                    self.named_errors[name].append(error)

    def _initialize_progressbar(self):
        """
        Initialize the progressbar.
        :return: None
        """

        self._progressbar = progress.Progress(*self._PROGRESS_WIDGETS)
        self._task = self._progressbar.add_task(total=100, description="")

        self._progressbar.start()

    def _update_progress(self, percentage, text=None, **kwargs):
        """
        Update the progress with a percentage, including updating the progressbar as well as calling the progress
        callback.

        :param float percentage:    Percentage of the progressbar. from 0.0 to 100.0.
        :param kwargs:              Other parameters that will be passed to the progress_callback handler.
        :return: None
        """

        if self._show_progressbar:
            if self._progressbar is None:
                self._initialize_progressbar()

            self._progressbar.update(self._task, completed=percentage)

        if text is not None and self._progressbar:
            self._progressbar.update(self._task, description=text)

        if self._progress_callback is not None:
            self._progress_callback(percentage, text=text, **kwargs)  # pylint:disable=not-callable

    def _finish_progress(self):
        """
        Mark the progressbar as finished.
        :return: None
        """

        if self._show_progressbar:
            if self._progressbar is None:
                self._initialize_progressbar()
            if self._progressbar is not None:
                self._progressbar.update(self._task, completed=100)
                self._progressbar.stop()
                self._progressbar = None

        if self._progress_callback is not None:
            self._progress_callback(100.0)  # pylint:disable=not-callable

    @staticmethod
    def _release_gil(ctr, freq, sleep_time=0.001):
        """
        Periodically calls time.sleep() and releases the GIL so other threads (like, GUI threads) have a much better
        chance to be scheduled, and other critical components (like the GUI) can be kept responsiveness.

        This is, of course, a hack before we move all computational intensive tasks to pure C++ implementations.

        :param int ctr:     A number provided by the caller.
        :param int freq:    How frequently time.sleep() should be called. time.sleep() is called when ctr % freq == 0.
        :param sleep_time:  Number (or fraction) of seconds to sleep.
        :return:            None
        """

        if ctr != 0 and ctr % freq == 0:
            time.sleep(sleep_time)

    def __getstate__(self):
        d = dict(self.__dict__)
        if "_progressbar" in d:
            del d["_progressbar"]
        if "_progress_callback" in d:
            del d["_progress_callback"]
        if "_statusbar" in d:
            del d["_statusbar"]
        return d

    def __setstate__(self, state):
        self.__dict__.update(state)

    def __repr__(self):
        return f"<{self._name} Analysis Result at {id(self):#x}>"


default_analyses = VendorPreset()
AnalysesHub.register_preset("default", default_analyses)
