import functools
import sys
import contextlib
from collections import defaultdict
from inspect import Signature
from typing import TYPE_CHECKING, TypeVar, Type, Generic, Callable, Optional

import progressbar
import logging
import time

from ..misc.plugins import PluginVendor, VendorPreset
from ..misc.ux import deprecated

if TYPE_CHECKING:
    from ..knowledge_base import KnowledgeBase
    from ..project import Project
    from typing_extensions import ParamSpec

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
            return "<AnalysisLogEntry %s>" % msg_str
        else:
            msg_str = repr(self.message)
            if len(msg_str) > 40:
                msg_str = msg_str[:36] + "..."
                if msg_str[0] in ('"', "'"):
                    msg_str += msg_str[0]
            return f"<AnalysisLogEntry {msg_str} with {self.exc_type.__name__}: {self.exc_value}>"


A = TypeVar("A", bound="Analysis")


class AnalysesHub(PluginVendor):
    """
    This class contains functions for all the registered and runnable analyses,
    """

    def __init__(self, project):
        super().__init__()
        self.project = project

    @deprecated()
    def reload_analyses(self):  # pylint: disable=no-self-use
        return

    def _init_plugin(self, plugin_cls: Type[A]) -> "AnalysisFactory[A]":
        return AnalysisFactory(self.project, plugin_cls)

    def __getstate__(self):
        s = super().__getstate__()
        return (s, self.project)

    def __setstate__(self, sd):
        s, self.project = sd
        super().__setstate__(s)

    def __getitem__(self, plugin_cls: "Type[A]") -> "AnalysisFactory[A]":
        return AnalysisFactory(self.project, plugin_cls)


class AnalysisFactory(Generic[A]):
    def __init__(self, project: "Project", analysis_cls: Type[A]):
        self._project = project
        self._analysis_cls = analysis_cls
        self.__doc__ = ""
        self.__doc__ += analysis_cls.__doc__ or ""
        self.__doc__ += analysis_cls.__init__.__doc__ or ""
        self.__call__.__func__.__signature__ = Signature.from_callable(analysis_cls.__init__)

    def prep(
        self,
        fail_fast=False,
        kb: Optional["KnowledgeBase"] = None,
        progress_callback: Optional[Callable] = None,
        show_progressbar: bool = False,
    ) -> Type[A]:
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


class StatusBar(progressbar.widgets.WidgetBase):
    """
    Implements a progressbar component for displaying raw text.
    """

    def __init__(self, width: Optional[int] = 40):
        super().__init__()
        self.status: str = ""
        self.width = width

    def __call__(self, progress, data, **kwargs):  # pylint:disable=unused-argument
        if self.width is None:
            return self.status
        if len(self.status) < self.width:
            return self.status.ljust(self.width, " ")
        else:
            return self.status[: self.width]


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
    :ivar progressbar.ProgressBar _progressbar: The progress bar object.
    """

    project: "Project" = None
    kb: "KnowledgeBase" = None
    _fail_fast = None
    _name = None
    errors = []
    named_errors = defaultdict(list)
    _progress_callback = None
    _show_progressbar = False
    _progressbar = None
    _statusbar: Optional[StatusBar] = None

    _PROGRESS_WIDGETS = [
        progressbar.Percentage(),
        " ",
        progressbar.Bar(),
        " ",
        progressbar.Timer(),
        " ",
        progressbar.ETA(),
        " ",
        StatusBar(),
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

        self._progressbar = progressbar.ProgressBar(widgets=Analysis._PROGRESS_WIDGETS, max_value=10000 * 100).start()
        self._statusbar = self._progressbar.widgets[-1]

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

            self._progressbar.update(percentage * 10000)

        if text is not None and self._statusbar is not None:
            self._statusbar.status = text

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
                self._progressbar.finish()
                # Remove the progressbar object so it will not be pickled
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
