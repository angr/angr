import sys
import contextlib
from collections import defaultdict
from inspect import Signature
import progressbar
import logging
import time
from typing import TYPE_CHECKING

from ..misc.plugins import PluginVendor, VendorPreset
from ..misc.ux import deprecated
from ..errors import AngrAnalysisError

if TYPE_CHECKING:
    from ..knowledge_base import KnowledgeBase

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
        return str(self.__dict__.get("exc_type")), \
               str(self.__dict__.get("exc_value")), \
               str(self.__dict__.get("exc_traceback")), \
               self.message

    def __setstate__(self, s):
        self.exc_type, self.exc_value, self.exc_traceback, self.message = s

    def __repr__(self):
        if self.exc_type is None:
            msg_str = repr(self.message)
            if len(msg_str) > 70:
                msg_str = msg_str[:66] + '...'
                if msg_str[0] in ('"', "'"):
                    msg_str += msg_str[0]
            return '<AnalysisLogEntry %s>' % msg_str
        else:
            msg_str = repr(self.message)
            if len(msg_str) > 40:
                msg_str = msg_str[:36] + '...'
                if msg_str[0] in ('"', "'"):
                    msg_str += msg_str[0]
            return '<AnalysisLogEntry %s with %s: %s>' % (msg_str, self.exc_type.__name__, self.exc_value)


class AnalysesHub(PluginVendor):
    """
    This class contains functions for all the registered and runnable analyses,
    """
    def __init__(self, project):
        super(AnalysesHub, self).__init__()
        self.project = project

    @deprecated()
    def reload_analyses(self): # pylint: disable=no-self-use
        return

    def _init_plugin(self, plugin_cls):
        return AnalysisFactory(self.project, plugin_cls)

    def __getstate__(self):
        s = super(AnalysesHub, self).__getstate__()
        return (s, self.project)

    def __setstate__(self, sd):
        s, self.project = sd
        super(AnalysesHub, self).__setstate__(s)


class AnalysisFactory:
    def __init__(self, project, analysis_cls):
        self._project = project
        self._analysis_cls = analysis_cls
        self.__doc__ = ''
        self.__doc__ += analysis_cls.__doc__ or ''
        self.__doc__ += analysis_cls.__init__.__doc__ or ''
        self.__call__.__func__.__signature__ = Signature.from_callable(analysis_cls.__init__)

    def __call__(self, *args, **kwargs):
        fail_fast = kwargs.pop('fail_fast', False)
        kb = kwargs.pop('kb', self._project.kb)
        progress_callback = kwargs.pop('progress_callback', None)
        show_progressbar = kwargs.pop('show_progressbar', False)

        oself = object.__new__(self._analysis_cls)
        oself.named_errors = {}
        oself.errors = []
        oself.log = []

        oself._fail_fast = fail_fast
        oself._name = self._analysis_cls.__name__
        oself.project = self._project
        oself.kb = kb
        oself._progress_callback = progress_callback

        if oself._progress_callback is not None:
            if not hasattr(oself._progress_callback, '__call__'):
                raise AngrAnalysisError('The "progress_callback" parameter must be a None or a callable.')

        oself._show_progressbar = show_progressbar
        oself.__init__(*args, **kwargs)
        return oself


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

    project = None # type: 'angr.Project'
    kb: 'KnowledgeBase' = None
    _fail_fast = None
    _name = None
    errors = []
    named_errors = defaultdict(list)
    _progress_callback = None
    _show_progressbar = False
    _progressbar = None

    _PROGRESS_WIDGETS = [
        progressbar.Percentage(),
        ' ',
        progressbar.Bar(),
        ' ',
        progressbar.Timer(),
        ' ',
        progressbar.ETA()
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

        self._progressbar = progressbar.ProgressBar(widgets=Analysis._PROGRESS_WIDGETS, maxval=10000 * 100).start()

    def _update_progress(self, percentage, **kwargs):
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

        if self._progress_callback is not None:
            self._progress_callback(percentage, **kwargs)  # pylint:disable=not-callable

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

        if ctr % freq == 0:
            time.sleep(sleep_time)

    def __repr__(self):
        return '<%s Analysis Result at %#x>' % (self._name, id(self))


default_analyses = VendorPreset()
AnalysesHub.register_preset('default', default_analyses)
