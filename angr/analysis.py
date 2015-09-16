import sys
import contextlib
from collections import defaultdict

import logging
l = logging.getLogger('angr.analysis')

registered_analyses = {}

def register_analysis(analysis, name):
    registered_analyses[name] = analysis

class AnalysisLogEntry(object):
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

class Analyses(object):
    """
    This class contains functions for all the registered and runnable analyses,
    """
    def __init__(self, p):
        """
        Creates an Analyses object

        @param p: the angr.Project object
        @param analysis_results: the result cache
        """
        self.project = p
        self._registered_analyses = {}
        self.reload_analyses()

    def reload_analyses(self):
        for analysis_name, analysis in registered_analyses.iteritems():
            self._registered_analyses[analysis_name] = self._specialize_analysis(analysis, analysis_name)

    def _specialize_analysis(self, analysis, name):
        def make_analysis(*args, **kwargs): # pylint: disable=unused-argument
            fail_fast = kwargs.pop('fail_fast', False)

            oself = analysis.__new__(analysis)
            oself.named_errors = {}
            oself.errors = []
            oself.log = []

            oself._fail_fast = fail_fast
            oself._name = name
            oself.project = self.project

            oself.__init__(*args, **kwargs)
            return oself

        make_analysis.__doc__ = analysis.__init__.__doc__
        return make_analysis

    def __getstate__(self):
        return self.project

    def __setstate__(self, s):
        self.__init__(s)

    def __getattr__(self, k):
        r = super(Analyses, self).__getattribute__('_registered_analyses')
        if k == '_registered_analyses':
            return r
        if k in r:
            return r[k]
        return super(Analyses, self).__getattribute__(k)

    def __dir__(self):
        return dir(Analyses) + self._registered_analyses.keys()


class Analysis(object):
    project = None
    _fail_fast = None
    _name = None
    errors = []
    named_errors = defaultdict(list)

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

    def __repr__(self):
        return '<%s Analysis Result at %#x>' % (self._name, id(self))
