import sys
import contextlib

RESULT_ERROR = "An error occured"
RESULT_NONE = "No result"

class AnalysisLogEntry(object):
    def __init__(self, message, exc_info=False):
        if exc_info:
            (e_type, value, traceback) = sys.exc_info()
            self.exc_type = e_type
            self.exc_value = value
            self.exc_traceback = traceback
        self.message = message

    def __getstate__(self):
        return str(self.__dict__.get("exc_type")), \
               str(self.__dict__.get("exc_value")), \
               str(self.__dict__.get("exc_traceback"))

    def __setstate__(self, s):
        self.exc_type, self.exc_value, self.exc_traceback = s


class AnalysisMeta(type):
    """
    Whenever Analaysis is subclassed, make sure we know about it.
    """

    def __new__(mcs, name, bases, d):
        t = type.__new__(mcs, name, bases, d)
        if name != 'Analysis':
            chosen_name = d.get('__analysis_name__', name)
            registered_analyses[chosen_name] = (t.__module__, name)
        return t


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
        self._p = p
        self._registered_analyses = {}
        self.reload_analyses()

    def reload_analyses(self):
        for analysis_name, (module_name, key) in registered_analyses.iteritems():
            module = reload(sys.modules[module_name])
            analysis = getattr(module, key)
            self._registered_analyses[analysis_name] = self._specialize_analysis(analysis)

    def _specialize_analysis(self, analysis):
        @staticmethod
        def __new__(cls, *args, **kwargs): # pylint: disable=unused-argument
            fail_fast = kwargs.pop('fail_fast', False)

            oself = object.__new__(cls)
            oself.named_errors = {}
            oself.errors = []
            oself.log = []

            oself._fail_fast = fail_fast
            oself._p = self._p

            oself.result = RESULT_NONE
            return oself

        analysis.__new__ = __new__
        return analysis

    def __getstate__(self):
        return self._p

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


registered_analyses = {}

class Analysis(object):
    # pylint: disable=no-member
    __metaclass__ = AnalysisMeta
    def post_load(self):
        pass

    @contextlib.contextmanager
    def _resilience(self, name=None, exception=Exception):
        try:
            yield
        except exception:  # pylint:disable=broad-except
            if self._fail_fast:
                raise
            else:
                error = AnalysisLogEntry("exception occurred", exc_info=True)
                if name is None:
                    self.errors.append(error)
                else:
                    self.named_errors[name] = error

    def _log(self, event):
        '''

        :return:
        '''
        # TODO: This function is not properly designed nor implemented!
        le = AnalysisLogEntry(event)
        self.log.append(le)

    def _checkpoint(self):
        pass

    def __repr__(self):
        return '<%s Analysis Result at %#x>' % id(self)
