import sys
import contextlib
import utils

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
        return str(self.exc_type), str(self.exc_value), str(self.exc_traceback)

    def __setstate__(self, s):
        self.exc_type, self.exc_value, self.exc_traceback = s


class AnalysisMeta(type):
    """
    This metaclass is Yan being too clever with analysis creation, and will probably
    come back to bite us in the ass. Basically, it replaces the Analysis' __init__
    with the base __init__, which yanks the project and the fail_fast setting out
    from the arguments. This lets us avoid the three worse alternatives:

        1. override __new__, which doesn't work because you still can't pull the
           args out
        2. make the analyses implement something other than __init__, which will
           reduce pylint's effectiveness in regards to the defined-outside-init stuff
        3. make the analyses handle the project and fail_fast args and pass them on
           to Analysis.__init__
    """

    def __new__(mcs, name, bases, d):
        if name == 'Analysis':
            d['__init__'] = d['__core_init__']
        else:
            d['__analysis_init__'] = d['__init__']
            del d['__init__']

        t = type.__new__(mcs, name, bases, d)
        if name != 'Analysis':
            registered_analyses[d.get('__analysis_name__', name)] = t
        return t



class Analyses(object):
    """
    This class contains functions for all the registered and runnable analyses,
    """

    def _analysis(self, key, val, *args, **kwargs):
        name = key
        analysis = val
        fail_fast = kwargs.pop('fail_fast', False)
        cache = kwargs.pop('cache', True)
        key = (name, args, tuple(sorted(kwargs.items())))
        if key in self._analysis_results:
            return self._analysis_results[key]

        # Call __init__ of chosen analysis
        a = analysis(self._p, fail_fast, *args, **kwargs)
        if cache:
            self._analysis_results[key] = a
        return a

    def __init__(self, p, analysis_results):
        """
        Creates an Analyses object

        @param p: the angr.Project object
        @param analysis_results: the result cache
        """
        self._p = p
        self._analysis_results = analysis_results
        utils.bind_dict_as_funcs(self, registered_analyses, self._analysis)

    def __getstate__(self):
        p = self._p
        analysis_results = self._analysis_results
        #d = self.__dict__
        #try:
        #    self.__dict__ = None
        return p, analysis_results
        #finally:
            #self.__dict__ = d

    def __setstate__(self, s):
        p, analysis_results = s
        self.__init__(p, analysis_results)


class AnalysisResults(object):
    """
    An AnalysisResults object provides attribute-level access to analysis results.
    This is strictly for convenience in iPython, and should not be used in scripts.

    When queried for attribute "A", this object does the following:

        1. It looks at project._analysis_results for the first analysis named "A".
           If such an analysis is present, it returns it.
        2. Otherwise, it runs analysis "A" with no arguments, and returns it.
    """

    def __init__(self, p):
        """
        Creates an AnalysisResults object.

        @param p: the angr.Project object
        """
        self._p = p

    def __dir__(self):
        d = set()
        d |= set(registered_analyses.keys())
        d |= set(k[0] for k in self._p._analysis_results)

        return sorted(tuple(d))

    def __getattr__(self, a):
        for (name, _, _), analysis in self._p._analysis_results.iteritems():
            if name == a:
                return analysis

        return self._p.analyses.__dict__[a]()

    def __getstate__(self):
        return self._p

    def __setstate__(self, p):
        self._p = p


registered_analyses = {}


class Analysis(object):
    __metaclass__ = AnalysisMeta

    def __core_init__(self, project, fail_fast, *args, **kwargs):
        # pylint:disable=attribute-defined-outside-init
        self.named_errors = {}
        self.errors = []
        self.log = []

        self._fail_fast = fail_fast
        self._p = project

        self.result = RESULT_NONE

        if kwargs.pop('do_analysis', True):
            self.__analysis_init__(*args, **kwargs)  # pylint:disable=no-member

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

    def copy(self):
        return self.__class__(self._p, self._fail_fast, do_analysis=False)
