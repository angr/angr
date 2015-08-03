import sys
import contextlib
import functools

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


# function that produces unpredictable results that should appease pylint's
# static analysis and stop giving us those awful errors!!!!

def dummy_func(*args, **kwargs):
    return args + list(kwargs)

class Analyses(object):
    """
    This class contains functions for all the registered and runnable analyses,
    """

    def _analysis(self, analysis, *args, **kwargs):
        fail_fast = kwargs.pop('fail_fast', False)

        # Call __init__ of chosen analysis
        a = analysis(self._p, fail_fast, *args, **kwargs)

        return a

    def __init__(self, p):
        """
        Creates an Analyses object

        @param p: the angr.Project object
        @param analysis_results: the result cache
        """
        self._p = p

        # Appease pylint's static analysis
        self.CFG = dummy_func
        self.VFG = dummy_func
        self.Veritesting = dummy_func
        self.DDG = dummy_func
        self.CDG = dummy_func
        self.BackwardSlice = dummy_func
        self.BoyScout = dummy_func
        self.GirlScout = dummy_func

        for analysis_name,analysis in registered_analyses.items():
            partial = functools.partial(self._analysis, analysis)
            partial.__doc__ = analysis_name + ' analysis'
            if analysis.__doc__:
                partial.__doc__ += analysis.__doc__
            if analysis.__analysis_init__.__doc__:
                partial.__doc__ += analysis.__analysis_init__.__doc__
            setattr(self, analysis_name, partial)

    def __getstate__(self):
        return self._p

    def __setstate__(self, s):
        self.__init__(s)


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
