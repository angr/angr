"""
A file containing utility functions for angr
"""
import os
from cle import ArchInfo
from cle import UnknownFormatException
import logging

l = logging.getLogger("angr.utils")

def is_executable(file):
    """
    Returns true if file is recognized as executable that can be loaded as Project in angr
    :return: True if the thing is executable, else false.
    """
    if os.path.isfile(file):
        try:
            ArchInfo(file)
            return True
        except UnknownFormatException as ex:
            l.d("%s not an executable: %s", file, ex)
    return False


def bind_dict_as_funcs(obj, dict, func):
    """
    Binds every key in the given dict as one function to an object.
    If this function is then called, the func parameter is called and the key and value are passed in.
    """

    def bind(key, value):
        """
        Create closure. Could use partial instead.
        see http://stackoverflow.com/questions/233673/lexical-closures-in-python
        """

        def bound(*args, **kwargs):
            """
            Runs this analysis, providing the given args and kwargs to it.
            If this analysis (with these options) has already been run, it simply returns
            the previously-run analysis.

            @param cache: if the result should be cached (default true)
            @param args: arguments to pass to the analysis
            @param kwargs: keyword arguments to pass to the analysis
            @returns the analysis results (an instance of a subclass of the Analysis object)
            """
            return func(key, value, *args, **kwargs)
        return bound

    for key, value in dict.iteritems():
        setattr(obj, key, bind(key, value))