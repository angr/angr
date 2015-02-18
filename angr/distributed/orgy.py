from collections import deque, namedtuple
import os
import celery
import logging
from ..project import Project
from ..utils import bind_dict_as_funcs
from celery import group
from ..analysis import registered_analyses, RESULT_ERROR
from ..utils import is_executable, bind_dict_as_funcs
from .celery_config import CELERY_RESULT_SERIALIZER

l = logging.getLogger('project.Orgy')
l.setLevel(logging.INFO)

AnalysisJob = namedtuple("AnalysisJob", "analysis, args, kwargs")

app = celery.Celery()
app.config_from_object("angr.distributed.celery_config")

AnalysisResult = namedtuple("AnalysisResult", "binary, job, result, log, errors, named_errors")


@app.task
def run_analysis(binary, analysis_jobs, **project_options):
    l.info("Loading binary %s", binary)
    binary = str(binary)  # C code sometimes doesn't like utf.
    try:
        p = Project(binary, **project_options)
        ret = []
        for job in analysis_jobs:
            job = AnalysisJob(*job)  # Needed only in case of JSON. But doesn't hurt either way.
            try:
                a = getattr(p.analyses, job.analysis)(*job.args, **job.kwargs)
                ret.append(AnalysisResult(binary, job, a.result, a.log, a.errors, a.named_errors))
            except Exception as ex:
                l.error("Error %s", ex)
                ret.append(AnalysisResult(binary, job, RESULT_ERROR, [], ["Analysis failed: %s" % str(ex)], {}))
        return ret
    except Exception as ex:
        l.error("Error loading %s: %s", binary, ex)
        return [AnalysisResult(binary, job, RESULT_ERROR, [], ["Loading project failed: %s" % str(ex)], {}) for job in
                analysis_jobs]


class Multi():
    """
    Chain multiple analyses together using the same project instance without writing a new analysis.
    """

    def __init__(self, orgy):
        self.orgy = orgy
        self.list = []
        bind_dict_as_funcs(self, registered_analyses, self._add_analysis)

    def _add_analysis(self, name, value, *args, **kwargs):
        self.list.append(AnalysisJob(name, args, kwargs))
        self.orgy.multi = Multi(self.orgy)
        return self

    def __getstate__(self):
        return (self.orgy, self.list)

    def execute(self):
        return self.orgy._execute(self.list)

    def __setstate__(self, s):
        orgy, list = s
        self.__init__(orgy)
        self.list = s


class Analyses():
    """
    Run a single analysis (on multiple binaries) using celery.
    """

    def __init__(self, orgy):
        self.orgy = orgy
        bind_dict_as_funcs(self, registered_analyses, self._analysis)

    def _analysis(self, name, value, *args, **kwargs):
        for result in self.orgy._execute([AnalysisJob(name, args, kwargs)]):
            yield result[0]

    def __getstate__(self):
        return self.orgy

    def __setstate__(self, s):
        self.__init__(s)


class Orgy():
    """
    Class for doing great stuff in da clouds.
    """

    def merge(*orgies, **kwargs):
        """
        Merges two orgy instances into one, keeping bin specific options and paths.
        Can be called using an orgy instance or simply using Orgy.merge()
        :param orgies: The orgies to merge
        :param kwargs: If proj_options_bin_specific is set to False, project_options are simply merged
                        (instead of pinning them to binary paths)
        :return: The merged Orgy (parameters are not touched)
        """
        proj_options_bin_specific = True
        if "proj_options_bin_specific" in kwargs:
            proj_options_bin_specific = kwargs["proj_options_bin_specific"]

        merged_bins = []
        merged_options = {}
        merged_bin_specific_options = {}
        for orgy in orgies:

            if proj_options_bin_specific:
                bin_specific_options = dict(orgy.bin_specific_options)
                for bin in orgy.binaries:
                    bin_specific_options[bin] = orgy.project_options
                    if bin in orgy.bin_specific_options:
                        bin_specific_options[bin].update(orgy.bin_specific_options) # single foo overrides normal stuff
            else:
                bin_specific_options = orgy.bin_specific_options
                merged_options.update(orgy.project_options)
            merged_bin_specific_options.update(bin_specific_options)
            merged_bins += orgy.binaries
        return Orgy(merged_bins, bin_specific_options=merged_bin_specific_options, **merged_options)

    def __init__(self, paths, recursive=True, keep_relative_paths=False, bin_specific_options=None, **project_options):
        """
        Create multiple projects that can run analyses.
        :param paths: takes 1..n paths. If the path is a file, it will process the file, else every file in the folder.
        :param recursive: If True, every path is searched recursively for files to process.
        :param **project_options: kwargs to pass into every loaded project.
        """
        if not bin_specific_options:
            bin_specific_options = {}
        self.bin_specific_options = bin_specific_options
        self.project_options = project_options
        self.binaries = []
        if isinstance(paths, basestring):
            paths = [paths]

        for path in paths:
            if not keep_relative_paths:
                path = os.path.realpath(path)
            if is_executable(path):
                self.binaries.append(path)
            elif os.path.isdir(path):
                found = False
                if recursive:
                    for walkpath, walkdirs, walkfiles in os.walk(path):
                        for file in walkfiles:
                            joined = os.path.join(walkpath, file)
                            if is_executable(joined):
                                found = True
                                self.binaries.append(joined)
                        if not recursive:
                            break
                if not found:
                    l.warning("No executables found in path %s", path)
            else:
                raise Exception("Path %s is not loadable" % path)

        self.analyses = Analyses(self)
        self.multi = Multi(self)

    def _execute(self, analyses):
        analysis_funcs = []
        for binary in self.binaries:
            options = self.project_options
            if binary in self.bin_specific_options:
                options = dict(self.project_options)
                options.update(self.bin_specific_options[binary])
            analysis_funcs.append(run_analysis.s(binary, analyses, **options))
        results = group(analysis_funcs)()
        for results in results.iterate():  # can set propagate here for errors n stuff.
            if CELERY_RESULT_SERIALIZER == "json":  # JSON serializes NamedTuples as lists. Recover them.
                ret = []
                for result in results:
                    result[1] = AnalysisJob(*result[1])
                    ret.append(AnalysisResult(*result))
                yield ret
            else:
                yield results
