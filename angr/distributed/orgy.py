from collections import deque, namedtuple
import os
import celery
import logging
from ..project import Project
from ..utils import bind_dict_as_funcs
from celery import group, task
from ..analysis import registered_analyses, RESULT_ERROR
from ..utils import is_executable, bind_dict_as_funcs
import angr

l = logging.getLogger('project.Orgy')
l.setLevel(logging.INFO)

AnalysisJob = namedtuple("AnalysisJob", "analysis, args, kwargs")

app = celery.Celery()
app.config_from_object("angr.distributed.celery_config")

AnalysisResult = namedtuple("AnalysisResult", "binary, job, result, log, errors, named_errors")


@app.task
def run_analysis(binary, analysis_jobs):
    l.info("Loading binary %s", binary)
    try:
        p = Project(binary)
        ret = []
        for job in analysis_jobs:
            job = AnalysisJob(*job)
            try:
                a = getattr(p.analyses, job.analysis)(*job.args, **job.kwargs)
                ret.append(AnalysisResult(binary, job, a.result, a.log, a.errors, a.named_errors))
            except Exception as ex:
                l.error("Error %s - %s", ex, ex.__traceback__())
                ret.append(AnalysisResult(binary, job, RESULT_ERROR, [], ["Analysis failed: %s" % str(ex)], {}))
        return ret
    except Exception as ex:
        l.error("Error loading %s: %s", binary, ex)
        return [AnalysisResult(binary, job, RESULT_ERROR, [], ["Loading project failed: %s" % str(ex)], {}) for job in
                analysis_jobs]


class Multi():
    def __init__(self, orgy):
        self.orgy = orgy
        self.list = []
        bind_dict_as_funcs(self, registered_analyses, self._add_analysis)

    def _add_analysis(self, name, value, *args, **kwargs):
        self.list.append(AnalysisJob(name, args, kwargs))
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
    def __init__(self, paths, recursive=False, **project_options):
        """
        Create multiple projects that can run analyses.
        :param paths: takes 1..n paths. If the path is a file, it will process the file, else every file in the folder.
        :param recursive: If True, every path is searched recursively for files to process.
        :param **project_options: kwargs to pass into every loaded project.
        """
        self.binaries = []
        if isinstance(paths, basestring):
            paths = [paths]

        for path in paths:
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
        results = group([run_analysis.s(x, analyses) for x in self.binaries])()
        for result in results.iterate():  # can set propagate here for errors n stuff.
            yield [AnalysisResult(*x) for x in result]


setattr(angr, "Orgy", Orgy)