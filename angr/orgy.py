import concurrent.futures
import pickle
import os

from .project import Project

import logging
l = logging.getLogger('project.Orgy')

import ana

def _run_one(p, analyses):
    for a in analyses:
        p.analyze(a)
    return p

class Orgy(object):
    def __init__(self, directory, save_dir='pickles'):
        self._save_dir = save_dir
        self._dir = directory
        self.projects = { }
        self._full_list = os.listdir(self._dir)
        ana.set_dl(self._save_dir + '/orgy')

        self.load()

    def run(self, analyses, background=False):
        if background:
            with concurrent.futures.ProcessPoolExecutor() as executor:
                futures = { }
                for f,p in self.projects.items():
                    completed = set(a for a,_,_ in p._analysis_results)
                    if len(set(analyses) - completed) > 0:
                        futures[executor.submit(_run_one, p, analyses)] = f

                for future in concurrent.futures.as_completed(futures):
                    self.projects[futures[future]] = future.result()
        else:
            for p in self.projects.values():
                _run_one(p, analyses)

    def _load_one(self, e):
        try:
            return pickle.load(open(self._save_dir + '/' + e + '/project.p'))
        except IOError: #pylint:disable=broad-except
            l.warning("Unable to load fucker %s (IOError)", e)

        try:
            return Project(self._dir + '/' + e)
        except (AngrError, cle.CLException):
            l.warning("Unable to create fucker %s", e, exc_info=True)

    def load(self):
        for e in self._full_list:
            self.projects[e] = self._load_one(e)

    def _save_one(self, e):
        try:
            pickle.dump(self.projects[e], open(self._save_dir + '/' + e, 'w'), pickle.HIGHEST_PROTOCOL)
        except Exception: #pylint:disable=broad-except
            l.warning("Unable to save fucker %s", e, exc_info=True)

    def save(self):
        for e in self._full_list:
            self._save_one(e)

from .errors import AngrError
import cle
