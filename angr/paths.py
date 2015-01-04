import logging

l = logging.getLogger('angr.states')

class PathGenerator(object):
    def __init__(self, project):
        self._project = project

    def blank_path(self, state=None, *args, **kwargs):
        '''
        blank_point - Returns a start path, representing a clean start of symbolic execution.
        '''
        s = self._project.state_generator.blank_state(*args, **kwargs) if state is None else state
        return Path(self._project, s)

    def entry_point(self, state=None, *args, **kwargs):
        '''
        entry_point - Returns a path reflecting the processor when execution
                      reaches the binary's entry point.
        '''
        s = self._project.state_generator.entry_point(*args, **kwargs) if state is None else state
        return Path(self._project, s)

from .path import Path
