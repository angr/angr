import logging

from ..surveyor import Surveyor

l = logging.getLogger("angr.surveyors.executor")

class Executor(Surveyor):
    '''
    This class handles pure concrete execution related issues.
    No state splitting is ever allowed.
    '''
    def __init__(self, project, start, final_addr=None, \
                 pickle_paths=None, max_run=50000):
        Surveyor.__init__(self, project, start=start, pickle_paths=pickle_paths)
        self._project = project
        self._final_addr = final_addr
        self._max_run = max_run
        self._done = False
        self._error_occured = False
        self._run_counter = 0
        self.found = []

    @property
    def done(self):
        if self.error_occured:
            return True
        if len(self.active) > 1:
            raise Exception("We have more than one path in concrete mode." + \
                            " Something is wrong.")
        elif len(self.active) == 0:
            return True
        else:
            path = self.active[0]
            if path.state is not None and \
                    path.state.se.is_true(path.state.ip == self._final_addr):
                self.found.append(self.active[0])
                self.active = []
                return True
        return False

    @property
    def error_occured(self):
        if len(self.active) == 0:
            # The path ends before get to the target
            return True
        elif self._run_counter > self._max_run:
            return True
        return False

    @property
    def last_state(self):
        if self.done or self.error_occured:
            return None
        return self.active[0].state

    def tick(self):
        self._run_counter += 1
        Surveyor.tick(self)

        if len(self.active) > 0:
             l.debug("Ran %d run, %s is active...", self._run_counter, self.active[0].previous_run)
        else:
             l.debug("Ran %d run, no more actives...", self._run_counter)

    def __repr__(self):
        return "%d active, %d spilled, %d found, %d deadended, %d errored, %d unconstrained" % (
            len(self.active), len(self.spilled), len(self.found), len(self.deadended), len(self.errored), len(self.unconstrained))


from . import all_surveyors
all_surveyors['Executor'] = Executor
