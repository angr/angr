import logging
from collections import defaultdict

import simuvex

l = logging.getLogger('simuvex.plugins.transition_tracker')


def is_power_of_two(n):
    return (n & (n - 1) == 0) and (n != 0)


class SimTransitionTracker(simuvex.SimStatePlugin):
    def __init__(self, initial_global_transition_counts=defaultdict(int),
                 initial_local_transition_counts=defaultdict(int),
                 initial_local_score=0, initial_local_score_alternative=0):

        super(SimTransitionTracker, self).__init__()

        self.global_transition_counts = initial_global_transition_counts
        self.local_transition_counts = initial_local_transition_counts
        self.local_transition_score = initial_local_score
        self.local_transition_score_alternative = initial_local_score_alternative

    def score_transition(self, t):
        count = self.local_transition_counts[t]
        return 0 if count < 2 or is_power_of_two(count) else count

    def register_transition(self, t):

        self.global_transition_counts[t] += 1

        self.local_transition_score -= self.score_transition(t)
        self.local_transition_counts[t] += 1
        self.local_transition_score += self.score_transition(t)

        if self.global_transition_counts[t] == 1:
            # Globally unique transition => Reset score to ensure this path is run
            self.local_transition_score_alternative = 0
            print "Found globally unique transition {} -> {}".format(t[0], t[1])
        elif self.local_transition_counts[t] == 1:
            # Locally unique transition, don't punish the path for it
            pass
        else:
            self.local_transition_score_alternative += 1

    def copy(self):
        return SimTransitionTracker(self.global_transition_counts,
                                    self.local_transition_counts.copy(),
                                    self.local_transition_score, self.local_transition_score_alternative)

    def set_state(self, s):
        super(SimTransitionTracker, self).set_state(s)
