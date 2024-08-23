from __future__ import annotations
import angr


class IsProcessorFeaturePresent(angr.SimProcedure):
    def run(self, feature):  # pylint: disable=unused-argument,no-self-use,arguments-differ
        return 0  # we're dumb as shit!!!!
