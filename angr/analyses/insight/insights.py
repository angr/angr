from __future__ import annotations

from .base import InsightBase


class Insights(InsightBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.args = args
        self.kwargs = kwargs

        self.analyze()

    def analyze(self):
        # run all known insights and collect their results
        ins = self.project.analyses.Insight_Switches(*self.args, **self.kwargs)
        self.kb.insights.add_insight("Switches", ins.result)

        ins = self.project.analyses.Insight_Sockets(*self.args, **self.kwargs)
        self.kb.insights.add_insight("Sockets", ins.result)

        features = self.project.analyses.Insight_Features(*self.args, **self.kwargs)
        self.kb.insights.add_insight("Features", features.result)


from angr.analyses import AnalysesHub

AnalysesHub.register_default("Insights", Insights)
