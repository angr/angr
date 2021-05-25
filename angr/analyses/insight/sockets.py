from __future__ import annotations

from .base import InsightBase


class SocketsInsight(InsightBase):
    """
    Identify uses of sockets.
    """

    def __init__(self, *args, case_threshold: int = 8, **kwargs):
        super().__init__(*args, **kwargs)

        self._case_threshold = case_threshold

        self.result = []

        self.analyze()

    def analyze(self):
        # socket
        try:
            sock_func = self.kb.functions.function(name="socket", plt=True)
        except KeyError:
            return

        # where is it called?
        sock_func_node = self.cfg.get_any_node(sock_func.addr)
        for caller in self.cfg.graph.predecessors(sock_func_node):
            caller_func_addr = caller.function_address
            caller_func = self.kb.functions[caller_func_addr]

            # what does the function do?

            # we are lazy, so... decompile it
            # dec = self.project.analyses.Decompiler(caller_func)
            # clinic = dec.clinic

            item = {
                "description": "Found a TCP socket listening at port ???",
                "ref_at": sock_func_node.addr,
                "func_addr": caller_func_addr,
                "func_name": caller_func.name,
            }

            self.result.append(item)


from angr.analyses import AnalysesHub

AnalysesHub.register_default("Insight_Sockets", SocketsInsight)
