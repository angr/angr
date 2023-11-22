from typing import Optional, List, Tuple, TYPE_CHECKING
import networkx
import logging

from ..analysis import Analysis, AnalysesHub

from angr.knowledge_plugins.cfg import CFGModel

_l = logging.getLogger(__name__)


class ObfuscationDetector(Analysis):
    """
    This analysis detects, usually in ways that are more robust than section name matching or signature matching, the
    existence of obfuscation techniques in a binary.
    """

    def __init__(self, cfg: Optional[CFGModel] = None):
        self.obfuscated: bool = False
        self.possible_obfuscators: List[str] = []

        if cfg is None:
            _l.warning(
                "PackingDetector is using a most accurate CFG model in the knowledge base. We assume it is "
                "generated with force_smart_scan=False and force_complete_scan=False."
            )
            self._cfg = self.kb.cfgs.get_most_accurate()
        else:
            self._cfg = cfg

        self.analyze()

    def analyze(self):

        analysis_routines = [
            self._analyze_vmprotect,
        ]

        for routine in analysis_routines:
            tool = routine()
            if tool:
                self.obfuscated = True
                self.possible_obfuscators.append(tool)

    def _analyze_vmprotect(self) -> Optional[str]:
        """
        We detect VMProtect v3 (with control-flow obfuscation) based on two main characteristics:

        - In amd64 binaries, there exists a strongly connected component in the call graph with over 1,000 nodes.
          Edge/node ratio is >= 1.3
        - There is a high number of pushf and popf instructions in the visible functions.
        """

        high_scc_node_edge_ratio = False
        high_pushf = False
        high_popf = False
        high_clc = False

        if self.project.arch.name == "AMD64":
            cg = self.kb.functions.callgraph
            sccs = networkx.strongly_connected_components(cg)

            for scc in sccs:
                subgraph = networkx.subgraph(cg, scc)
                node_count = len(scc)
                if node_count > 1000:
                    edge_count = len(subgraph.edges)

                    if edge_count / node_count >= 1.3:
                        high_scc_node_edge_ratio = True
                        break
        else:
            high_scc_node_edge_ratio = True

        pushf_ctr = 0
        popf_ctr = 0
        clc_ctr = 0  # only used for x86
        is_x86 = self.project.arch.name == "X86"
        cfg_node_count = len(self._cfg.graph)
        for node in self._cfg.nodes():
            if node.size > 0 and node.instruction_addrs:
                block = node.block
                for insn in block.capstone.insns:
                    if insn.mnemonic in {"pushf", "pushfd", "pushfq"}:
                        pushf_ctr += 1
                    elif insn.mnemonic in {"popf", "popfd", "popfq"}:
                        popf_ctr += 1
                    elif is_x86 and insn.mnemonic == "clc":
                        clc_ctr += 1

        if pushf_ctr > cfg_node_count * 0.002:
            high_pushf = True
        if popf_ctr > cfg_node_count * 0.002:
            high_popf = True
        if not is_x86:
            high_clc = True
        elif clc_ctr > cfg_node_count * 0.002:
            high_clc = True

        if high_scc_node_edge_ratio and high_pushf and high_popf:
            return "vmprotect"
        return None


AnalysesHub.register_default("ObfuscationDetector", ObfuscationDetector)
