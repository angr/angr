from typing import Optional, List, Tuple, TYPE_CHECKING
import math
import logging

from ..analysis import Analysis, AnalysesHub

from angr.knowledge_plugins.cfg import CFGModel

if TYPE_CHECKING:
    from cle import Section

_l = logging.getLogger(__name__)


class PackingDetector(Analysis):
    """
    This analysis detects if a binary is likely packed or not. We may extend it to identify which packer is in use in
    the future.
    """

    PACKED_MIN_BYTES = 256
    PACKED_ENTROPY_MIN_THRESHOLD = 0.88

    def __init__(self, cfg: Optional[CFGModel] = None, region_size_threshold: int = 0x20):
        self.packed: bool = False
        self.region_size_threshold: int = region_size_threshold

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
        # assume we already have a CFG with complete scanning disabled
        # collect all regions that are not covered by the CFG in r+x sections, and then compute the entropy. we believe
        # the binary is packed if it is beyond a threshold

        covered_regions: List[Tuple[int, int]] = []
        last_known_section: Optional["Section"] = None
        for node in sorted(self._cfg.nodes(), key=lambda n: n.addr):
            section = None
            if last_known_section is not None:
                if last_known_section.contains_addr(node.addr):
                    section = last_known_section
            if section is None:
                section = self.project.loader.find_section_containing(node.addr)
                if section is None:
                    # this node does not belong to any known section - ignore it
                    continue
                if section.is_readable and section.is_executable:
                    last_known_section = section

            if section is None:
                # the node does not belong to any section. ignore it
                continue

            if node.size == 0:
                # ignore empty nodes
                continue

            if not covered_regions:
                covered_regions.append((node.addr, node.addr + node.size))
            else:
                last_item = covered_regions[-1]
                if last_item[0] <= node.addr <= last_item[1] < node.addr + node.size:
                    # update the last item
                    covered_regions[-1] = last_item[0], node.addr + node.size
                else:
                    # add a new item
                    covered_regions.append((node.addr, node.addr + node.size))

        # now we get the uncovered regions
        uncovered_regions: List[Tuple[int, int]] = self._get_uncovered_regions(covered_regions)

        # compute entropy
        total_bytes, entropy = self._compute_entropy(uncovered_regions)

        breakpoint()

        self.packed = total_bytes >= self.PACKED_MIN_BYTES and entropy >= self.PACKED_ENTROPY_MIN_THRESHOLD

    def _get_uncovered_regions(self, covered_regions: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
        # FIXME: We only support binaries with sections. Add support for segments in the future
        all_executable_sections = [
            sec
            for sec in self.project.loader.main_object.sections
            if sec.is_executable and sec.is_readable and not sec.only_contains_uninitialized_data
        ]
        all_executable_sections = sorted(all_executable_sections, key=lambda sec: sec.vaddr)
        idx = 0

        uncovered_regions: List[Tuple[int, int]] = []
        for section in all_executable_sections:
            if idx >= len(covered_regions):
                if section.memsize > self.region_size_threshold:
                    uncovered_regions.append((section.vaddr, section.vaddr + section.memsize))
            else:
                i = idx
                last_end = section.vaddr
                while i < len(covered_regions):
                    region_start, region_end = covered_regions[i]
                    if region_end >= section.vaddr + section.memsize:
                        # move on to the next section
                        break
                    if last_end < region_start:
                        if region_start - last_end > self.region_size_threshold:
                            uncovered_regions.append((last_end, region_start))
                    i += 1
                    if region_end >= last_end:
                        last_end = region_end
                idx = i

        return uncovered_regions

    def _compute_entropy(self, regions: List[Tuple[int, int]]) -> Tuple[int, float]:
        byte_counts = [0] * 256

        for start, end in regions:
            for b in self.project.loader.memory.load(start, end - start):
                byte_counts[b] += 1

        total = sum(byte_counts)
        if total == 0:
            return 0, 0.0

        entropy = 0.0
        for count in byte_counts:
            if count == 0:
                continue
            p = 1.0 * count / total
            entropy -= p * math.log(p, 256)

        return total, entropy


AnalysesHub.register_default("PackingDetector", PackingDetector)
