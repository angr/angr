from __future__ import annotations
from typing import Any
import logging
from collections import defaultdict

from angr.analyses import Analysis

l = logging.getLogger(name=__name__)


class DephicationBase(Analysis):
    """
    This is the base class for analyses that removes phi expressions from AIL graphs, SequenceNodes, and other types of
    AIL statement containers.
    """

    def __init__(self, func, vvar_to_vvar_mapping: dict[int, int] | None = None, rewrite: bool = False):
        if isinstance(func, str):
            self._function = self.kb.functions[func]
        else:
            self._function = func

        self.vvar_to_vvar_mapping = vvar_to_vvar_mapping if vvar_to_vvar_mapping is not None else None
        self.rewrite = rewrite
        self.output = None

    def _analyze(self):
        if self.vvar_to_vvar_mapping is None:
            self.vvar_to_vvar_mapping = self._collect_and_remap()

        if self.rewrite:
            self.output = self._rewrite_container()

    def _collect_and_remap(self) -> dict[int, int]:
        # collect phi assignments
        phi_to_srcvarid = self._collect_phi_assignments()

        vvar_to_vvar = {}  # a mapping between vvar IDs to phi vvar IDs when applicable
        vvar_to_phivarids = defaultdict(set)
        for phi_varid, varids in phi_to_srcvarid.items():
            for varid in varids:
                vvar_to_phivarids[varid].add(phi_varid)

        # iterate until fixed point
        while True:
            changed = False
            for varid in list(vvar_to_phivarids):
                phivarids = vvar_to_phivarids[varid]
                new = phivarids.copy()
                for vv in phivarids:
                    if vv in vvar_to_phivarids:
                        new |= vvar_to_phivarids[vv]
                if new != phivarids:
                    changed = True
                    vvar_to_phivarids[varid] = new

            if not changed:
                break

        # unify those that are mapped to multiple phi variables
        phivarid_to_phivarid = {}
        for phivarids in vvar_to_phivarids.values():
            if len(phivarids) > 1:
                min_phivarid = min(phivarids)
                # remap the existing ones first
                for phivarid, mapped_to in list(phivarid_to_phivarid.items()):
                    if phivarid in phivarids:
                        continue
                    if mapped_to in phivarids:
                        phivarid_to_phivarid[phivarid] = min_phivarid
                # map the new ones
                for phivarid in phivarids:
                    phivarid_to_phivarid[phivarid] = min_phivarid

        # fill in vvar_to_vvar mapping
        for phi_varid, varids in phi_to_srcvarid.items():
            mapped_phivarid = phivarid_to_phivarid.get(phi_varid, phi_varid)
            for varid in varids:
                vvar_to_vvar[varid] = mapped_phivarid

        return vvar_to_vvar

    def _collect_phi_assignments(self) -> dict[int, set[int]]:
        raise NotImplementedError

    def _rewrite_container(self) -> Any:
        raise NotImplementedError
