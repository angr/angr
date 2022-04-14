from typing import Optional, Generator

import claripy

from ....sim_options import HYBRID_SOLVER, APPROXIMATE_FIRST
from .... import concretization_strategies
from ....errors import SimMergeError, SimMemoryAddressError
from .. import MemoryMixin
from .abstract_address_descriptor import AbstractAddressDescriptor
from .region_data import AddressWrapper


class RegionedAddressConcretizationMixin(MemoryMixin):
    def __init__(self, read_strategies=None, write_strategies=None, **kwargs):
        super().__init__(**kwargs)

        self.read_strategies = read_strategies
        self.write_strategies = write_strategies

    def set_state(self, state):
        super().set_state(state)

        if self.state is not None:
            if self.read_strategies is None:
                self._create_default_read_strategies()
            if self.write_strategies is None:
                self._create_default_write_strategies()

    @MemoryMixin.memo
    def copy(self, memo):
        o = super().copy(memo)
        o.read_strategies = list(self.read_strategies)
        o.write_strategies = list(self.write_strategies)
        return o

    def merge(self, others, merge_conditions, common_ancestor=None) -> bool:
        r = super().merge(others, merge_conditions, common_ancestor=common_ancestor)
        self.read_strategies = self._merge_strategies(self.read_strategies, *[
            o.read_strategies for o in others
        ])
        self.write_strategies = self._merge_strategies(self.write_strategies, *[
            o.write_strategies for o in others
        ])
        return r

    def _create_default_read_strategies(self):
        """
        This function is used to populate `self.read_strategies` if by set-state time none have been provided
        It uses state options to pick defaults.
        """
        self.read_strategies = [concretization_strategies.SimConcretizationStrategyUnlimitedRange(self._read_targets_limit)]

    def _create_default_write_strategies(self):
        """
        This function is used to populate `self.write_strategies` if by set-state time none have been provided.
        It uses state options to pick defaults.
        """
        self.write_strategies = [concretization_strategies.SimConcretizationStrategyUnlimitedRange(self._write_targets_limit)]

    @staticmethod
    def _merge_strategies(*strategy_lists):
        """
        Utility function for merging. Does the merge operation on lists of strategies
        """
        if len(set(len(sl) for sl in strategy_lists)) != 1:
            raise SimMergeError("unable to merge memories with amounts of strategies")

        merged_strategies = [ ]
        for strategies in zip(*strategy_lists):
            if len(set(s.__class__ for s in strategies)) != 1:
                raise SimMergeError("unable to merge memories with different types of strategies")

            unique = list(set(strategies))
            if len(unique) > 1:
                unique[0].merge(unique[1:])
            merged_strategies.append(unique[0])
        return merged_strategies

    def _apply_concretization_strategies(self, addr, strategies):
        """
        Applies concretization strategies on the address until one of them succeeds.
        """

        for s in strategies:
            a = s.concretize(self, addr)
            # return the result if not None!
            if a is not None:
                return a

        # well, we tried
        raise SimMemoryAddressError(
            "Unable to concretize address with the provided strategies."
        )

    def _concretize_address_descriptor(self, desc: AbstractAddressDescriptor, original_addr: claripy.ast.Bits,
                                       is_write: bool=False,
                                       target_region: Optional[str]=None) -> Generator[AddressWrapper,None,None]:

        strategies = self.write_strategies if is_write else self.read_strategies
        targets_limit = self._write_targets_limit if is_write else self._read_targets_limit

        for region, addr_si in desc:
            concrete_addrs = self._apply_concretization_strategies(addr_si, strategies)
            if len(concrete_addrs) == targets_limit and HYBRID_SOLVER in self.state.options:
                exact = True if APPROXIMATE_FIRST not in self.state.options else None
                solutions = self.state.solver.eval_upto(original_addr, targets_limit, exact=exact)

                if len(solutions) < len(concrete_addrs):
                    concrete_addrs = [addr_si.intersection(s).eval(1)[0] for s in solutions]

            for c in concrete_addrs:
                yield self._normalize_address_core(region, c, target_region=target_region)

    def _normalize_address_core(self, region_id: str, relative_address: int,
                                target_region: Optional[str]=None) -> AddressWrapper:
        return super()._normalize_address_core(region_id, relative_address, target_region)
