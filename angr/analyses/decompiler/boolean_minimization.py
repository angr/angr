"""
A dependency-free two-level Boolean minimizer based on the Quine-McCluskey algorithm.

Truth tables are Python integers used as bit vectors: bit ``m`` is set iff the formula holds under the assignment where
atom ``i`` takes the value ``(m >> i) & 1``. A formula that does not constrain the high atoms has a table periodic in
them, so evaluating it against wider columns and masking down with ``full_table()`` matches evaluating it at its own
width. Literals are non-zero integers, ``i + 1`` for atom ``i`` and ``-(i + 1)`` for its negation. An implicant is a
``(value, dashes)`` pair, where ``dashes`` marks the atoms the cube leaves unconstrained and those bits of ``value``
are zero.
"""

from __future__ import annotations

from collections import defaultdict
from functools import lru_cache
from typing import NamedTuple

_Implicant = tuple[int, int]


class MinimizedFormula(NamedTuple):
    """
    A minimized truth table: an OR of AND terms when ``is_sop``, an AND of OR clauses otherwise.
    """

    is_sop: bool
    terms: tuple[tuple[int, ...], ...]

    @property
    def literal_count(self) -> int:
        return sum(len(term) for term in self.terms)


@lru_cache(maxsize=16)
def atom_columns(num_atoms: int) -> tuple[int, ...]:
    columns = []
    for atom in range(num_atoms):
        run = 1 << atom
        ones = (1 << run) - 1
        column = 0
        for start in range(run, 1 << num_atoms, run * 2):
            column |= ones << start
        columns.append(column)
    return tuple(columns)


def full_table(num_atoms: int) -> int:
    return (1 << (1 << num_atoms)) - 1


def minimize(truth_table: int, num_atoms: int) -> bool | MinimizedFormula:
    """
    Minimize a truth table, returning whichever of its sum-of-products and product-of-sums forms is smaller, or a plain
    bool if the formula is a tautology or a contradiction.
    """

    all_ones = full_table(num_atoms)
    truth_table &= all_ones

    if truth_table == 0:
        return False
    if truth_table == all_ones:
        return True

    on_set = [m for m in range(1 << num_atoms) if truth_table >> m & 1]
    off_set = [m for m in range(1 << num_atoms) if not truth_table >> m & 1]

    sop = MinimizedFormula(True, tuple(_product(impl, num_atoms) for impl in _cover(on_set, num_atoms)))
    pos = MinimizedFormula(
        False,
        tuple(tuple(-lit for lit in _product(impl, num_atoms)) for impl in _cover(off_set, num_atoms)),
    )

    if (pos.literal_count, len(pos.terms)) < (sop.literal_count, len(sop.terms)):
        return pos
    return sop


def _product(implicant: _Implicant, num_atoms: int) -> tuple[int, ...]:
    value, dashes = implicant
    return tuple(
        (atom + 1 if value >> atom & 1 else -(atom + 1)) for atom in range(num_atoms) if not dashes >> atom & 1
    )


def _prime_implicants(minterms: list[int], num_atoms: int) -> list[_Implicant]:
    primes: set[_Implicant] = set()
    current: set[_Implicant] = {(minterm, 0) for minterm in minterms}

    while current:
        merged: set[_Implicant] = set()
        used: set[_Implicant] = set()

        by_dashes: dict[int, set[int]] = defaultdict(set)
        for value, dashes in current:
            by_dashes[dashes].add(value)

        for dashes, values in by_dashes.items():
            for value in values:
                for atom in range(num_atoms):
                    bit = 1 << atom
                    if dashes & bit or value & bit:
                        continue
                    if value | bit in values:
                        used.add((value, dashes))
                        used.add((value | bit, dashes))
                        merged.add((value, dashes | bit))

        primes.update(current - used)
        current = merged

    return sorted(primes)


def _cover(minterms: list[int], num_atoms: int) -> list[_Implicant]:
    if not minterms:
        return []

    primes = _prime_implicants(minterms, num_atoms)
    position = {minterm: pos for pos, minterm in enumerate(minterms)}

    coverage: list[int] = []
    covering: list[list[int]] = [[] for _ in minterms]
    for prime_id, (value, dashes) in enumerate(primes):
        mask = 0
        subset = dashes
        while True:
            pos = position[value | subset]
            mask |= 1 << pos
            covering[pos].append(prime_id)
            if not subset:
                break
            subset = (subset - 1) & dashes
        coverage.append(mask)

    chosen: list[int] = []
    chosen_ids: set[int] = set()
    uncovered = (1 << len(minterms)) - 1

    def select(prime_id: int) -> None:
        nonlocal uncovered
        chosen.append(prime_id)
        chosen_ids.add(prime_id)
        uncovered &= ~coverage[prime_id]

    for prime_ids in covering:
        if len(prime_ids) == 1 and prime_ids[0] not in chosen_ids:
            select(prime_ids[0])

    while uncovered:
        select(
            max(
                (prime_id for prime_id in range(len(primes)) if prime_id not in chosen_ids),
                key=lambda prime_id: (
                    (coverage[prime_id] & uncovered).bit_count(),
                    primes[prime_id][1].bit_count(),
                    -primes[prime_id][0],
                ),
            )
        )

    for prime_id in reversed(chosen[:]):
        others = 0
        for other_id in chosen:
            if other_id != prime_id:
                others |= coverage[other_id]
        if coverage[prime_id] & ~others == 0:
            chosen.remove(prime_id)

    return [primes[prime_id] for prime_id in chosen]
