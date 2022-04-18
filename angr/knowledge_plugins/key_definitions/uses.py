from typing import Dict, Set, Optional, Tuple, Any, Union, TYPE_CHECKING
from collections import defaultdict

from ...code_location import CodeLocation

if TYPE_CHECKING:
    from .definition import Definition


class Uses:

    __slots__ = ('_uses_by_definition', '_uses_by_location' )

    def __init__(self):
        self._uses_by_definition: Dict['Definition',Set[Tuple[CodeLocation,Optional[Any]]]] = defaultdict(set)
        self._uses_by_location: Dict[CodeLocation, Set[Tuple['Definition',Optional[Any]]]] = defaultdict(set)

    def add_use(self, definition: "Definition", codeloc: CodeLocation, expr: Optional[Any]=None):
        """
        Add a use for a given definition.

        :param definition:  The definition that is used.
        :param codeloc:     The code location where the use occurs.
        :param expr:        The expression that uses the specified definition at this location.
        """
        self._uses_by_definition[definition].add((codeloc, expr))
        self._uses_by_location[codeloc].add((definition, expr))

    def get_uses(self, definition: 'Definition') -> Set[CodeLocation]:
        """
        Retrieve the uses of a given definition.

        :param definition: The definition for which we get the uses.
        """
        return { codeloc for codeloc, _ in self._uses_by_definition.get(definition, set()) }

    def get_uses_with_expr(self, definition: 'Definition') -> Set[Tuple[CodeLocation,Optional[Any]]]:
        """
        Retrieve the uses and the corresponding expressions of a given definition.

        :param definition: The definition for which we get the uses and the corresponding expressions.
        """
        return self._uses_by_definition.get(definition, set())

    def remove_use(self, definition: 'Definition', codeloc: 'CodeLocation', expr: Optional[Any]=None) -> None:
        """
        Remove one use of a given definition.

        :param definition:  The definition of which to remove the uses.
        :param codeloc:     The code location where the use is.
        :param expr:        The expression that uses the definition at the given location.
        :return:            None
        """
        if definition in self._uses_by_definition:
            if codeloc in self._uses_by_definition[definition]:
                if expr is None:
                    for codeloc_, expr_ in list(self._uses_by_definition[definition]):
                        if codeloc_ == codeloc:
                            self._uses_by_definition[definition].remove((codeloc_, expr_))
                else:
                    self._uses_by_definition[definition].remove((codeloc, expr))

        if codeloc in self._uses_by_location:
            for item in list(self._uses_by_location[codeloc]):
                if item[0] == definition:
                    self._uses_by_location[codeloc].remove(item)

    def remove_uses(self, definition: 'Definition'):
        """
        Remove all uses of a given definition.

        :param definition:  The definition of which to remove the uses.
        :return:            None
        """
        if definition in self._uses_by_definition:
            codeloc_and_ids = self._uses_by_definition[definition]
            del self._uses_by_definition[definition]

            for codeloc, _ in codeloc_and_ids:
                for item in list(self._uses_by_location[codeloc]):
                    if item[0] == definition:
                        self._uses_by_location[codeloc].remove(item)

    def get_uses_by_location(self, codeloc: CodeLocation, exprs: bool=False) -> \
            Union[Set['Definition'],Set[Tuple['Definition',Optional[Any]]]]:
        """
        Retrieve all definitions that are used at a given location.

        :param codeloc: The code location.
        :return:        A set of definitions that are used at the given location.
        """
        if exprs:
            return self._uses_by_location.get(codeloc, set())
        return { item[0] for item in self._uses_by_location.get(codeloc, set()) }

    def get_uses_by_insaddr(self, ins_addr: int, exprs: bool=False) -> \
            Union[Set['Definition'],Set[Tuple['Definition',Optional[Any]]]]:
        """
        Retrieve all definitions that are used at a given location specified by the instruction address.

        :param ins_addr:    The instruction address.
        :return:            A set of definitions that are used at the given location.
        """

        all_uses = set()
        for codeloc, uses in self._uses_by_location.items():
            if codeloc.ins_addr == ins_addr:
                all_uses |= uses

        if exprs:
            return all_uses
        return { item[0] for item in all_uses }

    def copy(self) -> 'Uses':
        """
        Copy the instance.

        :return:    Return a new <Uses> instance containing the same data.
        """
        u = Uses()
        u._uses_by_definition = defaultdict(set, ((k, set(v)) for k, v in self._uses_by_definition.items()))
        u._uses_by_location = defaultdict(set, ((k, set(v)) for k, v in self._uses_by_location.items()))

        return u

    def merge(self, other) -> bool:
        """
        Merge an instance of <Uses> into the current instance.

        :param angr.angr.analyses.reaching_definitions.uses.Uses other: The other <Uses> from which the data will be added
                                                                        to the current instance.
        :return: True if any merge occurred, False otherwise
        """
        merge_occurred = False

        for k, v in other._uses_by_definition.items():
            if k not in self._uses_by_definition:
                self._uses_by_definition[k] = v
                merge_occurred = True
            elif not v.issubset(self._uses_by_definition[k]):
                merge_occurred = True
                self._uses_by_definition[k] |= v

        for k, v in other._uses_by_location.items():
            if k not in self._uses_by_location:
                self._uses_by_location[k] = v
                merge_occurred = True
            elif not v.issubset(self._uses_by_location[k]):
                merge_occurred = True
                self._uses_by_location[k] |= v

        return merge_occurred
