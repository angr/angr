from typing import List, Union, Set, Tuple
import logging
import operator
import re

from ...engines.light import RegisterOffset
from .constants import DEBUG
from .undefined import Undefined, UNDEFINED
from .unknown_size import UnknownSize, UNKNOWN_SIZE

l = logging.getLogger(name=__name__)


class DataSet:

    __slots__ = ('data', '_bits', '_mask')

    """
    This class represents a set of data.

    Addition and subtraction are performed on the cartesian product of the operands. Duplicate results are removed.
    Data must always include a set.

    :ivar set[Union[int,str,Undefined]] data: The set of data to represent.
    :ivar Union[int,UnknownSize] bits: The size of an element of the set, in number of bits its representation takes.
    """
    maximum_size = 5

    def __init__(self, data: Union[Set[Union[Undefined,RegisterOffset,int]],Undefined,RegisterOffset,int], bits: Union[int,UnknownSize]):
        self.data: Set[Union[Undefined,RegisterOffset,int]] = data if isinstance(data, set) else {data}
        self._bits = bits
        self._mask = (1 << bits) - 1
        self._limit()

    @property
    def bits(self) -> Union[int,UnknownSize]:
        return self._bits

    @property
    def mask(self) -> int:
        return self._mask

    def _limit(self):
        if DEBUG is True:
            # Deterministic limit
            if (len(self.data)) > DataSet.maximum_size:
                data = list(self.data)
                data.sort(key=repr)
                self.data = set(data[:DataSet.maximum_size])
                l.warning('Reached maximum size of DataSet, discarded %s.', str(data[DataSet.maximum_size:]))
        else:
            # Hash dependent implementation
            while len(self.data) > DataSet.maximum_size:
                l.warning('Reached maximum size of DataSet, discarded %s.', str(self.data.pop()))

    def truncate(self, bits):
        if self._bits <= bits:
            return DataSet(self.data, bits)

        def _truncate(datum):
            if isinstance(datum, int):
                mask = (1 << bits) - 1
                return datum & mask
            elif isinstance(datum, str):
                number_of_bytes = bits // 8
                return datum[:number_of_bytes]
            else:
                return datum

        data = { _truncate(d) for d in self.data }
        return DataSet(data, bits)

    def update(self, data):
        if type(data) is DataSet:
            if self.bits != data.bits:
                l.warning('Update with different sizes.')
            self.data.update(data.data)
        else:
            self.data.add(data)
        self._limit()

    def get_first_element(self):
        assert len(self.data) >= 1
        return next(iter(self.data))

    def __len__(self):
        return len(self.data)

    def _un_op(self, op):
        res = set()

        for s in self:
            if type(s) is Undefined:
                res.add(UNDEFINED)
            else:
                try:
                    tmp = op(s)
                    if isinstance(tmp, int):
                        tmp &= self._mask
                    res.add(tmp)
                except TypeError as ex:  # pylint:disable=try-except-raise,unused-variable
                    # l.warning(ex)
                    raise

        return DataSet(res, self._bits)

    def _bin_op(self, other, op):
        if not type(other) is DataSet:
            raise TypeError("_bin_op() only works on another DataSet instance.")

        res = set()

        #if self._bits != other.bits:
        #    l.warning('Binary operation with different sizes.')

        for o in other:
            for s in self:
                if type(o) is Undefined or type(s) is Undefined:
                    res.add(UNDEFINED)
                else:
                    try:
                        tmp = op(s, o)
                        if isinstance(tmp, int):
                            tmp &= self._mask
                        res.add(tmp)
                    except TypeError as ex:  # pylint:disable=try-except-raise,unused-variable
                        # l.warning(ex)
                        raise

        return DataSet(res, self._bits)

    def __add__(self, other):
        return self._bin_op(other, operator.add)

    def __sub__(self, other):
        return self._bin_op(other, operator.sub)

    def __mul__(self, other):
        return self._bin_op(other, operator.mul)

    def __div__(self, other):
        return self._bin_op(other, operator.floordiv)

    def __lshift__(self, other):
        return self._bin_op(other, operator.lshift)

    def __rshift__(self, other):
        return self._bin_op(other, operator.rshift)

    def __and__(self, other):
        return self._bin_op(other, operator.and_)

    def __xor__(self, other):
        return self._bin_op(other, operator.xor)

    def __or__(self, other):
        return self._bin_op(other, operator.or_)

    def __neg__(self):
        return self._un_op(operator.neg)

    def __invert__(self):
        return self._un_op(operator.invert)

    def __eq__(self, other):
        if type(other) == DataSet:
            return self.data == other.data and self._bits == other.bits and self._mask == other.mask
        else:
            return False

    def __hash__(self):
        return hash((self._bits, self._mask))

    def __iter__(self):
        return iter(self.data)

    def __str__(self):
        if UNDEFINED in self.data:
            data_string = str(self.data)
        else:
            data_string = str([ _stringify_datum(i) for i in self.data ])
        size = "%d" % self._bits if isinstance(self._bits, int) else self._bits

        return 'DataSet<%s>: %s' % (size, data_string)

def _stringify_datum(datum):
    if isinstance(datum, int): return hex(datum)

    # Shorten long strings if possible
    if isinstance(datum, str) and len(datum) > 50:
        regex = r'(.)\1{10,}'
        matches = list(re.finditer(regex, datum))

        if len(matches) == 0: return datum

        _new_datum = datum[:matches[0].span()[0]]
        for m in matches:
            number_of_occurences = m.span()[1] - m.span()[0]
            _new_datum += "%s...(repeats %d times)" % (m.groups()[0], number_of_occurences)
        return _new_datum

    return datum


def size_of_datasets(datasets: List[DataSet]) -> Tuple[int,UnknownSize]:
    """
    If the size of all datasets are equal, then the result will be of that size; Otherwise, it will be of size UNKNOWN_SIZE.

    :param datasets: The datasets to get the size from.
    :return: The common size of the given datasets.
    """
    if not datasets:
        return UNKNOWN_SIZE
    return (
        datasets[0]._bits if all(map(lambda d: d._bits == datasets[0]._bits, datasets))
        else UNKNOWN_SIZE
    )


def dataset_from_datasets(datasets: List[DataSet]) -> DataSet:
    """
    Instantiate a <DataSet> by "merging" several <DataSet>s.

    :param datasets: The datasets to merge into one.
    :return: A new <DataSet>, containing the data from all given datasets.
    """
    if not datasets:
        return DataSet({UNDEFINED}, UNKNOWN_SIZE)

    size = size_of_datasets(datasets)

    result = DataSet(set(), size)
    for ds in datasets:
        result.update(ds)

    return result
