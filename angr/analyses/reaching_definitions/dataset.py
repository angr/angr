import logging
import operator

from .constants import DEBUG
from .undefined import Undefined

l = logging.getLogger('angr.analyses.reaching_definitions.dataset')


class DataSet(object):
    """
    This class represents a set of data.

    Addition and subtraction are performed on the cartesian product of the operands. Duplicate results are removed.
    data must always include a set.
    """
    maximum_size = 5

    def __init__(self, data, bits):
        self.data = data if type(data) is set else {data}
        self._bits = bits
        self._mask = (1 << bits) - 1
        self._limit()

    @property
    def bits(self):
        return self._bits

    @property
    def mask(self):
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
                res.add(Undefined())
            else:
                try:
                    tmp = op(s)
                    if isinstance(tmp, int):
                        tmp &= self._mask
                    res.add(tmp)
                except TypeError as e:
                    res.add(Undefined())
                    l.warning(e)

        return DataSet(res, self._bits)

    def _bin_op(self, other, op):
        assert type(other) is DataSet

        res = set()

        if self._bits != other.bits:
            l.warning('Binary operation with different sizes.')

        for o in other:
            for s in self:
                if type(o) is Undefined or type(s) is Undefined:
                    res.add(Undefined())
                else:
                    try:
                        tmp = op(s, o)
                        if isinstance(tmp, int):
                            tmp &= self._mask
                        res.add(tmp)
                    except TypeError as e:
                        res.add(Undefined())
                        l.warning(e)

        return DataSet(res, self._bits)

    def __add__(self, other):
        return self._bin_op(other, operator.add)

    def __sub__(self, other):
        return self._bin_op(other, operator.sub)

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
        return 'DataSet<%d>: %s' % (self._bits, str(self.data))
