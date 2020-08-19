from typing import Optional

#
# Types
#

class BaseType:
    def __init__(self, in_: bool, out_: bool):
        self.in_ = in_
        self.out_ = out_

    def io_repr(self) -> str:
        s = "/%s%s/" % (
            "." if not self.in_ else "i",
            "." if not self.out_ else "o",
        )
        return s


class Buffer(BaseType):
    def __init__(self, lbound: Optional[int]=None, ubound: Optional[int]=None, element_size: Optional[int]=None,
                 element_count: Optional[int]=None, in_: bool=True, out_: bool=False, is_string: bool=False):
        super().__init__(in_, out_)
        self.lbound = lbound
        self.ubound = ubound
        self.element_size = element_size
        self.element_count = element_count
        self.is_string = is_string

    def __eq__(self, other):
        return isinstance(other, Buffer) \
            and other.lbound == self.lbound \
            and other.ubound == self.ubound \
            and other.element_size == self.element_size \
            and other.element_count == self.element_count \
            and self.in_ == other.in_ \
            and self.out_ == other.out_

    def __hash__(self):
        return hash((Buffer, self.lbound, self.ubound, self.element_size, self.element_count, self.in_, self.out_))

    def __repr__(self):
        return self.io_repr() + "%sBuffer %s-%s" % (("" if not self.is_string else "String "), self.lbound, self.ubound)


class Pointer(BaseType):
    def __init__(self, pts_to: BaseType, in_: bool=True, out_: bool=False):
        super().__init__(in_, out_)
        self.pts_to = pts_to

    def __eq__(self, other):
        return isinstance(other, Pointer) \
            and other.pts_to == self.pts_to \
            and self.in_ == other.in_ \
            and self.out_ == other.out_

    def __hash__(self):
        return hash((Pointer, self.pts_to, self.in_, self.out_))

    def __repr__(self):
        return self.io_repr() + "ptr(%r)" % self.pts_to
