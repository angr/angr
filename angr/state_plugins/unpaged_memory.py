import bisect

class PagedMemory(object):

    PAGE_SIZE = 0x1000

    def __init__(self, memory, pages=dict()):
        self._addrs = pages
        self._cached_pages = None

    def __getitem__(self, addr):
        if addr in self._addrs:
            return self._addrs[addr]
        return None

    def __setitem__(self, addr, value):
        self._cached_pages = None
        self._addrs[addr] = value

    def __len__(self):
        return len(self._addrs)

    @property
    def _pages(self):

        if self._cached_pages is not None:
            return self._cached_pages

        pages = dict()
        for a in self._addrs:
            index = a / 0x1000
            if index not in pages:
                pages[index] = dict()

            pages[index][a % 0x1000] = self._addrs[a]

        self._cached_pages = pages
        return pages

    def find(self, start, end, result_is_flat_list=False):

        assert result_is_flat_list
        values = []

        for a in self._addrs:
            if start <= a <= end:
                v = self._addrs[a]
                if type(v) in (list,):
                    for vv in v:
                        assert type(vv) not in (list,)
                        values.append(vv)
                else:
                    values.append(v)

        return values

    def copy(self, memory):
        return PagedMemory(pages=dict(self._addrs), memory=memory)

