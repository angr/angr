import bisect

class PagedMemory(object):

    PAGE_SIZE = 0x1000

    ACCESS_EXECUTE  = 0x1
    ACCESS_WRITE    = 0x2
    ACCESS_READ     = 0x4

    def __init__(self, memory, pages=dict()):
        self._pages = pages
        self._cowed = set()
        self.memory = memory

    def _get_index_offset(self, addr):
        index = addr // self.PAGE_SIZE
        offset = addr % self.PAGE_SIZE
        return index, offset

    def __getitem__(self, addr):

        #self._check_access(addr, self.ACCESS_READ)

        index, offset = self._get_index_offset(addr)

        if index not in self._pages:
            return None

        page = self._pages[index]

        if offset not in page:
            return None

        return page[offset]

    def __setitem__(self, addr, value):

        #self._check_access(addr, self.ACCESS_WRITE)
        #print "Storing at " + str(addr) + " data: " + str(value)

        index, offset = self._get_index_offset(addr)

        #print "storing at index= " + str(index) + " offset=" + str(offset)

        if index not in self._pages:
            page = dict()
            self._cowed.add(index)
            self._pages[index] = page
        else:
            page = self._pages[index]
            if index not in self._cowed:
                page = dict(page)
                self._pages[index] = page
                self._cowed.add(index)

        page[offset] = value

    def __len__(self):
        count = 0
        for p in self._pages:
            count += len(self._pages[p])
        return count

    def find(self, start, end, result_is_flat_list=False):

        """
        assert result_is_flat_list
        values = []

        addr = start
        index, offset = self._get_index_offset(addr)
        while addr <= end:

            if index not in self._pages:
                addr += self.PAGE_SIZE - offset
                assert addr % self.PAGE_SIZE == 0
                offset = 0
                index += 1
                continue

            if offset in self._pages[index]:
                v = self._pages[index][offset]
                if type(v) in (list,):
                    for vv in v:
                        assert type(vv) not in (list,)
                        values.append(vv)
                else:
                    values.append(v)

            addr += 1
            offset += 1
            if offset >= self.PAGE_SIZE:
                assert addr % self.PAGE_SIZE == 0
                offset = 0
                index += 1


        """
        if result_is_flat_list:
            values = []
        else:
            values = {}

        range_len = end - start
        if range_len >= 1024:

            #print "Large range... pages are " + str(len(self._pages))

            indexes = sorted(self._pages.keys())
            min_index = int(start / self.PAGE_SIZE)
            max_index = int(end / self.PAGE_SIZE)
            offset = start % self.PAGE_SIZE

            #print "min_index=" + str(min_index) + " max_index=" + str(max_index)
            #print indexes

            pos = bisect.bisect_left(indexes, min_index)

            while pos < len(indexes) and indexes[pos] <= max_index:

                index = indexes[pos]
                if index in self._pages:
                    #print "Looking at page index=" + str(index) + " offset=" + str(offset)
                    page = self._pages[index]
                    while offset < self.PAGE_SIZE:
                        if offset in page:

                            if result_is_flat_list:

                                v = page[offset]
                                if type(v) in (list,):
                                    for vv in v:
                                        assert type(vv) not in (list,)
                                        values.append(vv)
                                else:
                                    values.append(v)

                            else:
                                values[index * self.PAGE_SIZE + offset] = page[offset]

                        offset += 1
                        if index * self.PAGE_SIZE + offset > end:
                            return values
                offset = 0
                pos += 1

        else:

            addr = start
            index, offset = self._get_index_offset(addr)
            while addr <= end:

                #print "reading from index=" + str(index) + " offset=" + str(offset)

                if index not in self._pages:
                    addr += self.PAGE_SIZE - offset
                    offset = 0
                    index += 1
                    continue

                if offset in self._pages[index]:

                    if result_is_flat_list:

                        v = self._pages[index][offset]
                        if type(v) in (list,):
                            for vv in v:
                                assert type(vv) not in (list,)
                                values.append(vv)
                        else:
                            values.append(v)

                    else:
                        values[addr] = self._pages[index][offset]

                #else: print "address is empty"

                addr += 1
                offset += 1
                if offset >= self.PAGE_SIZE:
                    offset = 0
                    index += 1

        return values

    def copy(self, memory):
        return PagedMemory(pages=dict(self._pages), memory=memory)

