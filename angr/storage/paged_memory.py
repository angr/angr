import bintrees
import cooldict
import claripy
import cffi
import cle

from ..errors import SimMemoryError, SimSegfaultError
from .. import sim_options as options
from .memory_object import SimMemoryObject
from claripy.ast.bv import BV

_ffi = cffi.FFI()

import logging
l = logging.getLogger("angr.storage.paged_memory")

class BasePage(object):
    """
    Page object, allowing for more flexibility than just a raw dict.
    """

    PROT_READ = 1
    PROT_WRITE = 2
    PROT_EXEC = 4

    def __init__(self, page_addr, page_size, permissions=None, executable=False):
        """
        Create a new page object. Carries permissions information.
        Permissions default to RW unless `executable` is True,
        in which case permissions default to RWX.

        :param int page_addr: The base address of the page.
        :param int page_size: The size of the page.
        :param bool executable: Whether the page is executable. Typically,
                            this will depend on whether the binary has an
                            executable stack.
        :param claripy.AST permissions: A 3-bit bitvector setting specific permissions
                            for EXEC, READ, and WRITE
        """

        self._page_addr = page_addr
        self._page_size = page_size

        if permissions is None:
            perms = Page.PROT_READ|Page.PROT_WRITE
            if executable:
                perms |= Page.PROT_EXEC
            self.permissions = claripy.BVV(perms, 3) # 3 bits is enough for PROT_EXEC, PROT_WRITE, PROT_READ, PROT_NONE
        else:
            self.permissions = permissions

    @property
    def concrete_permissions(self):
        if self.permissions.symbolic:
            return 7
        else:
            return self.permissions.args[0]

    def contains(self, state, idx):
        m = self.load_mo(state, idx)
        return m is not None and m.includes(idx)

    def _resolve_range(self, mo):
        start = max(mo.base, self._page_addr)
        end = min(mo.last_addr + 1, self._page_addr + self._page_size)
        if end <= start:
            l.warning("Nothing left of the memory object to store in SimPage.")
        return start, end

    def store_mo(self, state, new_mo, overwrite=True): #pylint:disable=unused-argument
        """
        Stores a memory object.

        :param new_mo: the memory object
        :param overwrite: whether to overwrite objects already in memory (if false, just fill in the holes)
        """
        start, end = self._resolve_range(new_mo)
        if overwrite:
            self.store_overwrite(state, new_mo, start, end)
        else:
            self.store_underwrite(state, new_mo, start, end)

    def copy(self):
        return Page(
            self._page_addr, self._page_size,
            permissions=self.permissions,
            **self._copy_args()
        )

    #
    # Abstract functions
    #

    def load_mo(self, state, page_idx):
        """
        Loads a memory object from memory.

        :param page_idx: the index into the page
        :returns: a tuple of the object
        """
        raise NotImplementedError()

    def keys(self):
        raise NotImplementedError()

    def replace_mo(self, state, old_mo, new_mo):
        raise NotImplementedError()

    def store_overwrite(self, state, new_mo, start, end):
        raise NotImplementedError()

    def store_underwrite(self, state, new_mo, start, end):
        raise NotImplementedError()

    def load_slice(self, state, start, end): #pylint:disable=unused-argument
        """
        Return the memory objects overlapping with the provided slice.

        :param start: the start address
        :param end: the end address (non-inclusive)
        :returns: tuples of (starting_addr, memory_object)
        """
        raise NotImplementedError()

    def _copy_args(self):
        raise NotImplementedError()

class TreePage(BasePage):
    """
    Page object, implemented with a bintree.
    """

    def __init__(self, *args, **kwargs):
        storage = kwargs.pop("storage", None)
        super(TreePage, self).__init__(*args, **kwargs)
        self._storage = bintrees.AVLTree() if storage is None else storage

    def keys(self):
        if len(self._storage) == 0:
            return set()
        else:
            return set.union(*(set(range(*self._resolve_range(mo))) for mo in self._storage.values()))

    def replace_mo(self, state, old_mo, new_mo):
        start, end = self._resolve_range(old_mo)
        possible_items = list(self._storage.item_slice(start, end))
        for a,v in possible_items:
            if v is old_mo:
                #assert new_mo.includes(a)
                self._storage[a] = new_mo

    def store_overwrite(self, state, new_mo, start, end):
        # get a list of items that we will overwrite
        current_items = list(self._storage.item_slice(start, end + 1))

        updates = { start: new_mo }

        # remove the items we are overwriting
        if not current_items:
            # make sure we aren't overwriting an entire item that starts before
            # the write range and extends past the end of it
            try:
                _, floor_value = self._storage.floor_item(start)
                if floor_value.includes(end):
                    updates[end] = floor_value
            except KeyError:
                pass
        else:
            # make sure we're not overwriting an entire item that starts inside
            # the write range and extends past the end of it
            if end < self._page_addr + self._page_size and current_items[-1][1].includes(end):
                updates[end] = current_items[-1][1]

            # remove existing items
            del self._storage[start:end]

        #assert all(m.includes(i) for i,m in updates.items())

        # store the new stuff
        self._storage.update(updates)

    def store_underwrite(self, state, new_mo, start, end):
        # first, get the current items
        current_items = list(self._storage.item_slice(start, end + 1))

        # go through them backwards and fill in the gaps
        last_missing = end - 1
        updates = { }
        for _,mo in reversed(current_items):
            if not mo.includes(last_missing) and not mo.base > last_missing:
                # this mo does not cover up to the end; we need to fill it in
                updates[mo.last_addr+1] = new_mo
            last_missing = mo.base - 1

        # if the beginning is missing, fill it in and make sure we're not
        # overwriting something we shouldn't be
        if last_missing >= start:
            try:
                _, floor_value = self._storage.floor_item(start)
                if not floor_value.includes(last_missing):
                    updates[max(floor_value.last_addr+1, start)] = new_mo
            except KeyError:
                updates[start] = new_mo

        #assert all(m.includes(i) for i,m in updates.items())

        # apply it
        self._storage.update(updates)

    def load_mo(self, state, page_idx):
        """
        Loads a memory object from memory.

        :param page_idx: the index into the page
        :returns: a tuple of the object
        """

        try:
            mo = self._storage.floor_item(page_idx)[1]
        except KeyError:
            mo = None

        return mo

    def load_slice(self, state, start, end):
        """
        Return the memory objects overlapping with the provided slice.

        :param start: the start address
        :param end: the end address (non-inclusive)
        :returns: tuples of (starting_addr, memory_object)
        """
        items = list(self._storage.item_slice(start, end))
        if not items or items[0][0] != start:
            try:
                _, floor_mo = self._storage.floor_item(start)
                if floor_mo.includes(start):
                    items.insert(0, (start, floor_mo))
            except KeyError:
                pass
        return items

    def _copy_args(self):
        return { 'storage': bintrees.AVLTree(self._storage) }

class ListPage(BasePage):
    """
    Page object, implemented with a list.
    """

    def __init__(self, *args, **kwargs):
        storage = kwargs.pop("storage", None)
        self._sinkhole = kwargs.pop("sinkhole", None)

        super(ListPage, self).__init__(*args, **kwargs)
        self._storage = [ None ] * self._page_size if storage is None else storage

    def keys(self):
        if self._sinkhole is not None:
            return range(self._page_addr, self._page_addr + self._page_size)
        else:
            return [ self._page_addr + i for i,v in enumerate(self._storage) if v is not None ]

    def replace_mo(self, state, old_mo, new_mo):
        if self._sinkhole is old_mo:
            self._sinkhole = new_mo
        else:
            start, end = self._resolve_range(old_mo)
            for i in range(start, end):
                if self._storage[i-self._page_addr] is old_mo:
                    self._storage[i-self._page_addr] = new_mo

    def store_overwrite(self, state, new_mo, start, end):
        if start == self._page_addr and end == self._page_addr + self._page_size:
            self._sinkhole = new_mo
            self._storage = [ None ] * self._page_size
        else:
            for i in range(start, end):
                self._storage[i-self._page_addr] = new_mo

    def store_underwrite(self, state, new_mo, start, end):
        if start == self._page_addr and end == self._page_addr + self._page_size:
            self._sinkhole = new_mo
        else:
            for i in range(start, end):
                if self._storage[i-self._page_addr] is None:
                    self._storage[i-self._page_addr] = new_mo

    def load_mo(self, state, page_idx):
        """
        Loads a memory object from memory.

        :param page_idx: the index into the page
        :returns: a tuple of the object
        """
        mo = self._storage[page_idx-self._page_addr]
        return self._sinkhole if mo is None else mo

    def load_slice(self, state, start, end):
        """
        Return the memory objects overlapping with the provided slice.

        :param start: the start address
        :param end: the end address (non-inclusive)
        :returns: tuples of (starting_addr, memory_object)
        """
        items = [ ]
        if start > self._page_addr + self._page_size or end < self._page_addr:
            l.warning("Calling load_slice on the wrong page.")
            return items

        for addr in range(max(start, self._page_addr), min(end, self._page_addr + self._page_size)):
            i = addr - self._page_addr
            mo = self._storage[i]
            if mo is None:
                mo = self._sinkhole
            if mo is not None and (not items or items[-1][1] is not mo):
                items.append((addr, mo))
        return items

    def _copy_args(self):
        return { 'storage': list(self._storage), 'sinkhole': self._sinkhole }

Page = ListPage

#pylint:disable=unidiomatic-typecheck

class SimPagedMemory(object):
    """
    Represents paged memory.
    """
    def __init__(self, memory_backer=None, permissions_backer=None, pages=None, initialized=None, name_mapping=None, hash_mapping=None, page_size=None, symbolic_addrs=None, check_permissions=False):
        self._cowed = set()
        self._memory_backer = { } if memory_backer is None else memory_backer
        self._permissions_backer = permissions_backer # saved for copying
        self._executable_pages = False if permissions_backer is None else permissions_backer[0]
        self._permission_map = { } if permissions_backer is None else permissions_backer[1]
        self._pages = { } if pages is None else pages
        self._initialized = set() if initialized is None else initialized
        self._page_size = 0x1000 if page_size is None else page_size
        self._symbolic_addrs = dict() if symbolic_addrs is None else symbolic_addrs
        self.state = None
        self._preapproved_stack = xrange(0)
        self._check_perms = check_permissions

        # reverse mapping
        self._name_mapping = cooldict.BranchingDict() if name_mapping is None else name_mapping
        self._hash_mapping = cooldict.BranchingDict() if hash_mapping is None else hash_mapping
        self._updated_mappings = set()

    def __getstate__(self):
        return {
            '_memory_backer': self._memory_backer,
            '_permissions_backer': self._permissions_backer,
            '_executable_pages': self._executable_pages,
            '_permission_map': self._permission_map,
            '_pages': self._pages,
            '_initialized': self._initialized,
            '_page_size': self._page_size,
            'state': None,
            '_name_mapping': self._name_mapping,
            '_hash_mapping': self._hash_mapping,
            '_symbolic_addrs': self._symbolic_addrs,
            '_preapproved_stack': self._preapproved_stack,
            '_check_perms': self._check_perms
        }

    def __setstate__(self, s):
        self._cowed = set()
        self.__dict__.update(s)

    def branch(self):
        new_name_mapping = self._name_mapping.branch() if options.REVERSE_MEMORY_NAME_MAP in self.state.options else self._name_mapping
        new_hash_mapping = self._hash_mapping.branch() if options.REVERSE_MEMORY_HASH_MAP in self.state.options else self._hash_mapping

        new_pages = dict(self._pages)
        m = SimPagedMemory(memory_backer=self._memory_backer,
                           permissions_backer=self._permissions_backer,
                           pages=new_pages,
                           initialized=set(self._initialized),
                           page_size=self._page_size,
                           name_mapping=new_name_mapping,
                           hash_mapping=new_hash_mapping,
                           symbolic_addrs=dict(self._symbolic_addrs),
                           check_permissions=self._check_perms)
        m._preapproved_stack = self._preapproved_stack
        return m

    def __getitem__(self, addr):
        page_num = addr / self._page_size
        page_idx = addr
        #print "GET", addr, page_num, page_idx

        try:
            v = self._get_page(page_num).load_mo(self.state, page_idx)
            return v
        except KeyError:
            raise KeyError(addr)

    def __setitem__(self, addr, v):
        page_num = addr / self._page_size
        page_idx = addr
        #print "SET", addr, page_num, page_idx

        self._get_page(page_num, write=True, create=True)[page_idx] = v
        self._update_mappings(addr, v.object)
        #print "...",id(self._pages[page_num])

    def __delitem__(self, addr):
        raise Exception("For performance reasons, deletion is not supported. Contact Yan if this needs to change.")
        # Specifically, the above is for two reasons:
        #
        #     1. deleting stuff out of memory doesn't make sense
        #     2. if the page throws a key error, the backer dict is accessed. Thus, deleting things would simply
        #        change them back to what they were in the backer dict

    @property
    def allow_segv(self):
        return self._check_perms and not self.state.scratch.priv and options.STRICT_PAGE_ACCESS in self.state.options

    def load_objects(self, addr, num_bytes, ret_on_segv=False):
        """
        Load memory objects from paged memory.

        :param addr: Address to start loading.
        :param num_bytes: Number of bytes to load.
        :param bool ret_on_segv: True if you want load_bytes to return directly when a SIGSEV is triggered, otherwise
                                 a SimSegfaultError will be raised.
        :return: list of tuples of (addr, memory_object)
        :rtype: tuple
        """

        result = [ ]
        end = addr + num_bytes
        for page_addr in self._containing_pages(addr, end):
            try:
                #print "Getting page %x" % (page_addr / self._page_size)
                page = self._get_page(page_addr / self._page_size)
                #print "... got it"
            except KeyError:
                #print "... missing"
                #print "... SEGV"
                # missing page
                if self.allow_segv:
                    if ret_on_segv:
                        break
                    raise SimSegfaultError(page_addr, 'read-miss')
                else:
                    continue

            if self.allow_segv and not page.concrete_permissions & Page.PROT_READ:
                #print "... SEGV"
                if ret_on_segv:
                    break
                raise SimSegfaultError(page_addr, 'non-readable')
            result.extend(page.load_slice(self.state, addr, end))

        return result

    #
    # Page management
    #

    def _create_page(self, page_num, permissions=None):
        return Page(
            page_num*self._page_size, self._page_size,
            executable=self._executable_pages, permissions=permissions
        )

    def _initialize_page(self, n, new_page):
        if n in self._initialized:
            return False
        self._initialized.add(n)

        new_page_addr = n*self._page_size
        initialized = False

        if self.state is not None:
            self.state.scratch.push_priv(True)

        if self._memory_backer is None:
            pass
        elif isinstance(self._memory_backer, cle.Clemory):
            # first, find the right clemory backer
            for addr, backer in self._memory_backer.cbackers:
                start_backer = new_page_addr - addr
                if isinstance(start_backer, BV):
                    continue
                if start_backer < 0 and abs(start_backer) >= self._page_size:
                    continue
                if start_backer >= len(backer):
                    continue

                # find permission backer associated with the address, there should be a
                # memory backer that matches the start_backer. if not fall back to read-write
                flags = Page.PROT_READ | Page.PROT_WRITE
                for start, end in self._permission_map:
                    if start == addr:
                        flags = self._permission_map[(start, end)]
                        break

                snip_start = max(0, start_backer)
                write_start = max(new_page_addr, addr + snip_start)
                write_size = self._page_size - write_start%self._page_size

                snip = _ffi.buffer(backer)[snip_start:snip_start+write_size]
                mo = SimMemoryObject(claripy.BVV(snip), write_start)
                self._apply_object_to_page(n*self._page_size, mo, page=new_page)

                new_page.permissions = claripy.BVV(flags, 3)
                initialized = True

        elif len(self._memory_backer) <= self._page_size:
            for i in self._memory_backer:
                if new_page_addr <= i and i <= new_page_addr + self._page_size:
                    if isinstance(self._memory_backer[i], claripy.ast.Base):
                        backer = self._memory_backer[i]
                    else:
                        backer = claripy.BVV(self._memory_backer[i])
                    mo = SimMemoryObject(backer, i)
                    self._apply_object_to_page(n*self._page_size, mo, page=new_page)
                    initialized = True
        elif len(self._memory_backer) > self._page_size:
            for i in range(self._page_size):
                try:
                    if isinstance(self._memory_backer[i], claripy.ast.Base):
                        backer = self._memory_backer[i]
                    else:
                        backer = claripy.BVV(self._memory_backer[i])
                    mo = SimMemoryObject(backer, new_page_addr+i)
                    self._apply_object_to_page(n*self._page_size, mo, page=new_page)
                    initialized = True
                except KeyError:
                    pass

        if self.state is not None:
            self.state.scratch.pop_priv()
        return initialized

    def _get_page(self, page_num, write=False, create=False, initialize=True):
        page_addr = page_num * self._page_size
        try:
            page = self._pages[page_num]
        except KeyError:
            if not (initialize or create or page_addr in self._preapproved_stack):
                raise

            page = self._create_page(page_num)
            self._symbolic_addrs[page_num] = set()
            if initialize:
                initialized = self._initialize_page(page_num, page)
                if not initialized and not create and page_addr not in self._preapproved_stack:
                    raise

            self._pages[page_num] = page
            self._cowed.add(page_num)
            return page

        if write and page_num not in self._cowed:
            page = page.copy()
            self._symbolic_addrs[page_num] = set(self._symbolic_addrs[page_num])
            self._cowed.add(page_num)
            self._pages[page_num] = page

        return page

    def __contains__(self, addr):
        try:
            return self.__getitem__(addr) is not None
        except KeyError:
            return False

    def contains_no_backer(self, addr):
        """
        Tests if the address is contained in any page of paged memory, without considering memory backers.

        :param int addr: The address to test.
        :return: True if the address is included in one of the pages, False otherwise.
        :rtype: bool
        """

        for i, p in self._pages.iteritems():
            if i * self._page_size <= addr < (i + 1) * self._page_size:
                return addr - (i * self._page_size) in p.keys()
        return False

    def keys(self):
        sofar = set()
        sofar.update(self._memory_backer.keys())

        for i, p in self._pages.items():
            sofar.update([k + i * self._page_size for k in p.keys()])

        return sofar

    def __len__(self):
        return len(self.keys())

    def changed_bytes(self, other):
        return self.__changed_bytes(other)

    def __changed_bytes(self, other):
        """
        Gets the set of changed bytes between `self` and `other`.

        :type other:    SimPagedMemory
        :returns:       A set of differing bytes.
        """
        if self._page_size != other._page_size:
            raise SimMemoryError("SimPagedMemory page sizes differ. This is asking for disaster.")

        our_pages = set(self._pages.keys())
        their_pages = set(other._pages.keys())
        their_additions = their_pages - our_pages
        our_additions = our_pages - their_pages
        common_pages = our_pages & their_pages

        candidates = set()
        for p in their_additions:
            candidates.update(other._pages[p].keys())
        for p in our_additions:
            candidates.update(self._pages[p].keys())

        for p in common_pages:
            our_page = self._pages[p]
            their_page = other._pages[p]

            if our_page is their_page:
                continue

            our_keys = set(our_page.keys())
            their_keys = set(their_page.keys())
            changes = (our_keys - their_keys) | (their_keys - our_keys) | {
                i for i in (our_keys & their_keys) if our_page.load_mo(self.state, i) is not their_page.load_mo(self.state, i)
            }
            candidates.update(changes)

        #both_changed = our_changes & their_changes
        #ours_changed_only = our_changes - both_changed
        #theirs_changed_only = their_changes - both_changed
        #both_deleted = their_deletions & our_deletions
        #ours_deleted_only = our_deletions - both_deleted
        #theirs_deleted_only = their_deletions - both_deleted

        differences = set()
        for c in candidates:
            if c not in self and c in other:
                differences.add(c)
            elif c in self and c not in other:
                differences.add(c)
            else:
                if type(self[c]) is not SimMemoryObject:
                    self[c] = SimMemoryObject(self.state.se.BVV(ord(self[c]), 8), c)
                if type(other[c]) is not SimMemoryObject:
                    other[c] = SimMemoryObject(self.state.se.BVV(ord(other[c]), 8), c)
                if c in self and self[c] != other[c]:
                    # Try to see if the bytes are equal
                    self_byte = self[c].bytes_at(c, 1)
                    other_byte = other[c].bytes_at(c, 1)
                    if self_byte is not other_byte:
                        #l.debug("%s: offset %x, two different bytes %s %s from %s %s", self.id, c,
                        #        self_byte, other_byte,
                        #        self[c].object.model, other[c].object.model)
                        differences.add(c)
                else:
                    # this means the byte is in neither memory
                    pass

        return differences

    #
    # Memory object management
    #

    def _apply_object_to_page(self, page_base, mo, page=None, overwrite=True):
        """
        Writes a memory object to a `page`

        :param page_base:   The base address of the page.
        :param mo:          The memory object.
        :param page:        (optional) the page to use.
        :param overwrite:   (optional) If False, only write to currently-empty memory.
        """
        page_num = page_base / self._page_size
        try:
            page = self._get_page(page_num,
                                  write=True,
                                  create=not self.allow_segv) if page is None else page
        except KeyError:
            if self.allow_segv:
                raise SimSegfaultError(mo.base, 'write-miss')
            else:
                raise
        if self.allow_segv and not page.concrete_permissions & Page.PROT_WRITE:
            raise SimSegfaultError(mo.base, 'non-writable')

        page.store_mo(self.state, mo, overwrite=overwrite)
        return True

    def _containing_pages(self, mo_start, mo_end):
        page_start = mo_start - mo_start%self._page_size
        page_end = mo_end + (self._page_size - mo_end%self._page_size) if mo_end % self._page_size else mo_end
        return [ b for b in range(page_start, page_end, self._page_size) ]

    def _containing_pages_mo(self, mo):
        mo_start = mo.base
        mo_end = mo.base + mo.length
        return self._containing_pages(mo_start, mo_end)

    def store_memory_object(self, mo, overwrite=True):
        """
        This function optimizes a large store by storing a single reference to the :class:`SimMemoryObject` instead of
        one for each byte.

        :param memory_object: the memory object to store
        """

        for p in self._containing_pages_mo(mo):
            self._apply_object_to_page(p, mo, overwrite=overwrite)

        self._update_range_mappings(mo.base, mo.object, mo.length)

    def replace_memory_object(self, old, new_content):
        """
        Replaces the memory object `old` with a new memory object containing `new_content`.

        :param old:         A SimMemoryObject (i.e., one from :func:`memory_objects_for_hash()` or :func:`
                            memory_objects_for_name()`).
        :param new_content: The content (claripy expression) for the new memory object.
        :returns: the new memory object
        """

        if old.object.size() != new_content.size():
            raise SimMemoryError("memory objects can only be replaced by the same length content")

        new = SimMemoryObject(new_content, old.base)
        for p in self._containing_pages_mo(old):
            self._get_page(p/self._page_size, write=True).replace_mo(self.state, old, new)

        if isinstance(new.object, claripy.ast.BV):
            for b in range(old.base, old.base+old.length):
                self._update_mappings(b, new.object)
        return new

    def replace_all(self, old, new):
        """
        Replaces all instances of expression `old` with expression `new`.

        :param old: A claripy expression. Must contain at least one named variable (to make it possible to use the
                    name index for speedup).
        :param new: The new variable to replace it with.
        """

        if options.REVERSE_MEMORY_NAME_MAP not in self.state.options:
            raise SimMemoryError("replace_all is not doable without a reverse name mapping. Please add "
                                 "sim_options.REVERSE_MEMORY_NAME_MAP to the state options")

        if not isinstance(old, claripy.ast.BV) or not isinstance(new, claripy.ast.BV):
            raise SimMemoryError("old and new arguments to replace_all() must be claripy.BV objects")

        if len(old.variables) == 0:
            raise SimMemoryError("old argument to replace_all() must have at least one named variable")

        # Compute an intersection between sets of memory objects for each unique variable name. The eventual memory
        # object set contains all memory objects that we should update.
        memory_objects = None
        for v in old.variables:
            if memory_objects is None:
                memory_objects = self.memory_objects_for_name(v)
            elif len(memory_objects) == 0:
                # It's a set and it's already empty
                # there is no way for it to go back...
                break
            else:
                memory_objects &= self.memory_objects_for_name(v)

        replaced_objects_cache = { }
        for mo in memory_objects:
            replaced_object = None

            if mo.object in replaced_objects_cache:
                if mo.object is not replaced_objects_cache[mo.object]:
                    replaced_object = replaced_objects_cache[mo.object]

            else:
                replaced_object = mo.object.replace(old, new)
                replaced_objects_cache[mo.object] = replaced_object
                if mo.object is replaced_object:
                    # The replace does not really occur
                    replaced_object = None

            if replaced_object is not None:
                self.replace_memory_object(mo, replaced_object)

    #
    # Mapping bullshit
    #

    def _mark_updated_mapping(self, d, m):
        if m in self._updated_mappings:
            return

        if options.REVERSE_MEMORY_HASH_MAP not in self.state.options and d is self._hash_mapping:
            #print "ABORTING FROM HASH"
            return
        if options.REVERSE_MEMORY_NAME_MAP not in self.state.options and d is self._name_mapping:
            #print "ABORTING FROM NAME"
            return
        #print m
        #SimSymbolicMemory.wtf += 1
        #print SimSymbolicMemory.wtf

        try:
            d[m] = set(d[m])
        except KeyError:
            d[m] = set()
        self._updated_mappings.add(m)

    def _update_range_mappings(self, actual_addr, cnt, size):
        if not (options.REVERSE_MEMORY_NAME_MAP in self.state.options or
                options.REVERSE_MEMORY_HASH_MAP in self.state.options or
                options.MEMORY_SYMBOLIC_BYTES_MAP in self.state.options):
            return

        for i in range(actual_addr, actual_addr+size):
            self._update_mappings(i, cnt)

    def _update_mappings(self, actual_addr, cnt):
        if options.MEMORY_SYMBOLIC_BYTES_MAP in self.state.options:
            page_num = actual_addr / self._page_size
            page_idx = actual_addr
            if self.state.se.symbolic(cnt):
                self._symbolic_addrs[page_num].add(page_idx)
            else:
                self._symbolic_addrs[page_num].discard(page_idx)

        if not (options.REVERSE_MEMORY_NAME_MAP in self.state.options or
                options.REVERSE_MEMORY_HASH_MAP in self.state.options):
            return

        if (options.REVERSE_MEMORY_HASH_MAP not in self.state.options) and \
                len(self.state.se.variables(cnt)) == 0:
           return

        l.debug("Updating mappings at address 0x%x", actual_addr)

        try:
            l.debug("... removing old mappings")

            # remove this address for the old variables
            old_obj = self[actual_addr]
            if isinstance(old_obj, SimMemoryObject):
                old_obj = old_obj.object

            if isinstance(old_obj, claripy.ast.BV):
                if options.REVERSE_MEMORY_NAME_MAP in self.state.options:
                    var_set = self.state.se.variables(old_obj)
                    for v in var_set:
                        self._mark_updated_mapping(self._name_mapping, v)
                        self._name_mapping[v].discard(actual_addr)
                        if len(self._name_mapping[v]) == 0:
                            self._name_mapping.pop(v, None)

                if options.REVERSE_MEMORY_HASH_MAP in self.state.options:
                    h = hash(old_obj)
                    self._mark_updated_mapping(self._hash_mapping, h)
                    self._hash_mapping[h].discard(actual_addr)
                    if len(self._hash_mapping[h]) == 0:
                        self._hash_mapping.pop(h, None)
        except KeyError:
            pass

        l.debug("... adding new mappings")
        if options.REVERSE_MEMORY_NAME_MAP in self.state.options:
            # add the new variables to the mapping
            var_set = self.state.se.variables(cnt)
            for v in var_set:
                self._mark_updated_mapping(self._name_mapping, v)
                if v not in self._name_mapping:
                    self._name_mapping[v] = set()
                self._name_mapping[v].add(actual_addr)

        if options.REVERSE_MEMORY_HASH_MAP in self.state.options:
            # add the new variables to the hash->addrs mapping
            h = hash(cnt)
            self._mark_updated_mapping(self._hash_mapping, h)
            if h not in self._hash_mapping:
                self._hash_mapping[h] = set()
            self._hash_mapping[h].add(actual_addr)

    def get_symbolic_addrs(self):
        symbolic_addrs = set()
        for page in self._symbolic_addrs:
            symbolic_addrs.update(page*self._page_size + page_off for page_off in self._symbolic_addrs[page])
        return symbolic_addrs

    def addrs_for_name(self, n):
        """
        Returns addresses that contain expressions that contain a variable named `n`.
        """
        if n not in self._name_mapping:
            return

        self._mark_updated_mapping(self._name_mapping, n)

        to_discard = set()
        for e in self._name_mapping[n]:
            try:
                if n in self[e].object.variables: yield e
                else: to_discard.add(e)
            except KeyError:
                to_discard.add(e)
        self._name_mapping[n] -= to_discard

    def addrs_for_hash(self, h):
        """
        Returns addresses that contain expressions that contain a variable with the hash of `h`.
        """
        if h not in self._hash_mapping:
            return

        self._mark_updated_mapping(self._hash_mapping, h)

        to_discard = set()
        for e in self._hash_mapping[h]:
            try:
                if h == hash(self[e].object): yield e
                else: to_discard.add(e)
            except KeyError:
                to_discard.add(e)
        self._hash_mapping[h] -= to_discard

    def memory_objects_for_name(self, n):
        """
        Returns a set of :class:`SimMemoryObjects` that contain expressions that contain a variable with the name of
        `n`.

        This is useful for replacing those values in one fell swoop with :func:`replace_memory_object()`, even if
        they have been partially overwritten.
        """
        return set([ self[i] for i in self.addrs_for_name(n)])

    def memory_objects_for_hash(self, n):
        """
        Returns a set of :class:`SimMemoryObjects` that contain expressions that contain a variable with the hash
        `h`.
        """
        return set([ self[i] for i in self.addrs_for_hash(n)])

    def permissions(self, addr, permissions=None):
        """
        Returns the permissions for a page at address `addr`.

        If optional arugment permissions is given, set page permissions to that prior to returning permissions.
        """

        if self.state.se.symbolic(addr):
            raise SimMemoryError("page permissions cannot currently be looked up for symbolic addresses")

        if isinstance(addr, claripy.ast.bv.BV):
            addr = self.state.se.any_int(addr)

        page_num = addr / self._page_size

        try:
            page = self._get_page(page_num)
        except KeyError:
            raise SimMemoryError("page does not exist at given address")

        # Set permissions for the page
        if permissions is not None:
            if isinstance(permissions, (int, long)):
                permissions = claripy.BVV(permissions, 3)

            if not isinstance(permissions,claripy.ast.bv.BV):
                raise SimMemoryError("Unknown permissions argument type of {0}.".format(type(permissions)))

            page.permissions = permissions

        return page.permissions

    def map_region(self, addr, length, permissions, init_zero=False):
        if o.TRACK_MEMORY_MAPPING not in self.state.options:
            return

        if self.state.se.symbolic(addr):
            raise SimMemoryError("cannot map region with a symbolic address")

        if isinstance(addr, claripy.ast.bv.BV):
            addr = self.state.se.max_int(addr)

        base_page_num = addr / self._page_size

        # round length
        pages = length / self._page_size
        if length % self._page_size > 0:
            pages += 1

        # this check should not be performed when constructing a CFG
        if self.state.mode != 'fastpath':
            for page in xrange(pages):
                page_id = base_page_num + page
                if page_id * self._page_size in self:
                    err = "map_page received address and length combination which contained mapped page"
                    l.warning(err)
                    raise SimMemoryError(err)

        if isinstance(permissions, (int, long)):
            permissions = claripy.BVV(permissions, 3)

        for page in xrange(pages):
            page_id = base_page_num + page
            self._pages[page_id] = self._create_page(page_id, permissions=permissions)
            if init_zero:
                mo = SimMemoryObject(claripy.BVV(0, self._page_size * 8), page_id*self._page_size)
                self._apply_object_to_page(page_id*self._page_size, mo, page=self._pages[page_id])
            self._symbolic_addrs[page_id] = set()

    def unmap_region(self, addr, length):
        if o.TRACK_MEMORY_MAPPING not in self.state.options:
            return

        if self.state.se.symbolic(addr):
            raise SimMemoryError("cannot unmap region with a symbolic address")

        if isinstance(addr, claripy.ast.bv.BV):
            addr = self.state.se.max_int(addr)

        base_page_num = addr / self._page_size

        pages = length / self._page_size
        if length % self._page_size > 0:
            pages += 1

        # this check should not be performed when constructing a CFG
        if self.state.mode != 'fastpath':
            for page in xrange(pages):
                if base_page_num + page not in self._pages:
                    l.warning("unmap_region received address and length combination is not mapped")
                    return

        for page in xrange(pages):
            del self._pages[base_page_num + page]
            del self._symbolic_addrs[base_page_num + page]

from .. import sim_options as o
