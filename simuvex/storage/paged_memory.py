import cooldict
import claripy
import cffi
import cle

from ..s_errors import SimMemoryError
from .. import s_options as options
from .memory_object import SimMemoryObject
from claripy.ast.bv import BV

_ffi = cffi.FFI()

import logging
l = logging.getLogger('simuvex.storage.paged_memory')

#_internal_storage = cooldict.SinkholeCOWDict
#_internal_storage = list
_internal_storage = dict

class Page(object):
    '''
    Page object, allowing for more flexibilty than just a raw dict
    '''

    PROT_READ = 1
    PROT_WRITE = 2
    PROT_EXEC = 4

    def __init__(self, page_size, permissions=None, executable=False):
        '''
        Create a new page object. Carries permissions information. Permissions default to RW unless
        `executable` is True in which case permissions default to RWX.

        :param page_size: self-explanatory
        :param executable: if the page is executable, typically this will depend on whether the binary has an
            executbale stack
        '''

        self._page_size = page_size
        self._storage = [None]*page_size if _internal_storage is list else _internal_storage()

        if permissions is None:
            perms = Page.PROT_READ|Page.PROT_WRITE
            if executable:
                perms |= Page.PROT_EXEC
            self.permissions = claripy.BVV(perms, 3) # 3 bits is enough for PROT_EXEC, PROT_WRITE, PROT_READ, PROT_NONE
        else:
            self.permissions = permissions

    def keys(self):

        return self._storage.keys()

    def __contains__(self, item):

        return item in self._storage

    def __getitem__(self, idx):
        '''
        I think we assume that idx has already been modded by page_size.
        '''

        return self._storage[idx]

    def __setitem__(self, idx, item):

        self._storage[idx] = item

    def copy(self):
        p = Page(self._page_size)
        p._storage = _internal_storage(self._storage)
        p.permissions = self.permissions
        return p

_storage = Page

#pylint:disable=unidiomatic-typecheck

class SimPagedMemory(object):
    def __init__(self, memory_backer=None, permissions_backer=None, pages=None, sinkholes=None, initialized=None, name_mapping=None, hash_mapping=None, page_size=None):
        self._cowed = set()
        self._memory_backer = { } if memory_backer is None else memory_backer
        self._permissions_backer = permissions_backer # saved for copying
        self._executable_pages = False if permissions_backer is None else permissions_backer[0]
        self._permission_map = { } if permissions_backer is None else permissions_backer[1]
        self._pages = { } if pages is None else pages
        self._sinkholes = { } if sinkholes is None else sinkholes
        self._sinkholes_cowed = False
        self._initialized = set() if initialized is None else initialized
        self._page_size = 0x1000 if page_size is None else page_size
        self.state = None

        # reverse mapping
        self._name_mapping = cooldict.BranchingDict() if name_mapping is None else name_mapping
        self._hash_mapping = cooldict.BranchingDict() if hash_mapping is None else hash_mapping
        self._updated_mappings = set()

    def __getstate__(self):
        return {
            '_memory_backer': self._memory_backer,
            '_executable_pages': self._executable_pages,
            '_permission_map': self._permission_map,
            '_pages': self._pages,
            '_sinkholes': self._sinkholes,
            '_initialized': self._initialized,
            '_page_size': self._page_size,
            'state': self.state,
            '_name_mapping': self._name_mapping,
            '_hash_mapping': self._hash_mapping,
        }

    def __setstate__(self, s):
        self.__dict__.update(s)

    def branch(self):
        new_name_mapping = self._name_mapping.branch() if options.REVERSE_MEMORY_NAME_MAP in self.state.options else self._name_mapping
        new_hash_mapping = self._hash_mapping.branch() if options.REVERSE_MEMORY_HASH_MAP in self.state.options else self._hash_mapping

        if _storage is cooldict.SinkholeCOWDict:
            new_pages = { k:v.branch() for k,v in self._pages.iteritems() }
        else:
            new_pages = dict(self._pages)

        self._sinkholes_cowed = False
        m = SimPagedMemory(memory_backer=self._memory_backer,
                           permissions_backer=self._permissions_backer,
                           pages=new_pages,
                           sinkholes=self._sinkholes,
                           initialized=set(self._initialized),
                           page_size=self._page_size,
                           name_mapping=new_name_mapping,
                           hash_mapping=new_hash_mapping)
        return m

    def __getitem__(self, addr):
        page_num = addr / self._page_size
        page_idx = addr % self._page_size
        #print "GET", addr, page_num, page_idx

        try:
            v = self._get_page(page_num)[page_idx]
        except KeyError:
            v = None

        if v is not None:
            return v
        elif self._sinkholed(page_num):
            return self._sinkhole_value(page_num)
        else:
            raise KeyError(addr)

    def __setitem__(self, addr, v):
        page_num = addr / self._page_size
        page_idx = addr % self._page_size
        #print "SET", addr, page_num, page_idx

        self._update_mappings(addr, v.object)
        self._get_page(page_num, write=True, create=True)[page_idx] = v
        #print "...",id(self._pages[page_num])

    def __delitem__(self, addr):
        raise Exception("For performance reasons, deletion is not supported. Contact Yan if this needs to change.")
        # Specifically, the above is for two reasons:
        #
        #     1. deleting stuff out of memory doesn't make sense
        #     2. if the page throws a key error, the backer dict is accessed. Thus, deleting things would simply
        #        change them back to what they were in the backer dict

    def _next_not(self, page, page_idx, addr_end, what):
        if _storage is cooldict.SinkholeCOWDict:
            return 0 if len(page.keys()) != 0 else min(self._page_size, page_idx+addr_end) - page_idx
        else:
            for j in range(page_idx, min(self._page_size, page_idx+addr_end)):
                try:
                    if page[j] is not what:
                        return j - page_idx
                except KeyError:
                    return j - page_idx
            return min(self._page_size, page_idx+addr_end) - page_idx

    def load_bytes(self, addr, num_bytes):
        missing = [ ]
        the_bytes = { }

        l.debug("Reading from memory at %#x", addr)
        i = 0
        old_page_num = None

        while i < num_bytes:
            actual_addr = addr + i
            page_num = actual_addr / self._page_size
            page_idx = actual_addr % self._page_size

            try:
                if old_page_num != page_num:
                    page = self._get_page(page_num)
                    old_page_num = page_num

                try:
                    v = page[page_idx]
                except KeyError:
                    v = None

                if v is not None:
                    # this value is present
                    the_bytes[i] = v
                    i += 1 + self._next_not(page, page_idx+1, num_bytes-i, v)
                elif self._sinkholed(page_num):
                    # this is a sinkholed value
                    the_bytes[i] = self._sinkhole_value(page_num)
                    i += 1 + self._next_not(page, page_idx+1, num_bytes-i, None)
                else:
                    # missing value
                    missing.append(i)
                    i += 1 + self._next_not(page, page_idx+1, num_bytes-i, None)
            except KeyError:
                if self._sinkholed(page_num):
                    # missing page, but sinkholed value
                    the_bytes[i] = self._sinkhole_value(page_num)
                else:
                    # missing page, missing value
                    missing.append(i)
                i += self._page_size - actual_addr%self._page_size


        l.debug("... %d found, %d missing", len(the_bytes), len(missing))
        return the_bytes, missing

    #
    # Page management
    #

    def _create_page(self): #pylint:disable=no-self-use,unused-argument
        if _storage is list:
            return [None]*self._page_size
        else:
            return Page(self._page_size, executable=self._executable_pages)

    @staticmethod
    def _copy_page(page):
        if _storage is cooldict.SinkholeCOWDict:
            return page.branch()
        else:
            return page.copy()

    def _initialize_page(self, n, new_page):
        if n in self._initialized:
            return False
        self._initialized.add(n)

        new_page_addr = n*self._page_size
        initialized = False

        if self._memory_backer is None:
            pass
        elif isinstance(self._memory_backer, cle.Clemory):
            # first, find the right clemory backer
            for addr, backer in self._memory_backer.cbackers:
                start_backer = new_page_addr - addr
                if isinstance(start_backer, BV):
                    continue
                if start_backer < 0 and abs(start_backer) > self._page_size:
                    continue
                if start_backer > len(backer):
                    continue

                # find permission backer associated with the address, there should be a
                # memory backer that matches the start_backer
                flags = None
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

        elif len(self._memory_backer) < self._page_size:
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

        return initialized

    def _get_page(self, page_num, write=False, create=False, initialize=True):
        try:
            page = self._pages[page_num]
        except KeyError:
            if not (initialize or create):
                raise

            page = self._create_page()
            if initialize:
                initialized = self._initialize_page(page_num, page)
                if not initialized and not create:
                    raise

            self._pages[page_num] = page
            self._cowed.add(page_num)
            return page

        if write and page_num not in self._cowed:
            page = self._copy_page(page)
            self._cowed.add(page_num)
            self._pages[page_num] = page

        return page

    def _sinkhole(self, page_num, value, page=None, wipe=True):
        if _storage is cooldict.SinkholeCOWDict:
            if page is None:
                page = self._get_page(page_num, initialize=False, create=True, write=True)
            page.sinkhole(value, wipe=wipe) #pylint:disable=no-member
        else:
            if not self._sinkholes_cowed:
                self._sinkholes_cowed = True
                self._sinkholes = dict(self._sinkholes)

            self._sinkholes[page_num] = value
            if wipe:
                try:
                    del self._pages[page_num]
                except KeyError:
                    pass

    def _sinkholed(self, page_num):
        if _storage is cooldict.SinkholeCOWDict:
            return False if page_num not in self._pages else self._pages[page_num]._sinkholed
        else:
            return page_num in self._sinkholes

    def _sinkhole_value(self, page_num):
        if _storage is cooldict.SinkholeCOWDict:
            return self._pages[page_num]._sinkhole_value
        else:
            try:
                return self._sinkholes[page_num]
            except KeyError:
                return None

    def __contains__(self, addr):
        try:
            return self.__getitem__(addr) is not None
        except KeyError:
            return False

    def keys(self):
        sofar = set()
        for s in self._sinkholes:
            sofar.update(range(s*self._page_size, (s+1)*self._page_size))

        sofar.update(self._memory_backer.keys())

        for p in self._pages:
            if not self._sinkholed(p):
                sofar.update(p*self._page_size + a for a in self._page_keys(self._pages[p]))
            else:
                sofar.update(range(p*self._page_size, (p+1)*self._page_size))

        return sofar

    def __len__(self):
        return sum((len(self._page_keys(k)) if not self._sinkholed(k) else self._page_size) for k in self._pages.iterkeys())

    def _page_keys(self, page):
        if _storage is list:
            return set(e for e,v in enumerate(page) if v is not None)
        elif _storage is cooldict.SinkholeCOWDict:
            return set(page.keys()) if not page._sinkholed else set(range(0, self._page_size))
        else:
            return set(page.keys())

    def changed_bytes(self, other):
        '''
        Gets the set of changed bytes between self and other.

        @param other: the other SimPagedMemory
        @returns a set of differing bytes
        '''
        if self._page_size != other._page_size:
            raise SimMemoryError("SimPagedMemory page sizes differ. This is asking for disaster.")

        our_pages = set(self._pages.keys())
        their_pages = set(other._pages.keys())
        their_additions = their_pages - our_pages
        our_additions = our_pages - their_pages
        common_pages = our_pages & their_pages

        candidates = set()
        for p in their_additions:
            candidates.update([ (p*self._page_size)+i for i in self._page_keys(other._pages[p]) ])
        for p in our_additions:
            candidates.update([ (p*self._page_size)+i for i in self._page_keys(self._pages[p]) ])

        for p in common_pages:
            our_page = self._pages[p]
            their_page = other._pages[p]

            if our_page is their_page:
                continue
            if _storage is cooldict.SinkholeCOWDict and our_page.common_ancestor(their_page) is not None:
                continue

            our_keys = self._page_keys(our_page)
            their_keys = self._page_keys(their_page)
            changes = (our_keys - their_keys) | (their_keys - our_keys) | { i for i in (our_keys & their_keys) if our_page[i] is not their_page[i] }
            candidates.update([ (p*self._page_size)+i for i in changes ])

        our_sinkholes = set(self._sinkholes.keys())
        their_sinkholes = set(other._sinkholes.keys())
        sinkhole_changes = (our_sinkholes - their_sinkholes) | (their_sinkholes - our_sinkholes)
        for s in our_sinkholes & their_sinkholes:
            if self._sinkholes[s] is not other._sinkholes[s]:
                sinkhole_changes.add(s)

        for s in sinkhole_changes:
            candidates.update(range(s*self._page_size, (s+1)*self._page_size))

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
                    if not self_byte is other_byte:
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
        '''
        Writes a memory object to a page, sinkholing if appropriate.

        @param page_base: the base address of the page
        @param mo: the memory object
        @param page: (optionally) the page to use
        @param overwrite: if False, only write to currently-empty
                          memory
        @returns True if the write went to the page, False if it got
                 sinkholed
        '''
        page_num = page_base / self._page_size
        if mo.base <= page_base and mo.base + mo.length >= page_base + self._page_size:
            # takes up the whole page
            self._sinkhole(page_num, mo, page=page, wipe=overwrite)
            return False if _storage is not cooldict.SinkholeCOWDict else True
        else:
            page = self._get_page(page_num, write=True, create=True) if page is None else page
            for a in range(max(mo.base, page_base), min(mo.base+mo.length, page_base+self._page_size)):
                if overwrite or (type(page) is list and page[a%self._page_size] is None) or (type(page) is not list and a%self._page_size not in page):
                    page[a%self._page_size] = mo
            return True

    def store_memory_object(self, mo, overwrite=True):
        '''
        This function optimizes a large store by storing a single reference to
        the SimMemoryObject instead of one for each byte.

        @param memory_object: the memory object to store
        '''

        self._update_range_mappings(mo.base, mo.object, mo.length)

        mo_start = mo.base
        mo_end = mo.base + mo.length
        page_start = mo_start - mo_start%self._page_size
        page_end = mo_end + (self._page_size - mo_end%self._page_size) if mo_end % self._page_size else mo_end
        pages = [ b for b in range(page_start, page_end, self._page_size) ]

        for p in pages:
            self._apply_object_to_page(p, mo, overwrite=overwrite)

    def replace_memory_object(self, old, new_content):
        '''
        Replaces the memory object 'old' with a new memory object containing
        'new_content'.

            @param old: a SimMemoryObject (i.e., one from memory_objects_for_hash() or
                        memory_objects_for_name())
            @param new_content: the content (claripy expression) for the new memory object
        '''

        if old.object.size() != new_content.size():
            raise SimMemoryError("memory objects can only be replaced by the same length content")

        new = SimMemoryObject(new_content, old.base)
        for b in range(old.base, old.base+old.length):
            try:
                here = self[b]
                if here is not old:
                    continue

                if isinstance(new.object, claripy.ast.BV):
                    self._update_mappings(b, new.object)
                self[b] = new
            except KeyError:
                pass

    def replace_all(self, old, new):
        '''
        Replaces all instances of expression old with expression new.

            @param old: a claripy expression. Must contain at least one named variable (to make
                        to make it possible to use the name index for speedup)
            @param new: the new variable to replace it with
        '''

        if options.REVERSE_MEMORY_NAME_MAP not in self.state.options:
            raise SimMemoryError("replace_all is not doable without a reverse name mapping. Please add simuvex.o.REVERSE_MEMORY_NAME_MAP to the state options")

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
                options.REVERSE_MEMORY_HASH_MAP in self.state.options):
            return

        for i in range(actual_addr, actual_addr+size):
            self._update_mappings(i, cnt)

    def _update_mappings(self, actual_addr, cnt):
        if not (options.REVERSE_MEMORY_NAME_MAP in self.state.options or
                options.REVERSE_MEMORY_HASH_MAP in self.state.options):
            return

        if (options.REVERSE_MEMORY_HASH_MAP not in self.state.options) and \
                len(self.state.se.variables(cnt)) == 0:
           return

        l.debug("Updating mappings at address 0x%x", actual_addr)

        try:
            old_obj = self[actual_addr]
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

    def addrs_for_name(self, n):
        '''
        Returns addresses that contain expressions that contain a variable
        named n.
        '''
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
        '''
        Returns addresses that contain expressions that contain a variable
        with the hash of h.
        '''
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
        '''
        Returns a set of SimMemoryObjects that contain expressions that contain a variable
        with the name of n. This is useful for replacing those values, in one fell swoop,
        with replace_memory_object(), even if they've been partially overwritten.
        '''
        return set([ self[i] for i in self.addrs_for_name(n)])

    def memory_objects_for_hash(self, n):
        '''
        Returns a set of SimMemoryObjects that contain expressions that contain a variable
        with the hash of h. This is useful for replacing those values, in one fell swoop,
        with replace_memory_object(), even if they've been partially overwritten.
        '''
        return set([ self[i] for i in self.addrs_for_hash(n)])

    def permissions(self, addr):
        '''
        Returns the permissions for a page at address, `addr`.
        '''

        if self.state.se.symbolic(addr):
            raise ValueError("page permissions cannot currently be looked up for symbolic addresses")

        if isinstance(addr, claripy.ast.bv.BV):
            addr = self.state.se.any_int(addr)

        page_num = addr / self._page_size

        return self._get_page(page_num).permissions

    def map_region(self, addr, length, permissions):

        if self.state.se.symbolic(addr):
            raise ValueError("cannot map region with a symbolic address")

        if isinstance(addr, claripy.ast.bv.BV):
            addr = self.state.se.max_int(addr)

        base_page_num = addr / self._page_size

        # round length
        pages = length / self._page_size
        if length % self._page_size > 0:
            pages += 1

        for page in xrange(pages):
            if base_page_num + page in self._pages:
                raise ValueError("map_page received address and length combination which contained mapped page")

        if isinstance(permissions, (int, long)):
            permissions = claripy.BVV(permissions, 3)

        for page in xrange(pages):
            self._pages[base_page_num + page] = Page(self._page_size, permissions)
