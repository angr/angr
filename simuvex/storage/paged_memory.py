import collections
import cooldict
import claripy

from ..s_errors import SimMemoryError
from .. import s_options as options
from .memory_object import SimMemoryObject

import logging
l = logging.getLogger('simuvex.storage.paged_memory')

#pylint:disable=unidiomatic-typecheck

class SimPagedMemory(collections.MutableMapping):
    def __init__(self, backer=None, pages=None, name_mapping=None, hash_mapping=None, page_size=None):
        self._backer = { } if backer is None else backer
        self._pages = { } if pages is None else pages
        self._page_size = 0x1000 if page_size is None else page_size
        self.state = None

        # reverse mapping
        self._name_mapping = cooldict.BranchingDict() if name_mapping is None else name_mapping
        self._hash_mapping = cooldict.BranchingDict() if hash_mapping is None else hash_mapping
        self._updated_mappings = set()

    def __getstate__(self):
        import pickle
        try:
            pickle.dumps(self._pages)
        except TypeError:
            __import__('ipdb').set_trace()
        return {
            # '_backer': self._backer,
            # '_pages': self._pages,
            '_page_size': self._page_size,
            'state': self.state,
            '_name_mapping': self._name_mapping,
            '_hash_mapping': self._hash_mapping,
        }

    def __setstate__(self, s):
        self.__dict__.update(s)

    def branch(self):
        new_pages = { k:v.branch() for k,v in self._pages.iteritems() }
        new_name_mapping = self._name_mapping.branch() if options.REVERSE_MEMORY_NAME_MAP in self.state.options else self._name_mapping
        new_hash_mapping = self._hash_mapping.branch() if options.REVERSE_MEMORY_HASH_MAP in self.state.options else self._hash_mapping

        m = SimPagedMemory(backer=self._backer,
                           pages=new_pages,
                           page_size=self._page_size,
                           name_mapping=new_name_mapping,
                           hash_mapping=new_hash_mapping)
        return m

    def __getitem__(self, addr):
        page_num = addr / self._page_size
        page_idx = addr % self._page_size
        #print "GET", addr, page_num, page_idx

        try:
            return self._pages[page_num][page_idx]
        except KeyError:
            return self._backer[addr]

    def __setitem__(self, addr, v):
        page_num = addr / self._page_size
        page_idx = addr % self._page_size
        #print "SET", addr, page_num, page_idx

        self._update_mappings(addr, v.object)
        if page_num not in self._pages:
            self._pages[page_num] = cooldict.COWDict()
        self._pages[page_num][page_idx] = v
        #print "...",id(self._pages[page_num])

    def __delitem__(self, addr):
        raise Exception("For performance reasons, deletion is not supported. Contact Yan if this needs to change.")
        # Specifically, the above is for two reasons:
        #
        #    1. deleting stuff out of memory doesn't make sense
        #    2. if the page throws a key error, the backer dict is accessed. Thus, deleting things would simply
        #       change them back to what they were in the backer dict

        #page_num = addr / self._page_size
        #page_idx = addr % self._page_size
        ##print "DEL", addr, page_num, page_idx

        #if page_num not in self._pages:
        #    self._pages[page_num] = cooldict.BranchingDict(d=self._backer)
        #del self._pages[page_num][page_idx]

    def __contains__(self, addr):
        try:
            self.__getitem__(addr)
            return True
        except KeyError:
            return False

    def __iter__(self):
        for k in self._backer:
            yield k
        for p in self._pages:
            for a in self._pages[p]:
                yield p*self._page_size + a

    def __len__(self):
        return len(self._backer) + sum(len(v) for v in self._pages.itervalues())

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
            candidates.update([ (p*self._page_size)+i for i in other._pages[p] ])
        for p in our_additions:
            candidates.update([ (p*self._page_size)+i for i in self._pages[p] ])

        for p in common_pages:
            our_page = self._pages[p]
            their_page = other._pages[p]

            common_ancestor = our_page.common_ancestor(their_page)
            if common_ancestor == None:
                l.warning("Merging without a common ancestor. This will be slow.")
                our_changes, our_deletions = set(our_page.iterkeys()), set()
                their_changes, their_deletions = set(their_page.iterkeys()), set()
            else:
                our_changes, our_deletions = our_page.changes_since(common_ancestor)
                their_changes, their_deletions = their_page.changes_since(common_ancestor)

            candidates.update([ (p*self._page_size)+i for i in our_changes | our_deletions | their_changes | their_deletions ])

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
                    self_byte = self[c].bytes_at(c, 1).model
                    other_byte = other[c].bytes_at(c, 1).model
                    if not self.state.se.is_true(self_byte == other_byte):
                        #l.debug("%s: offset %x, two different bytes %s %s from %s %s", self.id, c,
                        #       self_byte, other_byte,
                        #       self[c].object.model, other[c].object.model)
                        differences.add(c)
                else:
                    # this means the byte is in neither memory
                    pass

        return differences

    #
    # Memory object management
    #

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

        memory_objects = set()
        for v in old.variables:
            memory_objects.update(self.memory_objects_for_name(v))

        for mo in memory_objects:
            self.replace_memory_object(mo, mo.object.replace(old, new))

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

