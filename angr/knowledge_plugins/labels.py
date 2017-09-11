from collections import Counter

from .artifact import KnowledgeArtifact
from ..misc.ux import deprecated

import logging
l = logging.getLogger("angr.knowledge.labels")


class LabelsPlugin(KnowledgeArtifact):
    """Storage for program labels. Access with kb.labels.    
    
    A label "name" is a label named "name", duh. Labels can be grouped into the seperate namespaces.
    An address is allowed to have a different labels within different namespace, but it is not allowed
    for address to have a different labels within a single namespace.
    
    The default namespace is set to empty string.
    """
    _provides = 'labels'

    _default_ns_name = ''

    def __init__(self, kb=None):
        super(LabelsPlugin, self).__init__(kb)

        self._namespaces = {}
        self._default_ns = self._default_ns_name
        self.add_namespace(self._default_ns_name)

    def copy(self):
        o = LabelsPlugin()
        o._namespaces = {k: v.copy() for k, v in self._namespaces.iteritems()}
        o._default_ns = self._default_ns
        return o

    #
    #   ...
    #

    def __getattr__(self, name):
        try:
            object.__getattribute__(self, name)
        except AttributeError:
            namespaces = object.__getattribute__(self, '_namespaces')
            namespace = namespaces[self.default_namespace]
            return getattr(namespace, name)

    def __iter__(self):
        namespace = self._namespaces[self.default_namespace]
        return iter(namespace)

    def __getitem__(self, addr):
        namespace = self._namespaces[self.default_namespace]
        return namespace[addr]

    def __delitem__(self, addr):
        namespace = self._namespaces[self.default_namespace]
        del namespace[addr]

    def __contains__(self, addr):
        namespace = self._namespaces[self.default_namespace]
        return addr in namespace

    #
    #   ...
    #

    @deprecated(replacement='get_label')
    def get(self, addr):
        namespace = self._namespaces[self.default_namespace]
        return namespace.get_name(addr)

    @deprecated(replacement='get_addr')
    def lookup(self, name):
        namespace = self._namespaces[self.default_namespace]
        addr = namespace.get_addr(name)
        if addr is None:
            raise KeyError(name)
        return addr

    #
    #   ...
    #

    @property
    def default_namespace(self):
        """Get the default namespace name
        
        :return:    
        """
        return self._default_ns

    @default_namespace.setter
    def default_namespace(self, name):
        """Set the default namespace name.
        
        If the namespace with a given name does not exist, it will be created first.
        
        :param name:    The name of the the default namespace.
        :return: 
        """
        self._default_ns = name
        if self._default_ns not in self._namespaces:
            self.add_namespace(self._default_ns)

    def get_namespace(self, name=None, create=True):
        """Get or create a namespace object.
        
        :param name:    The name of the namespace to get.
        :return:        LabelsNamespace
        """
        if name is None:
            name = self.default_namespace
        if name not in self._namespaces and create:
            self.add_namespace(name)
        return self._namespaces[name]

    def add_namespace(self, name):
        """Create a new namespace with the given name.
        
        :param name:    The name for the namespace which is to be created. 
        :return:        
        """
        if name in self._namespaces:
            raise ValueError("Namespace %r already exists" % name)
        self._namespaces[name] = LabelsNamespace(name, self)

    def make_alias(self, name, alias):
        if name not in self._namespaces:
            raise ValueError("Namespace %r does not exist" % name)
        if alias in self._namespaces:
            raise ValueError("Namespace %r already exists" % alias)
        self._namespaces[alias] = self._namespaces[name]

    def find_labels(self, addr):
        labels = []
        for ns_name, namespace in self._namespaces.iteritems():
            labels.extend((ns_name, name) for name in namespace.get_all_names(addr))
        return labels


class LabelsNamespace(object):
    """
    This represents a single labels namespace. The addresses to names relations are represented
    with a one-to-many mapping. That means every address can have multiple names, but every name is
    assigned to only one address.
    
    :ivar _name_to_addr:    A mapping from name to its assigned address.
    :type _name_to_addr:    dict
    :ivar _addr_to_names:   A mapping from address to a list of assigned names. The first name
                            in a list will be the default name for the address.
    :type _addr_to_names:   dict of lists
    """

    def __init__(self, name, plugin):
        self._name = name  # here for better repr only
        self._plugin = plugin  # to enable notifications
        self._name_to_addr = {}
        self._addr_to_names = {}
        self._name_usage_cnt = Counter()

    def __str__(self):
        return "<LabelsNamespace(%s)>" % repr(self._name)

    def __repr__(self):
        return str(self)

    def __getitem__(self, addr):
        name = self.get_name(addr)
        if name is None:
            raise KeyError(addr)
        return name

    def __setitem__(self, addr, name):
        self.set_label(addr, name)

    def __delitem__(self, addr):
        self.del_addr(addr)

    def __contains__(self, addr):
        return self.has_addr(addr)

    def __iter__(self):
        return iter(self._name_to_addr)

    def copy(self):
        o = LabelsNamespace(self._name)
        o._name_to_addr = self._name_to_addr.copy()
        o._addr_to_names = self._addr_to_names.copy()
        o._name_usage_cnt = self._name_usage_cnt.copy()
        return o

    #
    #   ...
    #

    def set_label(self, addr, name, make_default=False, dup_mode='overwrite'):
        """Assign a name to a given address.

        :param addr:            An address to be assigned with a name.
        :param name:            A name to be assigned to address.
        :param make_default:    True, if the given name should be the default name for the address.
        :param dup_mode:   
        :return: 
        """
        if self._name_to_addr.get(name, addr) != addr:

            if dup_mode == 'overwrite':
                prev_addr = self._name_to_addr[name]
                l.debug("Reassigning name '%s' to address %#x (previous address was %#x)",
                        name, addr, prev_addr)
                self.del_name(name)

            elif dup_mode == 'suffix':
                new_name = self._add_suffix(name)
                l.debug("Name %s is already present within the current namespace, "
                        "so %s will be used instead" % (name, new_name))
                name = new_name

            elif dup_mode == 'raise':
                prev_addr = self._name_to_addr[name]
                raise ValueError("Name %s is already assigned to address %#x, different from %#x" %
                                 (name, prev_addr, addr))

        self._name_to_addr[name] = addr
        names_list = self._addr_to_names.setdefault(addr, [])

        if make_default is True:
            names_list.insert(0, name)
        else:
            names_list.append(name)

        self._plugin._notify_observers('set_label', addr=addr, name=name)

        return name

    def iter_labels(self):
        """Iterate over the labels within this namespace.
        
        :return:    Tuples of (name, addr)
        """
        return self._name_to_addr.iteritems()

    #
    #   ...
    #

    def get_name(self, addr, default=None):
        """Get the default name for an address.
        
        :param addr:        The address to look for.
        :param default:     Default value to return, if the address is not present within the namespace.
        :return: 
        """
        return self._addr_to_names.get(addr, [default])[0]

    def get_all_names(self, addr):
        """Get all names that a assigned to a given address.
        
        :param addr:    The address to look for.
        :return:        A list of all names for the given address.
        """
        return self._addr_to_names.get(addr, [])

    def del_name(self, name):
        """Remove a name from the namespace.
        
        :param name:    The name which is to be removed.
        :return: 
        """
        if name not in self._name_to_addr:
            raise KeyError("No such name: %s" % name)

        addr = self._name_to_addr.pop(name)
        self._addr_to_names[addr].remove(name)
        if not self._addr_to_names[addr]:
            del self._addr_to_names[addr]

        self._plugin._notify_observers('del_name', name=name)

    def has_name(self, name):
        """Check whether the given name is present within the namespace.
        
        :param name:    A name to look for.
        :return: 
        """
        return name in self._name_to_addr

    def iter_names(self):
        """Iterate over names that are present within the namespace.
        
        :return: 
        """
        return iter(self._name_to_addr)

    #
    #   ...
    #

    def get_addr(self, name, default=None):
        """Get the address to which the given name is assigned to.
        
        :param name:        A name to look for.
        :param default:     Default value to return, if the name is not present within the namespace.
        :return: 
        """
        return self._name_to_addr.get(name, default)

    def del_addr(self, addr):
        """Remove the address from the namespace, thus effectivly removing all the names that 
        are assigned to this address.
        
        :param addr:    The address which is to be removed.
        :return: 
        """
        if addr not in self._addr_to_names:
            raise KeyError("No such address: %#x" % addr)

        names_list = self._addr_to_names.pop(addr)
        map(self._name_to_addr.pop, names_list)

        self._plugin._notify_observers('del_addr', addr=addr)

    def has_addr(self, addr):
        """Check whether the given address has any name assigned to it.
        
        :param addr:    An address to look for.
        :return: 
        """
        return addr in self._addr_to_names

    def iter_addrs(self):
        """Iterate over the adresses that are present within the namespace.
        
        :return: 
        """
        return iter(self._addr_to_names)

    #
    #   ...
    #

    def _add_suffix(self, name):
        """Add an apropriate suffix to the name, if it is already present within the namespace. 
        
        :param name:    A name to which to add the suffix.
        :return: 
        """
        new_name = '%s_%d' % (name, self._name_usage_cnt[name])
        self._name_usage_cnt[name] += 1
        return new_name

