from ..project import Project
from networkx import union
import logging
from . import Analysis, register_analysis

l = logging.getLogger(name=__name__)


class CGFastAPK(Analysis):
    """
    CGFastAPK generates callgraph that integrates Java with Native(C/C++) of APK.

    The field full_callgraph is a unionized callgraph, from projects APK and native library,
    that link edges between a native method call.
    Due to prevent node collision, it maintains only a single ELF object. If callgraph is collected
    from multiple objects, it may occur confusing which node is whose node of the library.
    The reason why the name is CGFastAPK is that it uses CFGFast and CFGFastSoot.
    """

    def __init__(self, support_jni=True):
        """
        :param support_jni: Enables native method invoking for CFGFastSoot

        :return: None
        """
        self.native_project = self._gen_native_project()
        self.kbs = None
        self.callgraphs = None
        self.full_callgraph = None

        # use for future works
        self.native_entrypoints = [ ]

        self.project.analyses.CFGFastSoot(support_jni=support_jni)

        if self.native_project is not None:
            self.native_project.analyses.CFGFast()
            self._pre_collect()
            self._merge_callgraph()
        else:
            l.warning('Cannot find native project.')
            self.full_callgraph = self.project.kb.functions.callgraph

    def _gen_native_project(self):
        # just support first of native libraries
        # multiple libraries make node confliction, it says how to resolve same addr but different library?
        elf_objects = self.project.loader.all_elf_objects

        if len(elf_objects) > 0:
            elf_object = elf_objects[0]
        else:
            return None

        native_project = Project(elf_object.binary)
        entry_symbol = native_project.loader.find_symbol("JNI_OnLoad")

        # set entrypoint: JNI_OnLoad
        if entry_symbol is not None:
            native_project.entry = entry_symbol.rebased_addr
        else:
            l.warning('Cannot find address of "JNI_OnLoad" in native project.')

        return native_project

    def _pre_collect(self):
        # kbs[0], callgraphs[0] is soot based. Follows are native based.
        self.kbs = [self.project.kb, self.native_project.kb]
        self.callgraphs = [kb.functions.callgraph for kb in self.kbs]

    def _merge_callgraph(self):
        # union single native library
        self.full_callgraph = union(self.callgraphs[0], self.callgraphs[1])
        soot_callgraph = self.callgraphs[0]
        native_callgraph = self.callgraphs[1]

        soot_jni_nodes = [ ]
        native_addr_list = [ ]

        find_native_symbol = self.native_project.loader.find_symbol

        # get native node in soot callgraph
        for soot_node in soot_callgraph.nodes():
            if soot_node.name == 'JNI_OnLoad' or soot_node.class_name == 'nativemethod':
                # e.g., "Java_com_example_nativemedia_NativeMedia_shutdown"
                native_symbol = find_native_symbol(soot_node.name)

                if native_symbol is None:
                    # e.g, "shutdown"
                    native_symbol = find_native_symbol(soot_node.name.split('_')[-1])

                if native_symbol is not None:
                    native_address = native_symbol.rebased_addr
                    native_addr_list.append(native_address)
                    soot_jni_nodes.append(soot_node)
                else:
                    l.warning('Cannot find address of %s in native project.', soot_node.name)

        # get native node in native callgraph
        for native_node in native_callgraph.nodes():
            try:
                idx = native_addr_list.index(native_node)
                self.full_callgraph.add_edge(soot_jni_nodes[idx], native_node)
                self.native_entrypoints.append(native_node)
                # Todo: convert native node by name
            except ValueError:
                continue

register_analysis(CGFastAPK, 'CGFastAPK')
