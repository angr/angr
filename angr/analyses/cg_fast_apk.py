import logging
import os
from networkx import union
from ..project import Project
from ..sim_options import refs
from . import Analysis, register_analysis
import time

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
        self.other_libs = None
        self.kbs = None
        self.callgraphs = None
        self.native_cfg = None
        self.full_callgraph = None
        self.lib_count = 0

        # use for future works
        self.native_entrypoints = [ ]

        self.benchmark = dict()
        t_start = time.process_time()
        self.project.analyses.CFGFastSoot(skip_android_classes=True, support_jni=support_jni)
        time_cfg_fast_soot = time.process_time() - t_start
        self.benchmark['cfg_soot'] = time_cfg_fast_soot

        if self.native_project is not None:
            self._pre_collect()
            self._merge_callgraph()
        else:
            l.warning('Cannot find native project.')
            self.callgraphs = [self.project.kb.functions.callgraph]
            self.full_callgraph = self.project.kb.functions.callgraph # Dummy

    def _gen_native_project(self):
        # just support first of native libraries
        # multiple libraries make node confliction, it says how to resolve same addr but different library?
        l.info("Finding elf objects ...")
        elf_objects = self.project.loader.all_elf_objects

        if len(elf_objects) < 1:
            l.info("There is no native library.")
            return None

        l.info("Constructing native project ...")
        main_lib = elf_objects[0]
        other_libs = [lib for lib in elf_objects[1:]]
        other_lib_binaries = [lib.binary for lib in other_libs]

        self.lib_count = len(other_libs) + 1
        native_project = Project(main_lib.binary, force_load_libs=other_lib_binaries)
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
        self.full_callgraph = self.callgraphs[0].copy()
        # self.full_callgraph.add_edges_from(self.callgraphs[1].edges())
        soot_callgraph = self.callgraphs[0]

        soot_jni_nodes = []
        native_addr_list = []

        find_native_symbol = self.native_project.loader.find_symbol

        # get native node in soot callgraph
        l.info("Collecting symbols of JNI methods in soot callgraph...")
        for soot_node in soot_callgraph.nodes():
            if soot_node.name == 'JNI_OnLoad':
                native_symbol = self.get_special_symbol(soot_node)
            elif soot_node.class_name == 'nativemethod':
                # e.g., "Java_com_example_nativemedia_NativeMedia_shutdown"
                native_symbol = find_native_symbol(soot_node.name)

                if native_symbol is None:
                    # e.g, "shutdown"
                    native_symbol = find_native_symbol(soot_node.name.split('_')[-1])
            else:
                native_symbol = None

            if native_symbol is not None:
                native_address = native_symbol.rebased_addr
                native_addr_list.append(native_address)
                soot_jni_nodes.append(soot_node)
            else:
                l.warning('Cannot find address of %s in native project.', soot_node.name)

        l.info("Generating native CFG ...")
        t_start = time.process_time()
        cfg = self.native_project.analyses.CFGEmulated(keep_state=True,
                                                       context_sensitivity_level=2,
                                                       state_add_options=refs,
                                                       starts=native_addr_list)
        time_cfg_native = time.process_time() - t_start
        self.benchmark['cfg_native'] = time_cfg_native
        l.debug("Native CFG generation time: %f" % time_cfg_native)
        self.native_cfg = cfg
        native_callgraph = cfg.kb.callgraph
        self.callgraphs[1] = native_callgraph

        # get native node in native callgraph
        l.debug("Merging Callgraph ...")
        t_start = time.process_time()
        for native_node in native_callgraph.nodes():
            try:
                idx = native_addr_list.index(native_node)
                self.full_callgraph.add_edge(soot_jni_nodes[idx], native_node)
                self.native_entrypoints.append(native_node)
                # Todo: convert native node by name

            except ValueError:
                continue
        self.full_callgraph.add_nodes_from(native_callgraph.nodes())
        self.full_callgraph.add_edges_from(native_callgraph.edges())
        time_merge_cg = time.process_time() - t_start
        self.benchmark['merge'] = time_merge_cg
        l.debug("Callgraph merge time: %f" % time_merge_cg)

    def get_special_symbol(self, soot_node):
        if soot_node.name == "JNI_OnLoad":
            prefix = 'lib'
            surfix = '.so'
            lib_name = prefix + soot_node.class_name + surfix
            print(lib_name)
            lib_object = self.native_project.loader.find_object(lib_name)

            if lib_object is None:
                return None

            return lib_object.symbols_by_name.get("JNI_OnLoad")

register_analysis(CGFastAPK, 'CGFastAPK')
