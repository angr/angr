from __future__ import annotations

from angr.simos.windows import SimWindows


class SimWindowsEmulated(SimWindows):
    """
    SimWindows for WindowsEmulator: the emulator builds the process environment and dispatches exceptions itself.
    """

    def configure_project(self):
        try:
            super().configure_project()
        except KeyError:
            # the last step, cle's TLS block for the main thread, could not read the template that the image's TLS
            # directory names. The emulator builds TLS itself (and reports such a directory when it runs), so cle
            # gets an empty template
            main = self.project.loader.main_object
            main.tls_data_size = main.tls_block_size = 0
            self.project.loader.tls.new_thread()

    def handle_exception(self, successors, engine, exception):
        raise exception
