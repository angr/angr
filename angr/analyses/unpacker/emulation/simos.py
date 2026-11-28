from __future__ import annotations

from angr.simos.windows import SimWindows


class SimWindowsEmulated(SimWindows):
    """
    A Windows SimOS for the processes that `WindowsEmulator` runs.

    The emulator builds the process environment and dispatches exceptions by itself.
    """

    def configure_project(self):
        try:
            super().configure_project()
        except KeyError:
            # cle could not read the TLS template that the TLS directory of the image names. The emulator builds TLS
            # by itself, so we give cle an empty template.
            main = self.project.loader.main_object
            main.tls_data_size = main.tls_block_size = 0
            self.project.loader.tls.new_thread()

    def handle_exception(self, successors, engine, exception):
        raise exception
