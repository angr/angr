from pathlib import Path

from angr.analyses import Analysis, AnalysesHub


SIGS_DIR = Path(__file__).parent / "sigs"


class RustcVersionIdentification(Analysis):
    def __init__(self, cfg):

        for sig_path in SIGS_DIR.rglob("*.sig"):
            flirt = self.project.analyses.Flirt(str(sig_path), dry_run=True)
            print(
                f"{sig_path=}, matched {sum(len(suggestions.values()) for _, suggestions in flirt.matched_suggestions.values())}"
            )

        self._analyze()

    def _analyze(self):
        pass


AnalysesHub.register_default("RustcVersionIdentification", RustcVersionIdentification)
