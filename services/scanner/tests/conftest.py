"""Give host-run unit tests their own scratch namespace before app imports."""
import os
from pathlib import Path
from tempfile import TemporaryDirectory


_scratch = None
if "KODESEC_SCRATCH_DIR" not in os.environ:
    _scratch = TemporaryDirectory(prefix="kodesec-scanner-unit-")
    os.environ["KODESEC_SCRATCH_DIR"] = str(Path(_scratch.name) / "scratch")
