# conftest.py (repo root)
#
# Ensure the in-tree ``src/`` layout takes precedence over any editable install
# of ``saprfclib`` that may be present on sys.path. Without this, pytest can resolve
# ``import saprfclib`` to a site-packages editable install pointing at a *different*
# checkout, hiding the modules under test in this working tree.
#
# Pure test-harness plumbing: no runtime behaviour, no third-party imports.

import sys
from pathlib import Path

_SRC = Path(__file__).parent / "src"
if _SRC.is_dir():
    sys.path.insert(0, str(_SRC))
