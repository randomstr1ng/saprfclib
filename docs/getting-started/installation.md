# Installation

## From PyPI

```bash
pip install saprfclib
```

!!! note "Package name vs import name"
    The distribution is `saprfclib` and the module is `saprfclib`. The name
    `saprfc` on PyPI belongs to an unrelated, long-abandoned project — it is not
    this library.

No native dependencies. `saprfclib` requires Python 3.12 or later and installs
two pure-Python dependencies: `wsproto` and `h11` (needed for WebSocket RFC support).
WebSocket RFC and SNC work out of the box — there are no optional install extras required.

## Development install

Clone the repository and install in editable mode with development dependencies:

```bash
git clone https://github.com/randomstr1ng/saprfclib
cd saprfclib
pip install -e ".[dev]"
```

To also install the documentation build tools:

```bash
pip install mkdocs-material "mkdocstrings[python]"
```

Or use Hatch to manage environments:

```bash
pip install hatch
hatch env create default   # installs dev deps
hatch env create docs      # installs docs deps
```

## Requirements

- Python 3.12 or later
- No C compiler or SAP SDK required
- Works on Linux, macOS, and Windows
