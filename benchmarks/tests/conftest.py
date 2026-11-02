"""
benchmarks/tests/conftest.py -- makes the repository root importable for
the harness self-tests, exactly as tests/conftest.py does for the
application suite.

These tests are NOT part of the application's 230-test suite and are
not collected by a bare `pytest` run: pytest.ini pins
`testpaths = tests`, so this directory is only collected when a path
under benchmarks/ is passed explicitly:

    python -m pytest benchmarks/tests -q

They test the measuring instrument, not the vault. A benchmark harness
whose statistics or record-keeping are wrong produces confident,
plausible, wrong numbers -- the single worst outcome available to this
phase -- so the instrument gets tests of its own.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
