"""
pytest configuration for DoIP EdgeNode tests.

Registers custom marks and configures pytest-asyncio mode.
"""
import sys
import os

# Ensure the doip_edgenode package is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "requires_root: mark test as requiring CAP_NET_RAW (raw socket privileges)",
    )


# Use asyncio mode = "auto" so @pytest.mark.asyncio tests run without
# the explicit decorator when using pytest-asyncio >= 0.21.
# Falls back gracefully if pytest-asyncio is not installed.
try:
    import pytest_asyncio  # noqa: F401
    # Tell pytest-asyncio to treat all async test functions as asyncio tests
    pytest_ini_options = {"asyncio_mode": "auto"}
except ImportError:
    pass
