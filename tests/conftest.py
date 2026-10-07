from pathlib import Path

import pytest

from ast_sentinel.core.scanner import ScannerOrchestrator

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def scanner():
    return ScannerOrchestrator()


@pytest.fixture
def vulnerable_source():
    return (FIXTURES_DIR / "vulnerable_sample.py").read_text(encoding="utf-8")


@pytest.fixture
def clean_source():
    return (FIXTURES_DIR / "clean_sample.py").read_text(encoding="utf-8")
