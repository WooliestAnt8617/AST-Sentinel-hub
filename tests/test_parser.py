import ast
from pathlib import Path

import pytest

from ast_sentinel.core.parser import ParsingError, parse_file, parse_source

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestParseSource:
    def test_valid_source(self):
        tree = parse_source("x = 1\nprint(x)", "test.py")
        assert isinstance(tree, ast.Module)
        assert len(tree.body) == 2

    def test_empty_source(self):
        tree = parse_source("", "empty.py")
        assert isinstance(tree, ast.Module)
        assert len(tree.body) == 0

    def test_syntax_error_raises_parsing_error(self):
        with pytest.raises(ParsingError) as exc_info:
            parse_source("def broken(\n", "bad.py")
        assert "bad.py" in str(exc_info.value.file_path)

    def test_multiline_functions(self):
        source = """
def add(a, b):
    return a + b

def subtract(a, b):
    return a - b
"""
        tree = parse_source(source, "funcs.py")
        funcs = [n for n in tree.body if isinstance(n, ast.FunctionDef)]
        assert len(funcs) == 2

    def test_unicode_source(self):
        source = '# コメント\nname = "日本語"'
        tree = parse_source(source, "unicode.py")
        assert isinstance(tree, ast.Module)


class TestParseFile:
    def test_valid_file(self):
        tree, lines = parse_file(FIXTURES_DIR / "clean_sample.py")
        assert isinstance(tree, ast.Module)
        assert len(lines) > 0

    def test_malformed_file(self):
        with pytest.raises(ParsingError):
            parse_file(FIXTURES_DIR / "malformed_sample.py")

    def test_nonexistent_file(self):
        with pytest.raises(ParsingError):
            parse_file(Path("nonexistent_file_xyz.py"))

    def test_returns_correct_line_count(self):
        tree, lines = parse_file(FIXTURES_DIR / "clean_sample.py")
        actual_content = (FIXTURES_DIR / "clean_sample.py").read_text(encoding="utf-8")
        assert len(lines) == len(actual_content.splitlines())
