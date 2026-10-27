"""
Unit tests for Code Auditor GitHub integration and URL parsing.
"""

import io
import zipfile
import sys
from pathlib import Path

# Add code-auditor to sys.path
CODE_AUDITOR_DIR = Path(__file__).resolve().parent.parent / "code-auditor"
if str(CODE_AUDITOR_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_AUDITOR_DIR))

from main import _parse_github_url, _github_url_to_raw
from services.file_handler import extract_zip


def test_parse_github_url_full_repo():
    res = _parse_github_url("https://github.com/WooliestAnt8617/AST-Sentinel-hub")
    assert res is not None
    assert res["kind"] == "repo"
    assert res["repo"] == "WooliestAnt8617/AST-Sentinel-hub"
    assert res["url"] == "https://github.com/WooliestAnt8617/AST-Sentinel-hub/archive/HEAD.zip"


def test_parse_github_url_repo_trailing_slash_and_git():
    res1 = _parse_github_url("github.com/user/repo/")
    assert res1 is not None
    assert res1["kind"] == "repo"
    assert res1["repo"] == "user/repo"

    res2 = _parse_github_url("https://github.com/user/repo.git")
    assert res2 is not None
    assert res2["kind"] == "repo"
    assert res2["repo"] == "user/repo"


def test_parse_github_url_tree_branch():
    res = _parse_github_url("https://github.com/pallets/flask/tree/main")
    assert res is not None
    assert res["kind"] == "repo"
    assert res["branch"] == "main"
    assert res["repo"] == "pallets/flask"
    assert res["url"] == "https://github.com/pallets/flask/archive/refs/heads/main.zip"


def test_parse_github_url_blob_file():
    res = _parse_github_url("https://github.com/pallets/flask/blob/main/src/flask/app.py")
    assert res is not None
    assert res["kind"] == "file"
    assert res["filename"] == "app.py"
    assert res["repo"] == "pallets/flask"
    assert res["url"] == "https://raw.githubusercontent.com/pallets/flask/main/src/flask/app.py"


def test_parse_github_url_with_line_anchor_and_query():
    res = _parse_github_url("https://github.com/user/repo/blob/master/server.py#L10-L40")
    assert res is not None
    assert res["kind"] == "file"
    assert res["filename"] == "server.py"
    assert res["url"] == "https://raw.githubusercontent.com/user/repo/master/server.py"


def test_parse_github_url_raw():
    res = _parse_github_url("https://raw.githubusercontent.com/user/repo/main/utils.py")
    assert res is not None
    assert res["kind"] == "file"
    assert res["filename"] == "utils.py"
    assert res["url"] == "https://raw.githubusercontent.com/user/repo/main/utils.py"


def test_parse_github_url_gist():
    res = _parse_github_url("https://gist.github.com/octocat/6cad326836d38bd3a7ae")
    assert res is not None
    assert res["kind"] == "file"
    assert "gist.githubusercontent.com" in res["url"]


def test_parse_github_url_invalid():
    assert _parse_github_url("https://google.com") is None
    assert _parse_github_url("") is None
    assert _parse_github_url("not a url") is None


def test_github_url_to_raw_compatibility():
    raw_url, filename = _github_url_to_raw("https://github.com/user/repo/blob/main/main.py")
    assert raw_url == "https://raw.githubusercontent.com/user/repo/main/main.py"
    assert filename == "main.py"

    repo_raw, repo_name = _github_url_to_raw("https://github.com/user/repo")
    assert repo_raw is None


def test_extract_zip_strips_github_common_prefix():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("myrepo-main/README.md", "# Hello")
        zf.writestr("myrepo-main/src/app.py", "def main(): pass")
    
    extracted = extract_zip(buf.getvalue())
    filenames = [f["filename"] for f in extracted]
    assert "src/app.py" in filenames
    assert "README.md" in filenames
    # Primary code should be prioritized first
    assert filenames[0] == "src/app.py"
