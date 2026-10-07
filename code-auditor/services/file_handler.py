"""
File handler service — ZIP extraction, language detection, and file filtering.
"""

import zipfile
import io
import os
from pathlib import PurePosixPath

# Max upload size: 10MB
MAX_UPLOAD_SIZE = 10 * 1024 * 1024

# Max files to process per ZIP
MAX_FILES_PER_ZIP = 20

# File extensions → language mapping
EXTENSION_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".html": "html",
    ".htm": "html",
    ".css": "css",
    ".scss": "scss",
    ".sass": "sass",
    ".less": "less",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".go": "go",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".swift": "swift",
    ".scala": "scala",
    ".r": "r",
    ".R": "r",
    ".sql": "sql",
    ".sh": "bash",
    ".bash": "bash",
    ".zsh": "zsh",
    ".ps1": "powershell",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".xml": "xml",
    ".toml": "toml",
    ".ini": "ini",
    ".cfg": "ini",
    ".md": "markdown",
    ".markdown": "markdown",
    ".dart": "dart",
    ".lua": "lua",
    ".pl": "perl",
    ".ex": "elixir",
    ".exs": "elixir",
    ".erl": "erlang",
    ".hs": "haskell",
    ".ml": "ocaml",
    ".fs": "fsharp",
    ".clj": "clojure",
    ".vue": "vue",
    ".svelte": "svelte",
}

# Directories to skip during extraction
SKIP_DIRS = {
    "node_modules",
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    ".env",
    "dist",
    "build",
    ".idea",
    ".vscode",
    ".DS_Store",
    "vendor",
    ".next",
    "target",
    "bin",
    "obj",
}

# Binary/non-text extensions to skip
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".mp3", ".mp4", ".wav", ".avi", ".mov",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib",
    ".pyc", ".pyo", ".class", ".o", ".obj",
    ".woff", ".woff2", ".ttf", ".eot",
    ".lock", ".sum",
}


def detect_language(filename: str | None = None, code: str | None = None) -> str:
    """
    Detect programming language from filename extension or code heuristics.
    
    Args:
        filename: Optional filename to check extension
        code: Optional code content for heuristic detection
    
    Returns:
        Detected language string
    """
    if filename:
        ext = os.path.splitext(filename)[1].lower()
        if ext in EXTENSION_MAP:
            return EXTENSION_MAP[ext]

    if code:
        return _detect_from_content(code)

    return "unknown"


def _detect_from_content(code: str) -> str:
    """Use simple heuristics to guess language from code content."""
    code_lower = code.strip().lower()
    lines = code.strip().split("\n")
    first_line = lines[0].strip() if lines else ""

    # Shebang detection
    if first_line.startswith("#!"):
        if "python" in first_line:
            return "python"
        if "node" in first_line or "deno" in first_line:
            return "javascript"
        if "bash" in first_line or "sh" in first_line:
            return "bash"
        if "ruby" in first_line:
            return "ruby"
        if "perl" in first_line:
            return "perl"

    # Keyword-based heuristics
    if "def " in code and ("import " in code or "from " in code) and ":" in code:
        return "python"
    if "function " in code and ("{" in code) and ("var " in code or "let " in code or "const " in code):
        return "javascript"
    if "interface " in code and ": " in code and ("export " in code or "import " in code):
        return "typescript"
    if "package " in code and "func " in code and ":=" in code:
        return "go"
    if "fn " in code and "let mut" in code:
        return "rust"
    if "public class " in code or "public static void main" in code_lower:
        return "java"
    if "<?php" in code_lower:
        return "php"
    if "<html" in code_lower or "<!doctype" in code_lower:
        return "html"
    if "using System" in code or "namespace " in code and "class " in code:
        return "csharp"
    if "#include" in code and ("{" in code):
        if "iostream" in code or "std::" in code or "cout" in code:
            return "cpp"
        return "c"
    if "SELECT " in code.upper() and ("FROM " in code.upper() or "INSERT " in code.upper()):
        return "sql"
    if "require " in code and "end" in code and "def " in code:
        return "ruby"

    return "unknown"


def extract_zip(file_bytes: bytes) -> list[dict]:
    """
    Extract text-based source files from a ZIP archive.
    
    Args:
        file_bytes: Raw bytes of the ZIP file
    
    Returns:
        List of dicts with 'filename', 'content', 'language' keys
    
    Raises:
        ValueError: If ZIP is too large, corrupted, or contains no valid files
    """
    if len(file_bytes) > MAX_UPLOAD_SIZE:
        raise ValueError(
            f"ZIP file exceeds maximum size of {MAX_UPLOAD_SIZE // (1024*1024)}MB"
        )

    try:
        zip_buffer = io.BytesIO(file_bytes)
        with zipfile.ZipFile(zip_buffer, "r") as zf:
            # Check for zip bombs
            total_uncompressed = sum(info.file_size for info in zf.infolist())
            if total_uncompressed > MAX_UPLOAD_SIZE * 5:
                raise ValueError("ZIP archive uncompressed size is too large")

            extracted_files = []
            warning_truncated = False

            for info in zf.infolist():
                # Skip directories
                if info.is_dir():
                    continue

                filepath = PurePosixPath(info.filename)

                # Skip hidden files
                if any(part.startswith(".") for part in filepath.parts[:-1]):
                    continue

                # Skip files in excluded directories
                if any(part in SKIP_DIRS for part in filepath.parts):
                    continue

                # Skip binary/non-text files
                ext = filepath.suffix.lower()
                if ext in SKIP_EXTENSIONS:
                    continue

                # Skip files without extensions (often binaries)
                if not ext and filepath.name not in (
                    "Makefile", "Dockerfile", "Rakefile", "Gemfile",
                    "Procfile", "Vagrantfile",
                ):
                    continue

                # Check file count limit
                if len(extracted_files) >= MAX_FILES_PER_ZIP:
                    warning_truncated = True
                    break

                # Try to read as text
                try:
                    content = zf.read(info.filename).decode("utf-8", errors="ignore")
                    # Skip very large individual files (>100KB)
                    if len(content) > 100_000:
                        continue
                    # Skip empty files
                    if not content.strip():
                        continue

                    language = detect_language(filename=info.filename)
                    extracted_files.append({
                        "filename": info.filename,
                        "content": content,
                        "language": language,
                        "size": len(content),
                    })
                except (UnicodeDecodeError, KeyError):
                    continue

            if not extracted_files:
                raise ValueError(
                    "No valid source code files found in the ZIP archive"
                )

            return extracted_files

    except zipfile.BadZipFile:
        raise ValueError("The uploaded file is not a valid ZIP archive")


def build_file_tree(files: list[dict]) -> dict:
    """
    Build a nested file tree structure from a flat list of file paths.
    
    Returns a nested dict where directories are dicts and files are leaf entries.
    """
    tree = {}
    for f in files:
        parts = PurePosixPath(f["filename"]).parts
        current = tree
        for i, part in enumerate(parts):
            if i == len(parts) - 1:
                # Leaf file
                current[part] = {
                    "type": "file",
                    "language": f["language"],
                    "size": f["size"],
                    "path": f["filename"],
                }
            else:
                # Directory
                if part not in current:
                    current[part] = {"type": "dir", "children": {}}
                current = current[part].get("children", current[part])
    return tree
