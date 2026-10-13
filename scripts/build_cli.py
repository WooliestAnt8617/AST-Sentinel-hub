"""
Build standalone executable for AST-Sentinel CLI using PyInstaller.
Outputs to dist/ast-sentinel.exe and copies to code-auditor/static/bin/ast-sentinel.exe
"""
import shutil
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_SRC = ROOT_DIR / "ast_sentinel" / "templates"
STATIC_BIN_DIR = ROOT_DIR / "code-auditor" / "static" / "bin"
DIST_DIR = ROOT_DIR / "dist"

def build():
    print("Building AST-Sentinel standalone CLI executable...")
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--name", "ast-sentinel",
        "--onefile",
        "--clean",
        "--add-data", f"{TEMPLATES_SRC};ast_sentinel/templates",
        "--exclude-module", "PyQt6",
        "--exclude-module", "PyQt5",
        "--exclude-module", "matplotlib",
        "--exclude-module", "IPython",
        "--exclude-module", "notebook",
        "--exclude-module", "tkinter",
        "--exclude-module", "PIL",
        "--exclude-module", "scipy",
        "--exclude-module", "pandas",
        "--exclude-module", "pytest",
        "--exclude-module", "zmq",
        "--paths", str(ROOT_DIR),
        str(ROOT_DIR / "ast_sentinel" / "main.py"),
    ]
    print(f"Running command: {' '.join(cmd)}")
    subprocess.check_call(cmd, cwd=str(ROOT_DIR))

    exe_path = DIST_DIR / ("ast-sentinel.exe" if sys.platform == "win32" else "ast-sentinel")
    if exe_path.exists():
        STATIC_BIN_DIR.mkdir(parents=True, exist_ok=True)
        target = STATIC_BIN_DIR / exe_path.name
        shutil.copy2(exe_path, target)
        print(f"Successfully copied executable to {target}")
    else:
        print(f"Warning: {exe_path} was not found after build.")

if __name__ == "__main__":
    build()
