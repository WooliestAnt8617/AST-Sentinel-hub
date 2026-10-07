import ast
import tokenize
from pathlib import Path


class ParsingError(Exception):
    def __init__(self, message: str, file_path: str = "<unknown>"):
        super().__init__(message)
        self.file_path = file_path

def parse_source(source: str, filename: str = "<unknown>") -> ast.Module:
    try:
        tree = ast.parse(source, filename=filename)
        return tree
    except SyntaxError as e:
        raise ParsingError(f"Syntax error at line {e.lineno}, col {e.offset}: {e.msg}", filename)
    except Exception as e:
        raise ParsingError(f"Failed to parse source: {e!s}", filename)

def parse_file(path: Path) -> tuple[ast.Module, list[str]]:
    try:
        with tokenize.open(path) as f:
            source = f.read()
        
        lines = source.splitlines()
        tree = parse_source(source, filename=str(path))
        return tree, lines
    except SyntaxError as e:
        raise ParsingError(f"Syntax error in file: {e.msg}", str(path))
    except UnicodeDecodeError:
        raise ParsingError(f"Failed to decode file {path}", str(path))
    except ParsingError:
        raise
    except Exception as e:
        raise ParsingError(f"Failed to read file: {e!s}", str(path))
