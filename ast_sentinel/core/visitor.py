import ast
from abc import ABC, abstractmethod

from ast_sentinel.schemas.findings import Finding, Location, Severity


class GenericNode(ABC):
    """
    Abstraction layer for syntax tree nodes to support multiple languages.
    Can wrap python's `ast.AST` or a `tree_sitter.Node`.
    """
    @property
    @abstractmethod
    def type(self) -> str:
        pass

    @property
    @abstractmethod
    def start_point(self) -> tuple[int, int]:
        """Returns (line, column) 1-indexed for line, 0-indexed for column"""
    
    @property
    @abstractmethod
    def end_point(self) -> tuple[int, int]:
        pass

class PythonASTNode(GenericNode):
    def __init__(self, node: ast.AST):
        self.node = node

    @property
    def type(self) -> str:
        return type(self.node).__name__

    @property
    def start_point(self) -> tuple[int, int]:
        return (getattr(self.node, 'lineno', 1), getattr(self.node, 'col_offset', 0))
    
    @property
    def end_point(self) -> tuple[int, int]:
        return (getattr(self.node, 'end_lineno', self.start_point[0]), getattr(self.node, 'end_col_offset', self.start_point[1]))

class BaseRuleVisitor(ABC):
    rule_id: str
    rule_name: str
    severity: Severity

    def __init__(self):
        self.findings: list[Finding] = []
        self._current_file: str = ""
        self._source_lines: list[str] = []

    def report(
        self,
        node: ast.AST | GenericNode,
        message: str,
        remediation: str,
        severity_override: Severity | None = None
    ):
        if isinstance(node, ast.AST):
            gen_node = PythonASTNode(node)
        else:
            gen_node = node
            
        start_line, start_col = gen_node.start_point
        end_line, end_col = gen_node.end_point

        location = Location(
            file_path=self._current_file,
            line_number=start_line,
            column_offset=start_col,
            end_line_number=end_line,
            end_column_offset=end_col
        )
        
        finding = Finding(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=severity_override or self.severity,
            message=message,
            location=location,
            code_snippet=self._get_code_snippet(start_line, end_line),
            remediation=remediation
        )
        self.findings.append(finding)

    def _get_code_snippet(self, start_line: int, end_line: int) -> str:
        if not self._source_lines:
            return ""
        # 1-indexed to 0-indexed
        start_idx = max(0, start_line - 1)
        end_idx = min(len(self._source_lines), end_line)
        return "\n".join(self._source_lines[start_idx:end_idx])

class PythonAstRuleVisitor(BaseRuleVisitor, ast.NodeVisitor):
    """Base class for standard python ast based rules"""
    
    def analyze(self, tree: ast.Module, source_lines: list[str], file_path: str) -> list[Finding]:
        self.findings = []
        self._current_file = file_path
        self._source_lines = source_lines
        self.visit(tree)
        return self.findings
