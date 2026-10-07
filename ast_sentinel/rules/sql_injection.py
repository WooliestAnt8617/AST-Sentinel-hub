import ast

from ast_sentinel.core.visitor import PythonAstRuleVisitor
from ast_sentinel.schemas.findings import Severity


class SQLInjectionVisitor(PythonAstRuleVisitor):
    rule_id = "SEC-003"
    rule_name = "SQL Injection"
    severity = Severity.CRITICAL

    EXECUTE_METHODS = {"execute", "executemany", "executescript"}

    def __init__(self):
        super().__init__()
        # Track variable names assigned to dynamic query strings
        self._dynamic_query_vars: set[str] = set()

    def visit_Assign(self, node: ast.Assign):
        """Track variables assigned with dynamic string operations (f-strings, %, .format, +)."""
        if isinstance(node.value, (ast.JoinedStr, ast.BinOp, ast.Call)):
            if self._is_dynamic_query(node.value):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self._dynamic_query_vars.add(target.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr in self.EXECUTE_METHODS:
            if node.args:
                query_arg = node.args[0]
                is_dynamic = self._is_dynamic_query(query_arg)

                # Also check if the argument is a variable we tracked as dynamic
                if not is_dynamic and isinstance(query_arg, ast.Name):
                    if query_arg.id in self._dynamic_query_vars:
                        is_dynamic = True

                if is_dynamic:
                    self.report(
                        node=node,
                        message=f"Potential SQL injection: dynamic query passed to '{node.func.attr}()'.",
                        remediation="Use parameterized queries with placeholders (e.g., cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,)))."
                    )
        self.generic_visit(node)

    def _is_dynamic_query(self, node: ast.expr) -> bool:
        # f-string
        if isinstance(node, ast.JoinedStr):
            return True
        # "SELECT ... " % (var,)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            return True
        # "SELECT ... ".format(...)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return True
        # string concatenation with +
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return True
        return False
