import ast

from ast_sentinel.core.visitor import PythonAstRuleVisitor
from ast_sentinel.schemas.findings import Severity


class CodeInjectionVisitor(PythonAstRuleVisitor):
    rule_id = "SEC-002"
    rule_name = "Code Injection"
    severity = Severity.CRITICAL

    DANGEROUS_FUNCTIONS = {"eval", "exec", "compile"}
    
    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in self.DANGEROUS_FUNCTIONS:
                # check if argument is a literal
                is_literal = False
                if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    is_literal = True
                    
                if not is_literal:
                    self.report(
                        node=node,
                        message=f"Use of dangerous function '{func_name}' with non-literal argument.",
                        remediation=f"Avoid using '{func_name}'. If necessary, validate and sanitize input strictly, or use safer alternatives like 'ast.literal_eval()'."
                    )
        
        # Subprocess with shell=True
        if self._is_subprocess_call(node):
            if self._has_shell_true(node):
                self.report(
                    node=node,
                    message="Subprocess call with shell=True. This can lead to shell injection.",
                    remediation="Set shell=False and pass arguments as a list.",
                    severity_override=Severity.HIGH
                )
                
        self.generic_visit(node)
        
    def _is_subprocess_call(self, node: ast.Call) -> bool:
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                return True
        return False
        
    def _has_shell_true(self, node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
        return False
