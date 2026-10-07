import ast
import math

from ast_sentinel.core.visitor import PythonAstRuleVisitor
from ast_sentinel.schemas.findings import Severity


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    entropy = 0.0
    for x in set(s):
        p_x = float(s.count(x)) / len(s)
        entropy -= p_x * math.log(p_x, 2)
    return entropy

class HardcodedSecretsVisitor(PythonAstRuleVisitor):
    rule_id = "SEC-001"
    rule_name = "Hardcoded Secrets"
    severity = Severity.HIGH
    
    # Common variables that hold secrets
    SECRET_KEYWORDS = {"password", "secret", "api_key", "token", "auth", "credential", "key"}

    def visit_Assign(self, node: ast.Assign):
        # check if assigning a string to a secret-sounding variable
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            val = node.value.value
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id.lower()
                    if any(kw in var_name for kw in self.SECRET_KEYWORDS):
                        # Calculate entropy to adjust severity
                        entropy = shannon_entropy(val)
                        sev = Severity.CRITICAL if entropy > 4.5 else Severity.HIGH
                        
                        self.report(
                            node=node,
                            message=f"Possible hardcoded secret in variable '{target.id}'.",
                            remediation="Use environment variables or a secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager).",
                            severity_override=sev
                        )
        self.generic_visit(node)
