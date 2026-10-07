import ast

from ast_sentinel.core.visitor import PythonAstRuleVisitor
from ast_sentinel.schemas.findings import Severity


class UnsafeDeserializationVisitor(PythonAstRuleVisitor):
    rule_id = "SEC-005"
    rule_name = "Unsafe Deserialization"
    severity = Severity.HIGH

    # module.func pairs that are dangerous
    DANGEROUS_CALLS = {
        ("pickle", "loads"),
        ("pickle", "load"),
        ("marshal", "loads"),
        ("marshal", "load"),
        ("shelve", "open"),
    }

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            module = node.func.value.id
            func = node.func.attr

            if (module, func) in self.DANGEROUS_CALLS:
                self.report(
                    node=node,
                    message=f"Unsafe deserialization via '{module}.{func}()'. Untrusted data can execute arbitrary code.",
                    remediation=f"Avoid deserializing untrusted data with '{module}'. Use JSON or a safe serialization format."
                )

            # yaml.load() without SafeLoader
            if module == "yaml" and func == "load":
                has_safe_loader = False
                for kw in node.keywords:
                    if kw.arg == "Loader":
                        if isinstance(kw.value, ast.Attribute) and kw.value.attr == "SafeLoader" or isinstance(kw.value, ast.Name) and kw.value.id == "SafeLoader":
                            has_safe_loader = True
                if not has_safe_loader:
                    self.report(
                        node=node,
                        message="yaml.load() called without SafeLoader — vulnerable to arbitrary code execution.",
                        remediation="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
                        severity_override=Severity.MEDIUM
                    )
        self.generic_visit(node)
