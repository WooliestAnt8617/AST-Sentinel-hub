import ast

from ast_sentinel.core.visitor import PythonAstRuleVisitor
from ast_sentinel.schemas.findings import Severity


class ExceptionHandlingVisitor(PythonAstRuleVisitor):
    rule_id = "SEC-006"
    rule_name = "Insecure Exception Handling"
    severity = Severity.MEDIUM

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        # Bare except: (no type specified)
        if node.type is None:
            self.report(
                node=node,
                message="Bare 'except:' clause catches all exceptions including SystemExit and KeyboardInterrupt.",
                remediation="Catch specific exceptions (e.g., 'except ValueError:') or at minimum use 'except Exception:'."
            )
        # except Exception: — overly broad
        elif isinstance(node.type, ast.Name) and node.type.id == "Exception":
            self.report(
                node=node,
                message="Broad 'except Exception:' may hide bugs and suppress meaningful errors.",
                remediation="Catch specific exceptions relevant to the operation.",
                severity_override=Severity.LOW
            )

        # Empty except body (just 'pass')
        if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            self.report(
                node=node,
                message="Empty except body silently swallows errors — potential debugging blind spot.",
                remediation="Log the exception or re-raise it after handling.",
                severity_override=Severity.MEDIUM
            )

        self.generic_visit(node)
