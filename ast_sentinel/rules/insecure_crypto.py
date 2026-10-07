import ast

from ast_sentinel.core.visitor import PythonAstRuleVisitor
from ast_sentinel.schemas.findings import Severity


class InsecureCryptoVisitor(PythonAstRuleVisitor):
    rule_id = "SEC-004"
    rule_name = "Insecure Cryptography"
    severity = Severity.HIGH

    WEAK_HASHES = {"md5", "sha1"}
    WEAK_CIPHERS = {"DES", "Blowfish", "RC4"}
    DEPRECATED_MODULES = {"Crypto.Cipher.DES", "crypt"}

    def visit_Call(self, node: ast.Call):
        # hashlib.md5(), hashlib.sha1()
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == "hashlib" and node.func.attr in self.WEAK_HASHES:
                self.report(
                    node=node,
                    message=f"Use of weak hash function 'hashlib.{node.func.attr}()'.",
                    remediation="Use hashlib.sha256() or hashlib.sha3_256() instead."
                )
            # random.random() — not cryptographically secure
            if node.func.value.id == "random" and node.func.attr in {"random", "randint", "choice", "randrange"}:
                self.report(
                    node=node,
                    message=f"Use of non-cryptographic PRNG 'random.{node.func.attr}()' — not suitable for security purposes.",
                    remediation="Use 'secrets' module for cryptographically secure random values.",
                    severity_override=Severity.MEDIUM
                )
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name in self.DEPRECATED_MODULES:
                self.report(
                    node=node,
                    message=f"Import of deprecated/insecure crypto module '{alias.name}'.",
                    remediation="Use 'cryptography' library with modern algorithms (AES-GCM, ChaCha20)."
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            full_module = node.module
            if full_module in self.DEPRECATED_MODULES or any(full_module.startswith(m) for m in self.DEPRECATED_MODULES):
                self.report(
                    node=node,
                    message=f"Import from deprecated/insecure crypto module '{full_module}'.",
                    remediation="Use 'cryptography' library with modern algorithms (AES-GCM, ChaCha20)."
                )
        self.generic_visit(node)
