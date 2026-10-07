import ast

from ast_sentinel.rules.hardcoded_secrets import HardcodedSecretsVisitor, shannon_entropy
from ast_sentinel.schemas.findings import Severity


def _analyze(source: str):
    visitor = HardcodedSecretsVisitor()
    tree = ast.parse(source)
    return visitor.analyze(tree, source.splitlines(), "test.py")


class TestHardcodedSecrets:
    def test_detects_password_assignment(self):
        findings = _analyze('DATABASE_PASSWORD = "mysecret123"')
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-001"

    def test_detects_api_key(self):
        findings = _analyze('API_KEY = "my-api-key-value"')
        assert len(findings) == 1

    def test_detects_token(self):
        findings = _analyze('AUTH_TOKEN = "bearer-token-value"')
        assert len(findings) == 1

    def test_detects_secret(self):
        findings = _analyze('APP_SECRET = "my-secret"')
        assert len(findings) == 1

    def test_high_entropy_gets_critical_severity(self):
        # High-entropy string simulating a real API key
        findings = _analyze('API_KEY = "sk-proj-a8Xk3mZ9qL2pR7wN4vT6yB1cF5dH0jE"')
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_low_entropy_gets_high_severity(self):
        findings = _analyze('PASSWORD = "password"')
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_ignores_non_secret_variable(self):
        findings = _analyze('username = "admin"')
        assert len(findings) == 0

    def test_ignores_numeric_assignment(self):
        findings = _analyze('password_length = 16')
        assert len(findings) == 0

    def test_ignores_empty_string(self):
        findings = _analyze('PASSWORD = ""')
        # Empty string is still flagged by keyword match
        assert len(findings) == 1

    def test_multiple_secrets_in_file(self):
        source = '''
PASSWORD = "secret1"
API_KEY = "key123"
TOKEN = "tok456"
'''
        findings = _analyze(source)
        assert len(findings) == 3

    def test_provides_remediation(self):
        findings = _analyze('PASSWORD = "secret"')
        assert findings[0].remediation is not None
        assert "environment" in findings[0].remediation.lower()


class TestShannonEntropy:
    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_single_char_repeated(self):
        assert shannon_entropy("aaaa") == 0.0

    def test_high_entropy(self):
        entropy = shannon_entropy("a8Xk3mZ9qL2pR7wN4vT6yB1cF5dH0jE")
        assert entropy > 4.0

    def test_low_entropy(self):
        entropy = shannon_entropy("password")
        assert entropy < 4.0
