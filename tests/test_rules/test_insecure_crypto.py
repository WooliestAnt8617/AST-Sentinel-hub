import ast

from ast_sentinel.rules.insecure_crypto import InsecureCryptoVisitor
from ast_sentinel.schemas.findings import Severity


def _analyze(source: str):
    visitor = InsecureCryptoVisitor()
    tree = ast.parse(source)
    return visitor.analyze(tree, source.splitlines(), "test.py")


class TestWeakHashes:
    def test_detects_md5(self):
        findings = _analyze('import hashlib\nhashlib.md5(b"data")')
        assert any("md5" in f.message for f in findings)
        assert findings[0].severity == Severity.HIGH

    def test_detects_sha1(self):
        findings = _analyze('import hashlib\nhashlib.sha1(b"data")')
        assert any("sha1" in f.message for f in findings)

    def test_ignores_sha256(self):
        findings = _analyze('import hashlib\nhashlib.sha256(b"data")')
        assert len(findings) == 0

    def test_ignores_sha3_256(self):
        findings = _analyze('import hashlib\nhashlib.sha3_256(b"data")')
        assert len(findings) == 0


class TestInsecurePRNG:
    def test_detects_random_random(self):
        findings = _analyze("import random\ntoken = random.random()")
        assert any("random" in f.message.lower() for f in findings)
        prng_finding = [f for f in findings if "random" in f.message.lower()][0]
        assert prng_finding.severity == Severity.MEDIUM

    def test_detects_random_randint(self):
        findings = _analyze("import random\nval = random.randint(1, 100)")
        assert any("random" in f.message.lower() for f in findings)

    def test_detects_random_choice(self):
        findings = _analyze("import random\nrandom.choice([1, 2, 3])")
        assert any("random" in f.message.lower() for f in findings)


class TestDeprecatedImports:
    def test_detects_crypto_des_import(self):
        findings = _analyze("import Crypto.Cipher.DES")
        assert len(findings) == 1

    def test_detects_crypt_import(self):
        findings = _analyze("import crypt")
        assert len(findings) == 1

    def test_detects_from_import(self):
        findings = _analyze("from Crypto.Cipher.DES import DESCipher")
        assert len(findings) == 1

    def test_ignores_safe_import(self):
        findings = _analyze("import hashlib")
        assert len(findings) == 0


class TestRemediation:
    def test_hash_remediation_suggests_sha256(self):
        findings = _analyze('import hashlib\nhashlib.md5(b"data")')
        assert "sha256" in findings[0].remediation.lower()

    def test_prng_remediation_suggests_secrets(self):
        findings = _analyze("import random\nrandom.random()")
        prng = [f for f in findings if "random" in f.message.lower()][0]
        assert "secrets" in prng.remediation.lower()
