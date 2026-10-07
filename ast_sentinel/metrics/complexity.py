import ast


class ComplexityAnalyzer(ast.NodeVisitor):
    """Calculates cyclomatic complexity via AST traversal."""

    DECISION_NODES = (
        ast.If, ast.For, ast.While, ast.ExceptHandler,
        ast.With, ast.Assert, ast.IfExp,  # ternary
    )

    def __init__(self):
        self._complexity = 0

    def _count(self, node: ast.AST):
        """Walk a subtree and return its cyclomatic complexity (base 1)."""
        counter = _ComplexityCounter()
        counter.visit(node)
        return 1 + counter.count

    def analyze_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
        return self._count(node)

    def analyze_file(self, tree: ast.Module) -> tuple[int, dict[str, int]]:
        """Returns (aggregate_complexity, {func_name: complexity})."""
        per_function: dict[str, int] = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                score = self.analyze_function(node)
                per_function[node.name] = score

        aggregate = sum(per_function.values()) if per_function else self._count(tree)
        return aggregate, per_function

    @staticmethod
    def complexity_grade(score: int) -> str:
        if score <= 10:
            return "A"  # Simple
        elif score <= 20:
            return "B"  # Moderate
        elif score <= 50:
            return "C"  # Complex
        else:
            return "F"  # Untestable


class _ComplexityCounter(ast.NodeVisitor):
    def __init__(self):
        self.count = 0

    def visit_If(self, node):
        self.count += 1
        self.generic_visit(node)

    def visit_For(self, node):
        self.count += 1
        self.generic_visit(node)

    def visit_While(self, node):
        self.count += 1
        self.generic_visit(node)

    def visit_ExceptHandler(self, node):
        self.count += 1
        self.generic_visit(node)

    def visit_With(self, node):
        self.count += 1
        self.generic_visit(node)

    def visit_Assert(self, node):
        self.count += 1
        self.generic_visit(node)

    def visit_IfExp(self, node):
        self.count += 1
        self.generic_visit(node)

    def visit_BoolOp(self, node):
        # Each 'and' / 'or' adds a branch
        self.count += len(node.values) - 1
        self.generic_visit(node)
