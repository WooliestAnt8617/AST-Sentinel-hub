import importlib
import inspect
import pkgutil

from ast_sentinel.core.visitor import BaseRuleVisitor, PythonAstRuleVisitor
from ast_sentinel.schemas.findings import Severity


class RuleRegistry:
    _instance: "RuleRegistry | None" = None

    def __new__(cls):
        if cls._instance is None:
            instance = super().__new__(cls)
            instance._rules: dict[str, type[BaseRuleVisitor]] = {}
            instance._discovered = False
            cls._instance = instance
        return cls._instance

    def discover_rules(self):
        self._rules.clear()

        try:
            import ast_sentinel.rules
            package = ast_sentinel.rules
        except ImportError:
            return

        prefix = package.__name__ + "."

        for _, modname, _ in pkgutil.iter_modules(package.__path__, prefix):
            try:
                module = importlib.import_module(modname)
                for name, obj in inspect.getmembers(module):
                    if (
                        inspect.isclass(obj)
                        and issubclass(obj, BaseRuleVisitor)
                        and obj not in (BaseRuleVisitor, PythonAstRuleVisitor)
                        and hasattr(obj, 'rule_id')
                    ):
                        self._rules[obj.rule_id] = obj
            except Exception as e:
                print(f"Error loading module {modname}: {e}")

        self._discovered = True

    def get_all_rules(self) -> dict[str, type[BaseRuleVisitor]]:
        if not self._discovered:
            self.discover_rules()
        return self._rules

    def get_rule(self, rule_id: str) -> type[BaseRuleVisitor] | None:
        if not self._discovered:
            self.discover_rules()
        return self._rules.get(rule_id)

    def get_rules_by_severity(self, severity: Severity) -> dict[str, type[BaseRuleVisitor]]:
        """Return rules at or above the given severity threshold."""
        if not self._discovered:
            self.discover_rules()

        severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        threshold_idx = severity_order.index(severity)
        allowed = set(severity_order[threshold_idx:])

        return {
            rid: cls for rid, cls in self._rules.items()
            if hasattr(cls, 'severity') and cls.severity in allowed
        }


def get_registry() -> RuleRegistry:
    return RuleRegistry()
