import unittest
from mcp_sentinel.scanner import scan_secrets, audit_python_ast, calculate_shannon_entropy


class TestMcpSentinel(unittest.TestCase):
    def test_scan_anthropic_key(self):
        fake_code = 'CLAUDE_KEY = "sk-ant-api03-abcdef1234567890abcdef1234567890"'
        findings = scan_secrets(fake_code, file_path="config.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "ANTHROPIC_API_KEY")
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_scan_github_token(self):
        fake_code = 'TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12"'
        findings = scan_secrets(fake_code, file_path="secrets.env")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "GITHUB_TOKEN")

    def test_clean_code_passes(self):
        clean_code = '''
def add(a, b):
    """Calculates sum of two integers."""
    return a + b
'''
        findings = scan_secrets(clean_code)
        self.assertEqual(len(findings), 0)

    def test_audit_dangerous_eval(self):
        unsafe_code = '''
user_input = "__import__('os').system('ls')"
res = eval(user_input)
'''
        findings = audit_python_ast(unsafe_code, file_path="unsafe.py")
        self.assertEqual(len(findings), 1)
        self.assertIn("DANGEROUS_CALL_EVAL", findings[0].rule_id)

    def test_entropy_calculation(self):
        low_entropy = "aaaaaaaaaa"
        high_entropy = "4kP9zW2mQ8vX1yR0!bL"
        self.assertLess(calculate_shannon_entropy(low_entropy), 1.0)
        self.assertGreater(calculate_shannon_entropy(high_entropy), 3.5)


if __name__ == "__main__":
    unittest.main()
