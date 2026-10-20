import unittest
from mcp_sentinel.scanner import scan_secrets, audit_python_ast, calculate_shannon_entropy, scan_directory_parallel
from mcp_sentinel.sarif import generate_sarif_report


class TestMcpSentinel(unittest.TestCase):
    def test_scan_anthropic_key(self):
        prefix = "sk-ant-api03"
        suffix = "abcdef1234567890abcdef1234567890"
        fake_code = f'CLAUDE_KEY = "{prefix}-{suffix}"'
        findings = scan_secrets(fake_code, file_path="config.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "ANTHROPIC_API_KEY")
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_scan_github_token(self):
        token_val = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz12"
        fake_code = f'TOKEN = "{token_val}"'
        findings = scan_secrets(fake_code, file_path="secrets.env")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "GITHUB_TOKEN")

    def test_scan_stripe_key(self):
        stripe_val = "sk_test_" + "51Abcdefghijklmnopqrstuvwxyza1234567890"
        fake_code = f'STRIPE = "{stripe_val}"'
        findings = scan_secrets(fake_code, file_path="payments.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "STRIPE_SECRET_KEY")

    def test_scan_huggingface_token(self):
        hf_val = "hf_" + "0123456789abcdefghijklmnopqrstuvwxyz"
        fake_code = f'HF_KEY = "{hf_val}"'
        findings = scan_secrets(fake_code, file_path="model.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "HUGGINGFACE_TOKEN")

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
        self.assertTrue(any("DANGEROUS_CALL_EVAL" in f.rule_id for f in findings))

    def test_entropy_calculation(self):
        low_entropy = "aaaaaaaaaa"
        high_entropy = "4kP9zW2mQ8vX1yR0!bL"
        self.assertLess(calculate_shannon_entropy(low_entropy), 1.0)
        self.assertGreater(calculate_shannon_entropy(high_entropy), 3.5)

    def test_sarif_export(self):
        tok = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz12"
        fake_code = f'API_TOKEN = "{tok}"'
        findings = scan_secrets(fake_code, file_path="test_file.py")
        sarif = generate_sarif_report(findings, tool_version="0.2.0")
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)
        self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "GITHUB_TOKEN")


if __name__ == "__main__":
    unittest.main()
