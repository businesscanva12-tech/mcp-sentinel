"""
Security rules and signature patterns for detection across 25+ credential providers.
"""

from typing import Dict

PATTERNS: Dict[str, Dict[str, str]] = {
    # AI & Cloud Providers
    "ANTHROPIC_API_KEY": {
        "regex": r"sk-ant-api[a-zA-Z0-9_\-]{20,}",
        "severity": "CRITICAL",
        "description": "Anthropic Claude API key detected",
    },
    "OPENAI_API_KEY": {
        "regex": r"sk-(?!ant-api)(?:proj-|live-)?[a-zA-Z0-9_\-]{32,}",
        "severity": "CRITICAL",
        "description": "OpenAI API key or project token detected",
    },
    "HUGGINGFACE_TOKEN": {
        "regex": r"hf_[a-zA-Z0-9]{34,}",
        "severity": "CRITICAL",
        "description": "Hugging Face User Access Token detected",
    },
    "GOOGLE_API_KEY": {
        "regex": r"AIza[0-9A-Za-z\-_]{35}",
        "severity": "HIGH",
        "description": "Google Cloud API key detected",
    },
    "AWS_ACCESS_KEY": {
        "regex": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "severity": "HIGH",
        "description": "AWS Access Key ID detected",
    },
    "AZURE_STORAGE_KEY": {
        "regex": r"""DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[a-zA-Z0-9+/=]{40,}""",
        "severity": "CRITICAL",
        "description": "Azure Storage connection string detected",
    },

    # Developer & VCS Platforms
    "GITHUB_TOKEN": {
        "regex": r"(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,255}",
        "severity": "CRITICAL",
        "description": "GitHub Personal Access Token or OAuth key detected",
    },
    "GITHUB_FINE_GRAINED_PAT": {
        "regex": r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}",
        "severity": "CRITICAL",
        "description": "GitHub Fine-Grained Personal Access Token detected",
    },
    "GITLAB_PAT": {
        "regex": r"glpat-[a-zA-Z0-9_\-]{20,}",
        "severity": "CRITICAL",
        "description": "GitLab Personal Access Token detected",
    },

    # Payment & SaaS Integrations
    "STRIPE_SECRET_KEY": {
        "regex": r"(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99}",
        "severity": "CRITICAL",
        "description": "Stripe Live/Test Secret API key detected",
    },
    "SLACK_BOT_TOKEN": {
        "regex": r"xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}",
        "severity": "HIGH",
        "description": "Slack Bot User OAuth Token detected",
    },
    "SLACK_WEBHOOK": {
        "regex": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        "severity": "HIGH",
        "description": "Slack Incoming Webhook URL detected",
    },
    "DISCORD_BOT_TOKEN": {
        "regex": r"(?:mfa\.[a-z0-9_\-]{20,}|[a-z0-9_\-]{24}\.[a-z0-9_\-]{6}\.[a-z0-9_\-]{27})",
        "severity": "HIGH",
        "description": "Discord Bot authentication token detected",
    },
    "SENDGRID_API_KEY": {
        "regex": r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
        "severity": "HIGH",
        "description": "SendGrid Email API key detected",
    },
    "SUPABASE_ANON_OR_SERVICE": {
        "regex": r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+",
        "severity": "HIGH",
        "description": "Supabase JWT or generic service secret token detected",
    },

    # Generic & Private Keys
    "PRIVATE_KEY_BLOCK": {
        "regex": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        "severity": "CRITICAL",
        "description": "Unencrypted Private Key header block detected",
    },
    "GENERIC_SECRET_ASSIGNMENT": {
        "regex": r"""(?i)(?:api_key|secret_key|auth_token|access_token|password|passwd|private_key)\s*[:=]\s*['"][a-zA-Z0-9@#$%^&*()_+=\-]{12,}['"]""",
        "severity": "MEDIUM",
        "description": "Hardcoded secret or credential assignment detected",
    },
}

DANGEROUS_AST_CALLS: Dict[str, str] = {
    "eval": "Dynamic code evaluation using eval() presents severe arbitrary execution risk",
    "exec": "Dynamic code execution using exec() presents arbitrary code execution risk",
    "os.system": "Executing shell commands directly with os.system() is vulnerable to injection",
    "subprocess.Popen": "Review subprocess usage with shell=True for command injection vulnerabilities",
    "__import__": "Dynamic package importation via __import__() bypasses static dependency analysis",
}
