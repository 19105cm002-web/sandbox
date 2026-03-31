import re

ALLOWED_COMMANDS = [
    "echo", "date", "whoami", "pwd",
    "ls", "uname", "ifconfig", "ip",
    "ping", "netstat", "hostname", "id",
    "uptime", "df", "free", "ps"
]

BLOCKED_PATTERNS = [
    # Dangerous file operations
    r"\brm\b", r"\bshutdown\b", r"\breboot\b",
    r"\bmkfs\b", r"\bdd\b", r">\s*/dev/",
    r"\bchmod\b", r"\bchown\b", r"\bmv\b",
    r"\bcp\b.*(/etc|/sys|/proc|/boot)",
    # Privilege escalation
    r"\bsudo\b", r"\bsu\b", r"\bpasswd\b",
    r"\bvisudo\b", r"\bcrontab\b",
    # Python / shell escapes
    r"\bos\b", r"\bsys\b", r"\beval\b", r"\bexec\b",
    r"\bimport\b", r"\bopen\b\s*\(",
    r"__import__", r"\bcompile\b",
    # Hacking tools
    r"\bnc\b", r"\bnmap\b", r"\bmsfconsole\b",
    r"\bmetasploit\b", r"\bhydra\b", r"\baircrack\b",
    r"\bjohn\b", r"\bhashcat\b", r"\bwireshark\b",
    r"\btcpdump\b", r"\bcurl\b", r"\bwget\b",
    # Command injection
    r";", r"&&", r"\|\|", r"\$\(",
    r"`", r"\bxargs\b",
    # Path traversal
    r"\.\./", r"/etc/passwd", r"/etc/shadow",
    r"/root/", r"/proc/", r"/sys/"
]

# Risk level thresholds
HIGH_RISK_PATTERNS = [
    r"\bnmap\b", r"\bmsfconsole\b", r"\bhydra\b",
    r"/etc/shadow", r"\bsudo\b", r"\bpasswd\b",
    r"__import__", r"\beval\b", r"\bexec\b"
]

def detect_risk_level(user_input: str) -> str:
    """Return HIGH if input contains critical patterns, else LOW."""
    for pattern in HIGH_RISK_PATTERNS:
        if re.search(pattern, user_input, re.IGNORECASE):
            return "HIGH"
    return "LOW"

def is_safe_command(user_input: str):
    """
    Zero-Trust Validation Engine.
    Returns (is_safe: bool, reason: str)
    """
    # Check blocked patterns first
    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, user_input, re.IGNORECASE):
            return False, f"Blocked pattern matched: [{pattern}]"

    parts = user_input.split()
    if not parts:
        return False, "Empty command"

    base_command = parts[0].lower()

    if base_command not in ALLOWED_COMMANDS:
        return False, f"Command '{base_command}' is not in the whitelist"

    return True, "Validated — safe to execute"
