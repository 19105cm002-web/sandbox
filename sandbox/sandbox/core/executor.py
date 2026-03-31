import subprocess
from core.analyzer import detect_risk_level, is_safe_command
from core.simulator import simulate_command
from logs.logger import log_event, update_stat

def execute_command(user_input: str) -> str:
    """
    Execute a validated command in the sandbox.
    Block, log, and alert on any policy violation.
    """
    risk = detect_risk_level(user_input)
    safe, message = is_safe_command(user_input)

    if not safe:
        update_stat("blocked")
        if risk == "HIGH":
            update_stat("high_risk")
        log_event("BLOCKED", user_input, message, risk)
        
        simulated_output = simulate_command(user_input)
        return f"[BLOCKED] {message}\n[SIMULATOR] {simulated_output}"

    try:
        result = subprocess.check_output(
            user_input,
            shell=True,
            stderr=subprocess.STDOUT,
            timeout=5
        )
        update_stat("allowed")
        log_event("ALLOWED", user_input, "Command executed successfully", "LOW")
        return result.decode(errors="replace").strip()

    except subprocess.TimeoutExpired:
        update_stat("blocked")
        log_event("BLOCKED", user_input, "Execution timeout (>5s)", "LOW")
        return "[BLOCKED] Execution timeout — possible DoS attempt"

    except Exception as e:
        update_stat("errors")
        log_event("ERROR", user_input, str(e), "LOW")
        return f"[ERROR] {str(e)}"
