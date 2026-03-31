def simulate_command(command: str) -> str:
    """Simulates responses for common attacks to keep attackers engaged without real risk."""
    cmd_lower = command.lower()
    
    if "rm -rf" in cmd_lower:
        return "rm: cannot remove '/': Permission denied"
    elif "sudo" in cmd_lower or "su " in cmd_lower:
        return "bash: sudo: command not found"
    elif "nmap" in cmd_lower:
        return "bash: nmap: command not found"
    elif "nc " in cmd_lower or "netcat" in cmd_lower:
        return "bash: nc: command not found"
    elif "cat /etc/shadow" in cmd_lower:
        return "cat: /etc/shadow: Permission denied"
    
    # Generic block message simulation
    return f"bash: {command.split()[0] if command else ''}: command not found"
