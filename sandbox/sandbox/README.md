# Advanced Secure Sandbox System

## Overview
A production-grade, zero-trust execution sandbox built in Python, designed to safely execute, monitor, and audit system commands. This project demonstrates advanced threat modeling, strict capability dropping, attack simulation, and structured logging, making it an ideal showcase for a SOC Analyst or DevSecOps portfolio.

## Architecture
The sandbox is modularized for maintainability and scalability:
- **`cli/`**: The interactive security console.
- **`core/`**: The brain of the sandbox, containing the `analyzer` (threat detection via regex patterns) and the `simulator` (attack emulation).
- **`logs/`**: The audit engine which generates structured logs and JSON reports.
- **`web/`**: A boilerplate for a potential dashboard (e.g. using Flask).

## Security Features
1. **Zero-Trust Input Validation**: Uses a strict whitelist approach `ALLOWED_COMMANDS`. Any unlisted command is blocked by default.
2. **Malicious Pattern Detection**: Employs regex signatures against known hacking tools (`nmap`, `nc`), destructive binaries (`rm -rf`), and command injections (`&&`, `;`, `$()`).
3. **Attack Emulation (Deception Layer)**: Provides simulated, unprivileged responses to high-risk commands (like trying to map the network or edit `/etc/shadow`), engaging the attacker while protecting the host.
4. **Hardened Docker Runtime**:
   - `cap_drop: ALL`
   - `read_only: true` (Read-only root filesystem)
   - `no-new-privileges` bounds.
   - Non-root user context.

## Setup & Execution

### Local Environment
```bash
# Clone the repository
git clone <your-repo-link>
cd sandbox

# Run the interactive sandbox
python main.py
```

### Docker (Recommended Secure Mode)
Run the sandbox within its hardened container isolation:
```bash
# Build and run interactively
docker-compose run --rm sandbox
```

## Running Tests
Unit tests validate the core `analyzer` against a suite of attacks.
```bash
python -m unittest discover tests
```

## Portfolio Value
This project highlights skills in **SIEM Auditing** (logging, risk scoring), **Container Security** (Docker hardening), **Threat Modeling**, and **Deception Technology**.
