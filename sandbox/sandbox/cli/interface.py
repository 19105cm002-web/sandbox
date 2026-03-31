import os
import sys
import time
import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from rich.align import Align

try:
    import readline
except ImportError:
    pass # Windows provides native history in modern terminals, or fallback

from core.executor import execute_command
from logs.logger import save_report, get_stats, get_log_file_path, log_event

# Define a professional SOC-style theme
custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "danger": "bold red",
    "success": "bold green",
    "prompt": "bold cyan"
})

console = Console(theme=custom_theme)

def clear_screen():
    """Clean screen refresh at startup."""
    os.system("cls" if os.name == "nt" else "clear")

def show_banner():
    """Display the clean, styled banner with title and subtitle."""
    title = Text("KALI SECURE SANDBOX – Zero Trust Engine v2.0", style="bold cyan", justify="center")
    subtitle = Text("Simulated Kali Linux | Monitored & Logged", style="bold white", justify="center")
    
    banner_group = Table.grid(padding=1)
    banner_group.add_column(justify="center")
    banner_group.add_row(title)
    banner_group.add_row(subtitle)
    
    panel = Panel(
        Align.center(banner_group),
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(panel)

def show_session_info():
    """Show session info dashboard inside a styled table/panel."""
    stats = get_stats()
    log_path = get_log_file_path()
    start_time = stats["session_start"][:19]
    
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="cyan", justify="right")
    table.add_column("Value", style="white")
    
    table.add_row("Session Start", start_time)
    table.add_row("Security Policy", "Whitelist + Threat Detection + Simulation")
    table.add_row("Mode", "[bold green]Secure CLI[/bold green]")
    table.add_row("Log File", log_path)
    
    panel = Panel(
        table,
        title="[bold white]SESSION DASHBOARD[/bold white]",
        title_align="left",
        border_style="cyan",
        padding=(0, 2)
    )
    console.print(panel)

def format_output(output: str):
    """Enhance command output formatting."""
    if "[BLOCKED]" in output:
        # Extract the reason visually
        cleaned = output.replace("[BLOCKED]", "").strip()
        console.print(f"🚨 [danger]THREAT DETECTED[/danger]: {cleaned}")
    elif "[ERROR]" in output:
        cleaned = output.replace("[ERROR]", "").strip()
        console.print(f"❌ [warning]ERROR[/warning]: {cleaned}")
    else:
        # Safe execution
        console.print("✔ [success]SUCCESS[/success]\n")
        console.print(output, style="white")

def show_stats():
    """Print current session statistics with colorful Rich tables."""
    stats = get_stats()
    table = Table(title="Live Session Statistics", style="cyan")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right", style="white")
    
    table.add_row("Allowed Commands", str(stats['allowed']))
    table.add_row("Blocked Attempts", f"[red]{stats['blocked']}[/red]")
    table.add_row("Execution Errors", str(stats['errors']))
    table.add_row("High Risk Events", f"[bold red]{stats['high_risk']}[/bold red]")
    table.add_row("Session Start", stats['session_start'][:19])
    
    console.print()
    console.print(table)
    console.print()

def show_logs():
    """Display the recent audit logs from file."""
    console.rule("[bold cyan]SANDBOX AUDIT LOG[/bold cyan]")
    try:
        with open(get_log_file_path(), "r") as f:
            lines = f.readlines()
        if not lines:
            console.print("[warning]No log entries found.[/warning]")
        else:
            for line in lines[-15:]:
                if "HIGH" in line:
                    console.print(line.strip(), style="danger")
                elif "BLOCKED" in line:
                    console.print(line.strip(), style="warning")
                else:
                    console.print(line.strip(), style="info")
    except FileNotFoundError:
        console.print("[warning]No log file found.[/warning]")
    console.rule("[bold cyan]END OF LOG[/bold cyan]")
    console.print()

HELP_TEXT = """
[bold cyan]BUILT-IN COMMANDS:[/bold cyan]
  [white]help[/white]   → Show this menu
  [white]logs[/white]   → View session logs
  [white]stats[/white]  → Session statistics
  [white]report[/white] → Export JSON security report
  [white]clear[/white]  → Clear terminal screen
  [white]exit[/white]   → Exit sandbox

[bold cyan]ALLOWED LINUX COMMANDS:[/bold cyan]
  ls, pwd, whoami, id, hostname, date, uname, ifconfig, ip, ping, netstat...
"""

def print_help():
    panel = Panel(HELP_TEXT, title="[bold white]HELP MENU[/bold white]", border_style="cyan", padding=(1, 2))
    console.print(panel)

def animate_loading():
    """Smooth animation at startup imitating security system boots."""
    with console.status("[bold cyan]Initializing zero-trust engine...", spinner="bouncingBar"):
        time.sleep(1.0)
    with console.status("[bold cyan]Loading behavioral threat profiles...", spinner="bouncingBar"):
        time.sleep(0.5)

def start_cli() -> None:
    """Main execution loop for the new SOC interface."""
    clear_screen()
    show_banner()
    animate_loading()
    console.print()
    show_session_info()
    console.print()
    
    log_event("INFO", "SYSTEM", "Sandbox session started (Rich UI)", "LOW")
    
    while True:
        try:
            # Styled prompt using Python's native input() allows up-arrow history
            # where supported by OS (Windows Terminal powershell automatically leverages PSReadline)
            user_input = console.input("[prompt]sandbox > [/prompt]").strip()
            
            if not user_input:
                continue

            cmd_lower = user_input.lower()

            if cmd_lower == "exit":
                console.print("\n[warning]Terminating sandbox session...[/warning]")
                save_report()
                log_event("INFO", "SYSTEM", "Sandbox session terminated", "LOW")
                console.print("[success]Session Ended cleanly.[/success]\n")
                break
            elif cmd_lower == "help":
                print_help()
            elif cmd_lower == "logs":
                show_logs()
            elif cmd_lower == "stats":
                show_stats()
            elif cmd_lower == "report":
                save_report()
            elif cmd_lower == "clear":
                clear_screen()
                show_banner()
                console.print()
                show_session_info()
                console.print()
            else:
                # Add a tiny delay to simulate deep analysis visually
                with console.status("[bold cyan]Analyzing & Executing...[/bold cyan]", spinner="dots"):
                    time.sleep(0.3)
                    output = execute_command(user_input)
                
                format_output(output)
                console.print() # spacer

        except KeyboardInterrupt:
            console.print("\n\n🚨 [danger]KeyboardInterrupt — Session terminated.[/danger]")
            save_report()
            log_event("INFO", "SYSTEM", "Session interrupted by user", "LOW")
            break
        except Exception as e:
            console.print(f"\n❌ [danger]CRITICAL ERROR: {str(e)}[/danger]")

def run_interface() -> None:
    start_cli()
