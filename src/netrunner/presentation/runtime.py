from rich.console import Console
from rich.theme import Theme


netrunner_theme = Theme(
    {
        "nr.primary": "bold cyan",
        "nr.text": "white",
        "nr.error": "bold red",
        "nr.success": "bold green",
        "nr.warning": "bold yellow",
        "nr.info": "bold blue",
        "nr.debug": "dim white",
        "nr.command": "bold magenta",
        "nr.argument": "yellow",
        "nr.description": "italic white",
        "nr.result": "bold green",
        "nr.status": "bold cyan",
        "nr.latency": "bold yellow",
        "nr.packet_loss": "bold red",
        "nr.packets_sent": "bold green",
        "nr.packets_received": "bold green",
    }
)

console = Console(theme=netrunner_theme)