"""Rich console setup and common UI utilities."""

from rich.console import Console
from rich.theme import Theme

# Custom theme for the application
SCANNER_THEME = Theme({
    # General colors
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "muted": "dim",

    # UI elements
    "header": "bold cyan",
    "highlight": "bold white",
    "repo": "bold blue",
    "finding.type": "magenta",
    "finding.file": "cyan",
    "finding.commit": "dim yellow",
})

# Global console instance
console = Console(theme=SCANNER_THEME)


def print_error(message: str) -> None:
    """Print an error message."""
    console.print(f"[error]Error:[/error] {message}")


def print_warning(message: str) -> None:
    """Print a warning message."""
    console.print(f"[warning]Warning:[/warning] {message}")


def print_success(message: str) -> None:
    """Print a success message."""
    console.print(f"[success]{message}[/success]")


def print_info(message: str) -> None:
    """Print an informational message."""
    console.print(f"[info]{message}[/info]")


