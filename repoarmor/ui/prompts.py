"""Interactive prompts for user input."""

from typing import Callable, TypeVar

from rich.prompt import Prompt, Confirm, IntPrompt

from .console import console

T = TypeVar("T")


def prompt_note() -> str | None:
    """Prompt user for an optional note.

    Returns:
        Note string or None if empty.
    """
    note = Prompt.ask("Note (optional)", default="")
    return note if note.strip() else None


def prompt_confirm(message: str, default: bool = False) -> bool:
    """Prompt user for confirmation.

    Args:
        message: Confirmation message.
        default: Default value if user presses enter.

    Returns:
        True if confirmed, False otherwise.
    """
    return Confirm.ask(message, default=default)


def prompt_finding_ids(max_id: int) -> list[int]:
    """Prompt user for finding IDs.

    Args:
        max_id: Maximum valid ID for validation hint.

    Returns:
        List of finding IDs.
    """
    console.print(f"\nEnter finding IDs (1-{max_id})")
    console.print("Examples: '1,2,3' or '1-5' or '1,3-5,7'")

    while True:
        ids_str = Prompt.ask("Finding IDs")

        try:
            ids = []
            for part in ids_str.split(","):
                part = part.strip()
                if "-" in part:
                    start, end = part.split("-")
                    ids.extend(range(int(start), int(end) + 1))
                else:
                    ids.append(int(part))

            # Validate all IDs are in range
            invalid = [i for i in ids if i < 1 or i > max_id]
            if invalid:
                console.print(f"[error]Invalid IDs: {invalid}[/error]")
                continue

            return sorted(set(ids))

        except ValueError:
            console.print("[error]Invalid format. Use: 1,2,3 or 1-5[/error]")


def prompt_repo_selection(repos: list[tuple[int, str]]) -> int | None:
    """Prompt user to select a repository.

    Args:
        repos: List of (id, name) tuples.

    Returns:
        Selected repository ID or None.
    """
    if not repos:
        console.print("[warning]No repositories found[/warning]")
        return None

    console.print("\nSelect a repository:")
    for repo_id, name in repos:
        console.print(f"  [{repo_id}] {name}")

    while True:
        choice = Prompt.ask("Repository ID (or 'q' to cancel)")

        if choice.lower() == "q":
            return None

        try:
            repo_id = int(choice)
            if any(r[0] == repo_id for r in repos):
                return repo_id
            console.print("[error]Invalid repository ID[/error]")
        except ValueError:
            console.print("[error]Please enter a number[/error]")
