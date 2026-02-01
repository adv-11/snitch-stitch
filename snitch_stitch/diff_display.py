"""Diff display and file modification module."""

import difflib
import os
from typing import List

import click

# ANSI color codes
RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def generate_diff(old_content: str, new_content: str, file_path: str) -> List[str]:
    """Generate a unified diff between old and new content.

    Args:
        old_content: The original file content.
        new_content: The modified file content.
        file_path: The file path (for diff header).

    Returns:
        A list of diff lines.
    """
    old_lines = old_content.splitlines(keepends=True)
    new_lines = new_content.splitlines(keepends=True)

    diff = list(
        difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            lineterm="",
        )
    )

    return diff


def colorize_diff(diff_lines: List[str]) -> str:
    """Add ANSI colors to diff output.

    Args:
        diff_lines: List of diff lines.

    Returns:
        Colored diff string ready for terminal output.
    """
    colored_lines = []

    for line in diff_lines:
        # Remove trailing newline for consistent handling
        line = line.rstrip("\n")

        if line.startswith("---") or line.startswith("+++"):
            # File headers - bold
            colored_lines.append(f"{BOLD}{line}{RESET}")
        elif line.startswith("@@"):
            # Hunk headers - dim
            colored_lines.append(f"{DIM}{line}{RESET}")
        elif line.startswith("-"):
            # Removals - red
            colored_lines.append(f"{RED}{line}{RESET}")
        elif line.startswith("+"):
            # Additions - green
            colored_lines.append(f"{GREEN}{line}{RESET}")
        else:
            # Context lines - default
            colored_lines.append(line)

    return "\n".join(colored_lines)


def display_and_apply_diff(
    file_path: str,
    original_lines: str,
    fixed_lines: str,
    finding_title: str,
    finding_severity: str,
    dry_run: bool = False,
    show_fixed_message: bool = True,
) -> bool:
    """Display a colored diff and optionally apply the fix.

    Args:
        file_path: Absolute path to the file to modify.
        original_lines: The original code block to replace.
        fixed_lines: The replacement code block.
        finding_title: Title of the vulnerability being fixed.
        finding_severity: Severity level of the vulnerability.
        dry_run: If True, show diff but don't write to disk.
        show_fixed_message: If True, show "Fixed" message after applying. Set to False
            when more changes may follow for the same vulnerability.

    Returns:
        True if the fix was applied, False otherwise.
    """
    # Check if file exists
    if not os.path.isfile(file_path):
        click.echo(f"Warning: File not found: {file_path}. Skipping this fix.")
        return False

    # Read the current file content
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            current_content = f.read()
    except Exception as e:
        click.echo(f"Error reading file {file_path}: {e}")
        return False

    # Check if original_lines exists in the file
    if original_lines not in current_content:
        click.echo(f"Could not locate the code block in {file_path}. Skipping this fix.")
        return False

    # Generate the new content
    new_content = current_content.replace(original_lines, fixed_lines, 1)

    # Generate and display the diff
    relative_path = os.path.basename(file_path)
    # Try to get a more meaningful relative path
    for marker in ["snitch_stitch", "src", "app", "lib"]:
        if marker in file_path:
            idx = file_path.find(marker)
            relative_path = file_path[idx:]
            break

    diff_lines = generate_diff(current_content, new_content, relative_path)

    if not diff_lines:
        click.echo("No changes detected.")
        return False

    # Print header
    click.echo(f"\n {BOLD}{relative_path}{RESET}")
    click.echo("\u2500" * 50)

    # Print colored diff
    colored_diff = colorize_diff(diff_lines)
    click.echo(colored_diff)

    click.echo("\u2500" * 50)

    if dry_run:
        click.echo(f"{DIM}[dry-run] Would apply fix to {relative_path}{RESET}")
        return False

    # Prompt user for confirmation
    response = click.prompt("Apply this fix? [y/n]", type=str, default="n")

    if response.lower() in ("y", "yes"):
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(new_content)
            if show_fixed_message:
                click.echo(f"{GREEN}\u2713 Fixed: {relative_path}{RESET}")
            return True
        except Exception as e:
            click.echo(f"{RED}Error writing file {file_path}: {e}{RESET}")
            return False
    else:
        click.echo("Skipped.")
        return False
