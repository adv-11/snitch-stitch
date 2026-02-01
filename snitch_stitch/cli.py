"""CLI entry point for snitch-stitch security auditor."""

import os
import sys

import click

from .ingest import ingest_repo
from .backend_scanner import scan_backend
from .frontend_scanner import scan_frontend
from .ranker import rank_findings
from .fixer import generate_fix
from .diff_display import display_and_apply_diff


def print_stage(stage_num: int, message: str) -> None:
    """Print a stage header."""
    click.echo(f"\n[{stage_num}/5] {message}")


def print_success(message: str) -> None:
    """Print a success message with checkmark."""
    click.echo(f"      \u2713 {message}")


def print_notice(message: str) -> None:
    """Print a notice message."""
    click.echo(f"      {message}")


def print_table(findings: list) -> None:
    """Print the findings summary table."""
    if not findings:
        click.echo("\nNo vulnerabilities found.")
        return

    # Calculate column widths
    title_width = max(len(f.get("title", "")[:40]) for f in findings)
    title_width = max(title_width, 5)  # minimum width

    # Print table
    click.echo()
    click.echo("\u2554" + "\u2550" * 4 + "\u2566" + "\u2550" * 10 + "\u2566" + "\u2550" * (title_width + 2) + "\u2566" + "\u2550" * 7 + "\u2557")
    click.echo("\u2551 #  \u2551 Severity \u2551 " + "Title".ljust(title_width) + " \u2551 Score \u2551")
    click.echo("\u2560" + "\u2550" * 4 + "\u256c" + "\u2550" * 10 + "\u256c" + "\u2550" * (title_width + 2) + "\u256c" + "\u2550" * 7 + "\u256c")

    for i, finding in enumerate(findings, 1):
        num = str(i).rjust(2)
        severity = finding.get("severity", "Unknown")[:8].ljust(8)
        title = finding.get("title", "")[:title_width].ljust(title_width)
        score = str(finding.get("score", 0)).rjust(3)
        click.echo(f"\u2551 {num} \u2551 {severity} \u2551 {title} \u2551  {score}  \u2551")

    click.echo("\u255a" + "\u2550" * 4 + "\u2569" + "\u2550" * 10 + "\u2569" + "\u2550" * (title_width + 2) + "\u2569" + "\u2550" * 7 + "\u255d")


def get_user_selection(findings: list, fix_all: bool) -> list:
    """Get user selection of vulnerabilities to fix."""
    if fix_all:
        return findings

    click.echo("\nSelect vulnerabilities to fix (comma-separated numbers, or 'all'):")
    user_input = click.prompt(">", type=str)

    if user_input.strip().lower() == "all":
        return findings

    try:
        indices = [int(x.strip()) for x in user_input.split(",")]
        selected = []
        for idx in indices:
            if 1 <= idx <= len(findings):
                selected.append(findings[idx - 1])
            else:
                click.echo(f"Warning: {idx} is out of range, skipping.")
        return selected
    except ValueError:
        click.echo("Invalid input. Skipping fix generation.")
        return []


@click.command()
@click.argument("repo_path", type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option(
    "--frontend-url",
    type=str,
    default=None,
    help="URL of a running frontend (e.g. http://localhost:3000). Enables frontend scanning.",
)
@click.option(
    "--fix-all",
    is_flag=True,
    default=False,
    help="Skip the selection prompt and attempt to fix everything.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Show diffs but never write anything to disk.",
)
@click.option(
    "--verbose",
    is_flag=True,
    default=False,
    help="Print debug info (raw API responses, parsed JSON, etc.).",
)
def main(repo_path: str, frontend_url: str, fix_all: bool, dry_run: bool, verbose: bool) -> None:
    """Scan a Git repository for security vulnerabilities and generate fixes.

    REPO_PATH is the path to the local repository directory to scan.

    This tool modifies real files when fixes are accepted. Use --dry-run to preview
    without making changes.
    """
    # Check required environment variables
    openai_api_key = os.environ.get("OPENAI_API_KEY")
    if not openai_api_key:
        click.echo("Error: OPENAI_API_KEY environment variable is not set. Please set it and try again.")
        sys.exit(1)

    rtrvr_api_key = os.environ.get("RTRVR_API_KEY")

    # Convert to absolute path
    repo_path = os.path.abspath(repo_path)

    # Stage 1: Ingest
    print_stage(1, "Ingesting repository...")
    try:
        summary, tree, content = ingest_repo(repo_path)
        file_count = summary.get("file_count", "?")
        total_size = summary.get("total_size", "?")
        print_success(f"Ingested {file_count} files ({total_size})")
        if verbose:
            click.echo(f"\n      Tree:\n{tree}")
    except Exception as e:
        click.echo(f"Error: Failed to ingest repository: {e}")
        sys.exit(1)

    # Stage 2: Backend scan
    print_stage(2, "Scanning backend code...")
    backend_findings = scan_backend(content, openai_api_key, verbose=verbose)
    print_success(f"Found {len(backend_findings)} backend vulnerabilities")

    # Stage 3: Frontend scan (optional)
    print_stage(3, "Scanning frontend...")
    frontend_findings = []
    if frontend_url and rtrvr_api_key:
        frontend_findings = scan_frontend(frontend_url, rtrvr_api_key, verbose=verbose)
        print_success(f"Found {len(frontend_findings)} frontend vulnerabilities")
    elif frontend_url and not rtrvr_api_key:
        print_notice("Notice: RTRVR_API_KEY not set. Skipping frontend scanning.")
    else:
        print_notice("Skipped (no --frontend-url provided)")

    # Stage 4: Rank findings
    print_stage(4, "Ranking findings...")
    all_findings = backend_findings + frontend_findings
    ranked_findings = rank_findings(all_findings)
    print_success(f"Ranked {len(ranked_findings)} findings")

    # Stage 5: Review and fix
    print_stage(5, "Review and fix")

    if not ranked_findings:
        click.echo("\nNo vulnerabilities to fix. Your code looks clean!")
        return

    print_table(ranked_findings)

    # Get user selection
    selected = get_user_selection(ranked_findings, fix_all)

    if not selected:
        click.echo("\nNo vulnerabilities selected. Exiting.")
        return

    # Generate and apply fixes
    for finding in selected:
        click.echo(f"\n--- Generating fix for: {finding.get('title', 'Unknown')} ---")

        fix = generate_fix(finding, content, openai_api_key, verbose=verbose)

        if fix is None:
            click.echo("Could not generate a fix for this vulnerability.")
            continue

        if fix.get("note"):
            click.echo(f"Note: {fix['note']}")
            continue

        original_lines = fix.get("original_lines", "")
        fixed_lines = fix.get("fixed_lines", "")

        if not original_lines:
            click.echo("No code changes needed for this vulnerability.")
            continue

        file_path = finding.get("file", "")
        if not file_path:
            click.echo("Error: No file path in finding. Skipping.")
            continue

        full_file_path = os.path.join(repo_path, file_path)

        display_and_apply_diff(
            file_path=full_file_path,
            original_lines=original_lines,
            fixed_lines=fixed_lines,
            finding_title=finding.get("title", "Unknown"),
            finding_severity=finding.get("severity", "Unknown"),
            dry_run=dry_run,
        )

    click.echo("\nDone!")


if __name__ == "__main__":
    main()
