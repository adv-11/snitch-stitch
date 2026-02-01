"""Fix generation module using Claude Sonnet 4.5 with extended thinking."""

import json
import sys
from typing import Dict, List, Optional

import anthropic
import click

from .ingest import extract_file_content

# Constants for display
THINKING_LINE_WIDTH = 60
THINKING_NUM_LINES = 3


class ThinkingDisplay:
    """Handles real-time display of thinking with 3-line scrolling window."""

    def __init__(self, header: str, color_code: str = "36"):
        self.header = header
        self.color = color_code
        self.lines: List[str] = []
        self.displayed_lines = 0
        self.started = False

    def _truncate_line(self, line: str) -> str:
        """Truncate a line to fit the display width, showing the end (most recent content)."""
        if len(line) > THINKING_LINE_WIDTH:
            # Show the end of the line so user sees the most recent content being typed
            return "..." + line[-(THINKING_LINE_WIDTH - 3):]
        return line.ljust(THINKING_LINE_WIDTH)

    def _clear_lines(self, count: int) -> None:
        """Move cursor up and clear lines."""
        for _ in range(count):
            sys.stdout.write("\033[A")  # Move up
            sys.stdout.write("\033[K")  # Clear line

    def start(self) -> None:
        """Print the header and initial empty lines."""
        if self.started:
            return
        self.started = True
        click.echo(f"\n      \033[{self.color}m┌─ {self.header} {'─' * (THINKING_LINE_WIDTH - len(self.header) - 1)}┐\033[0m")
        # Print empty placeholder lines
        for _ in range(THINKING_NUM_LINES):
            click.echo(f"      \033[{self.color}m│\033[0m {' ' * THINKING_LINE_WIDTH} \033[{self.color}m│\033[0m")
        self.displayed_lines = THINKING_NUM_LINES

    def update(self, text: str) -> None:
        """Update the display with new thinking text."""
        if not self.started:
            self.start()

        # Split text into lines and keep last N
        all_lines = text.split("\n")
        # Filter out empty lines at the end
        while all_lines and not all_lines[-1].strip():
            all_lines.pop()

        # Get the last 3 non-empty lines
        self.lines = all_lines[-THINKING_NUM_LINES:] if all_lines else []

        # Move cursor up to overwrite previous lines
        self._clear_lines(self.displayed_lines)

        # Print the current lines (always print exactly 3 lines)
        for i in range(THINKING_NUM_LINES):
            if i < len(self.lines):
                line = self._truncate_line(self.lines[i])
            else:
                line = " " * THINKING_LINE_WIDTH
            click.echo(f"      \033[{self.color}m│\033[0m {line} \033[{self.color}m│\033[0m")

        sys.stdout.flush()

    def finish(self) -> None:
        """Print the footer."""
        if not self.started:
            return
        click.echo(f"      \033[{self.color}m└{'─' * (THINKING_LINE_WIDTH + 2)}┘\033[0m")

EVALUATE_AND_FIX_PROMPT = """You are a code security fixer. A fix was just applied to address a specific vulnerability. Your job is to evaluate if THIS SPECIFIC vulnerability is now FULLY fixed, and if not, provide the next fix.

IMPORTANT RULES:
- ONLY consider whether THIS SPECIFIC vulnerability (described below) needs more changes
- Do NOT consider other vulnerabilities or general code improvements
- Do NOT suggest fixes for other security issues
- If the vulnerability requires changes in multiple places in the file to be fully fixed, provide the next fix
- If the fix is complete, indicate no more changes are needed
- CRITICAL: Your fix must NOT break existing functionality. Ensure the code still works correctly after the fix.

Respond with ONLY a JSON object with these keys:
- "needs_more_changes": true or false
- "reason": brief explanation (1 sentence max)
- "original_lines": (ONLY if needs_more_changes is true) the exact block of code that needs to change next. Must be an exact substring match.
- "fixed_lines": (ONLY if needs_more_changes is true) the replacement code.

If needs_more_changes is false, only include "needs_more_changes" and "reason" keys.

Return ONLY the JSON object. No markdown. No explanation outside the JSON."""

FIX_GENERATION_PROMPT = """You are a code security fixer. You are given a specific security vulnerability and the full content of the file where it exists.

Your job: produce a MINIMAL fix. Change only what is necessary to fix the vulnerability. Do not refactor. Do not rewrite the file. Do not add comments explaining the fix.

CRITICAL: Your fix must NOT break existing functionality. The code must continue to work correctly after the fix is applied. Preserve the original behavior while eliminating the security vulnerability.

Respond with ONLY a JSON object with these two keys:
- "original_lines": the exact block of code (as it currently exists in the file) that needs to change. This must be an exact substring match — copy it character for character from the file.
- "fixed_lines": the replacement code that fixes the vulnerability.

Rules for the fix:
- For SQL injection: use parameterized queries or ORM methods instead of string concatenation.
- For command injection: use subprocess.run() with a list of arguments and shell=False instead of os.system() or shell=True.
- For hardcoded secrets: replace the literal value with a reference to an environment variable using os.environ or os.getenv. Add a comment showing which env var name to set.
- For path traversal: add os.path.realpath() + a check that the resolved path starts with the expected base directory.
- For deserialization: replace pickle.loads / yaml.load with safe alternatives. For yaml, use yaml.safe_load(). For pickle, remove the usage and note that a safe alternative is needed.
- For XSS (if a fix can be applied server-side): ensure output is escaped. For frontend-only XSS, the fix may not be applicable — in that case set original_lines and fixed_lines both to an empty string and add a key "note" explaining why.
- For missing auth checks: add an authentication/authorization guard at the top of the relevant handler function.

Return ONLY the JSON object. No markdown. No explanation."""


def generate_fix(
    finding: Dict,
    repo_content: str,
    api_key: str,
    verbose: bool = False,
    file_content_override: Optional[str] = None,
    show_thinking: bool = True,
) -> Optional[Dict]:
    """Generate a fix for a vulnerability using Claude Sonnet 4.5 with extended thinking.

    Args:
        finding: The vulnerability finding dict with file, description, etc.
        repo_content: The full repository content from gitingest.
        api_key: Anthropic API key.
        verbose: If True, print debug information.
        file_content_override: If provided, use this as the file content instead of
            extracting from repo_content. Useful for generating additional fixes
            after the file has already been modified.
        show_thinking: If True, display Claude's thinking process in the CLI.

    Returns:
        A dict with "original_lines" and "fixed_lines" keys, or None if
        fix generation failed. May also include a "note" key for frontend-only issues.
    """
    file_path = finding.get("file", "")

    # Frontend findings may not have a file path
    if not file_path:
        if finding.get("_source") == "frontend":
            return {
                "original_lines": "",
                "fixed_lines": "",
                "note": "This is a frontend-only vulnerability. The fix must be applied in the client-side code or server rendering logic.",
            }
        return None

    # Use override content if provided, otherwise extract from repo
    if file_content_override is not None:
        file_content = file_content_override
    else:
        file_content = extract_file_content(repo_content, file_path)

    if not file_content:
        if verbose:
            click.echo(f"      [DEBUG] Could not extract content for file: {file_path}")
        return None

    # Build the prompt
    vulnerability_info = f"""Vulnerability details:
- ID: {finding.get('id', 'unknown')}
- Title: {finding.get('title', 'Unknown vulnerability')}
- Class: {finding.get('class', 'unknown')}
- File: {file_path}
- Line range: {finding.get('line_range', 'unknown')}
- Description: {finding.get('description', 'No description')}
- Source: {finding.get('source', 'unknown')}
- Sink: {finding.get('sink', 'unknown')}

File content:
```
{file_content}
```"""

    client = anthropic.Anthropic(api_key=api_key)

    try:
        thinking_text = ""
        result_text = ""
        display = ThinkingDisplay("Thinking...", "36") if show_thinking else None

        # Use streaming to show thinking in real-time
        with client.messages.stream(
            model="claude-sonnet-4-5-20250929",
            max_tokens=16000,
            thinking={
                "type": "enabled",
                "budget_tokens": 5000,
            },
            messages=[
                {"role": "user", "content": f"{FIX_GENERATION_PROMPT}\n\n{vulnerability_info}"},
            ],
        ) as stream:
            for event in stream:
                # Handle thinking content
                if hasattr(event, "type"):
                    if event.type == "content_block_start":
                        if hasattr(event, "content_block") and event.content_block.type == "thinking":
                            if display:
                                display.start()
                    elif event.type == "content_block_delta":
                        if hasattr(event, "delta"):
                            if event.delta.type == "thinking_delta":
                                thinking_text += event.delta.thinking
                                if display:
                                    display.update(thinking_text)
                            elif event.delta.type == "text_delta":
                                result_text += event.delta.text

        if display:
            display.finish()

        if verbose and result_text:
            click.echo(f"\n      [DEBUG] Fix generation raw response:\n{result_text}")

        # Parse the JSON response
        fix = parse_fix_response(result_text)

        return fix

    except Exception as e:
        if verbose:
            import traceback
            click.echo(f"      Warning: Fix generation failed: {e}")
            click.echo(f"      [DEBUG] Traceback:\n{traceback.format_exc()}")
        return None


def parse_fix_response(response_text: str) -> Optional[Dict]:
    """Parse the JSON response from fix generation.

    Args:
        response_text: The raw response text from Claude.

    Returns:
        A dict with original_lines and fixed_lines, or None if parsing fails.
    """
    if not response_text:
        return None

    text = response_text.strip()

    # Remove markdown code fences if present
    if text.startswith("```"):
        first_newline = text.find("\n")
        if first_newline != -1:
            text = text[first_newline + 1:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

    # Find JSON object
    if not text.startswith("{"):
        start_idx = text.find("{")
        if start_idx != -1:
            text = text[start_idx:]

    if not text.endswith("}"):
        end_idx = text.rfind("}")
        if end_idx != -1:
            text = text[:end_idx + 1]

    try:
        fix = json.loads(text)
        if isinstance(fix, dict) and "original_lines" in fix and "fixed_lines" in fix:
            return fix
        return None
    except json.JSONDecodeError:
        return None


def evaluate_and_fix_remaining(
    finding: Dict,
    current_file_content: str,
    api_key: str,
    verbose: bool = False,
    show_thinking: bool = True,
) -> Optional[Dict]:
    """Evaluate if more changes are needed and return the next fix if so.

    This combines the "check if more needed" and "generate fix" steps into a single
    model call for efficiency.

    Args:
        finding: The vulnerability finding dict with file, description, etc.
        current_file_content: The current content of the file after applying fixes.
        api_key: Anthropic API key.
        verbose: If True, print debug information.
        show_thinking: If True, display Claude's thinking process in the CLI.

    Returns:
        A dict with "original_lines" and "fixed_lines" if more changes are needed,
        or None if the vulnerability is fully fixed. May include a "note" key with
        the reason when no more changes are needed.
    """
    file_path = finding.get("file", "")

    vulnerability_info = f"""Vulnerability that was just partially fixed:
- ID: {finding.get('id', 'unknown')}
- Title: {finding.get('title', 'Unknown vulnerability')}
- Class: {finding.get('class', 'unknown')}
- File: {file_path}
- Line range: {finding.get('line_range', 'unknown')}
- Description: {finding.get('description', 'No description')}
- Source: {finding.get('source', 'unknown')}
- Sink: {finding.get('sink', 'unknown')}

Current file content after the fix:
```
{current_file_content}
```

Does this file still need MORE changes to fully fix THIS SPECIFIC vulnerability? If yes, provide the next fix. If no, indicate the fix is complete. Remember: only consider this exact vulnerability, not other issues."""

    client = anthropic.Anthropic(api_key=api_key)

    try:
        thinking_text = ""
        result_text = ""
        display = ThinkingDisplay("Evaluating...", "35") if show_thinking else None

        # Use streaming to show thinking in real-time
        with client.messages.stream(
            model="claude-sonnet-4-5-20250929",
            max_tokens=16000,
            thinking={
                "type": "enabled",
                "budget_tokens": 5000,
            },
            messages=[
                {"role": "user", "content": f"{EVALUATE_AND_FIX_PROMPT}\n\n{vulnerability_info}"},
            ],
        ) as stream:
            for event in stream:
                if hasattr(event, "type"):
                    if event.type == "content_block_start":
                        if hasattr(event, "content_block") and event.content_block.type == "thinking":
                            if display:
                                display.start()
                    elif event.type == "content_block_delta":
                        if hasattr(event, "delta"):
                            if event.delta.type == "thinking_delta":
                                thinking_text += event.delta.thinking
                                if display:
                                    display.update(thinking_text)
                            elif event.delta.type == "text_delta":
                                result_text += event.delta.text

        if display:
            display.finish()

        if verbose and result_text:
            click.echo(f"\n      [DEBUG] Evaluate and fix response:\n{result_text}")

        # Parse the response
        text = result_text.strip()

        # Remove markdown code fences if present
        if text.startswith("```"):
            first_newline = text.find("\n")
            if first_newline != -1:
                text = text[first_newline + 1:]
            if text.endswith("```"):
                text = text[:-3]
            text = text.strip()

        # Find JSON object
        if not text.startswith("{"):
            start_idx = text.find("{")
            if start_idx != -1:
                text = text[start_idx:]

        if not text.endswith("}"):
            end_idx = text.rfind("}")
            if end_idx != -1:
                text = text[: end_idx + 1]

        result = json.loads(text)
        needs_more = result.get("needs_more_changes", False)
        reason = result.get("reason", "")

        if verbose:
            click.echo(f"      [DEBUG] More changes needed: {needs_more} - {reason}")

        if not needs_more:
            # Return note explaining why no more changes are needed
            if reason:
                click.echo(f"Note: {reason}")
            return None

        # Return the fix if more changes are needed
        original_lines = result.get("original_lines", "")
        fixed_lines = result.get("fixed_lines", "")

        if not original_lines:
            # Model said more changes needed but didn't provide a fix
            if verbose:
                click.echo("      [DEBUG] Model indicated more changes needed but didn't provide fix")
            return None

        return {
            "original_lines": original_lines,
            "fixed_lines": fixed_lines,
        }

    except Exception as e:
        if verbose:
            click.echo(f"      [DEBUG] Evaluate and fix failed: {e}")
        # Default to no more changes needed if we can't determine
        return None
