"""Fix generation module using litellm (supports OpenAI, Anthropic, etc.)."""

import json
import sys
from typing import Dict, List, Optional

import click
import litellm

from .ingest import extract_file_content

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


def _set_api_key(model: str, api_key: str) -> None:
    """Set the appropriate API key env var for the given model."""
    import os
    model_lower = model.lower()
    if model_lower.startswith("claude") or "anthropic" in model_lower:
        os.environ.setdefault("ANTHROPIC_API_KEY", api_key)
    elif model_lower.startswith("gemini") or "google" in model_lower:
        os.environ.setdefault("GEMINI_API_KEY", api_key)
    elif model_lower.startswith("azure"):
        os.environ.setdefault("AZURE_API_KEY", api_key)
    else:
        os.environ.setdefault("OPENAI_API_KEY", api_key)


def generate_fix(
    finding: Dict,
    repo_content: str,
    api_key: str,
    model: str = "gpt-4o",
    verbose: bool = False,
    file_content_override: Optional[str] = None,
) -> Optional[Dict]:
    """Generate a fix for a vulnerability using litellm.

    Args:
        finding: The vulnerability finding dict with file, description, etc.
        repo_content: The full repository content from gitingest.
        api_key: API key for the LLM provider.
        model: litellm model string. Defaults to "gpt-4o".
        verbose: If True, print debug information.
        file_content_override: If provided, use this as the file content instead of
            extracting from repo_content.

    Returns:
        A dict with "original_lines" and "fixed_lines" keys, or None if
        fix generation failed. May also include a "note" key for frontend-only issues.
    """
    file_path = finding.get("file", "")

    if not file_path:
        if finding.get("_source") == "frontend":
            return {
                "original_lines": "",
                "fixed_lines": "",
                "note": "This is a frontend-only vulnerability. The fix must be applied in the client-side code or server rendering logic.",
            }
        return None

    if file_content_override is not None:
        file_content = file_content_override
    else:
        file_content = extract_file_content(repo_content, file_path)

    if not file_content:
        if verbose:
            click.echo(f"      [DEBUG] Could not extract content for file: {file_path}")
        return None

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

    _set_api_key(model, api_key)

    try:
        click.echo("      Generating fix...", nl=False)

        response = litellm.completion(
            model=model,
            messages=[
                {
                    "role": "user",
                    "content": f"{FIX_GENERATION_PROMPT}\n\n{vulnerability_info}",
                }
            ],
            max_tokens=4000,
        )

        result_text = response.choices[0].message.content or ""
        click.echo(" done.")

        if verbose:
            click.echo(f"\n      [DEBUG] Fix generation raw response:\n{result_text}")

        return parse_fix_response(result_text)

    except Exception as e:
        if verbose:
            import traceback
            click.echo(f"\n      Warning: Fix generation failed: {e}")
            click.echo(f"      [DEBUG] Traceback:\n{traceback.format_exc()}")
        return None


def parse_fix_response(response_text: str) -> Optional[Dict]:
    """Parse the JSON response from fix generation."""
    if not response_text:
        return None

    text = response_text.strip()

    if text.startswith("```"):
        first_newline = text.find("\n")
        if first_newline != -1:
            text = text[first_newline + 1:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

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
    model: str = "gpt-4o",
    verbose: bool = False,
) -> Optional[Dict]:
    """Evaluate if more changes are needed and return the next fix if so.

    Args:
        finding: The vulnerability finding dict.
        current_file_content: The current content of the file after applying fixes.
        api_key: API key for the LLM provider.
        model: litellm model string. Defaults to "gpt-4o".
        verbose: If True, print debug information.

    Returns:
        A dict with "original_lines" and "fixed_lines" if more changes are needed,
        or None if the vulnerability is fully fixed.
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

    _set_api_key(model, api_key)

    try:
        click.echo("      Evaluating...", nl=False)

        response = litellm.completion(
            model=model,
            messages=[
                {
                    "role": "user",
                    "content": f"{EVALUATE_AND_FIX_PROMPT}\n\n{vulnerability_info}",
                }
            ],
            max_tokens=4000,
        )

        result_text = response.choices[0].message.content or ""
        click.echo(" done.")

        if verbose:
            click.echo(f"\n      [DEBUG] Evaluate and fix response:\n{result_text}")

        text = result_text.strip()

        if text.startswith("```"):
            first_newline = text.find("\n")
            if first_newline != -1:
                text = text[first_newline + 1:]
            if text.endswith("```"):
                text = text[:-3]
            text = text.strip()

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
            if reason:
                click.echo(f"Note: {reason}")
            return None

        original_lines = result.get("original_lines", "")
        fixed_lines = result.get("fixed_lines", "")

        if not original_lines:
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
        return None 