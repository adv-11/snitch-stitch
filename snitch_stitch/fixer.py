"""Fix generation module using OpenAI."""

import json
from typing import Dict, Optional

import click
from openai import OpenAI

from .ingest import extract_file_content

FIX_GENERATION_PROMPT = """You are a code security fixer. You are given a specific security vulnerability and the full content of the file where it exists.

Your job: produce a MINIMAL fix. Change only what is necessary to fix the vulnerability. Do not refactor. Do not rewrite the file. Do not add comments explaining the fix.

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
    finding: Dict, repo_content: str, api_key: str, verbose: bool = False
) -> Optional[Dict]:
    """Generate a fix for a vulnerability.

    Args:
        finding: The vulnerability finding dict with file, description, etc.
        repo_content: The full repository content from gitingest.
        api_key: OpenAI API key.
        verbose: If True, print debug information.

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

    # Extract the file content from the repo
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

    client = OpenAI(api_key=api_key)

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": FIX_GENERATION_PROMPT},
                {"role": "user", "content": vulnerability_info},
            ],
            temperature=0.1,
        )

        result_text = response.choices[0].message.content

        if verbose:
            click.echo(f"\n      [DEBUG] Fix generation raw response:\n{result_text}")

        # Parse the JSON response
        fix = parse_fix_response(result_text)

        return fix

    except Exception as e:
        click.echo(f"      Warning: Fix generation failed: {e}")
        if verbose:
            import traceback
            click.echo(f"      [DEBUG] Traceback:\n{traceback.format_exc()}")
        return None


def parse_fix_response(response_text: str) -> Optional[Dict]:
    """Parse the JSON response from fix generation.

    Args:
        response_text: The raw response text from OpenAI.

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
    except json.JSONDecodeError as e:
        click.echo(f"      Warning: Could not parse fix response: {e}")
        return None
