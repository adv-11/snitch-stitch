"""Backend code security scanner using Claude Sonnet 4.5 with extended thinking."""

import json
from typing import Dict, List

import anthropic
import click

from .fixer import ThinkingDisplay

SECURITY_ANALYSIS_PROMPT = """You are a security auditor. You are given the full source code of a software repository.

Your job: identify REAL security vulnerabilities in this code. Do not hallucinate. Only report issues that are clearly present in the code you are reading.

For each vulnerability you find, return a JSON object with these exact keys:
- "id": a short unique slug (e.g. "sqli-user-login")
- "title": one-line description
- "class": one of: command_injection, sqli, path_traversal, ssrf, deserialization, xss, secrets_exposure, authz, input_validation, idor
- "file": the file path where the issue is
- "line_range": [start_line, end_line] (approximate is fine)
- "description": 2-3 sentences explaining exactly what is wrong and how it could be exploited
- "source": where the untrusted input enters (e.g. "HTTP query parameter 'id'", "environment variable", "user upload")
- "sink": the dangerous function or operation (e.g. "os.system()", "cursor.execute() with string concatenation", "pickle.loads()")

Return ONLY a JSON array of these objects. No markdown, no explanation outside the JSON. If you find nothing, return an empty array: []

Rules:
- Do NOT report something as vulnerable if the code already uses parameterized queries, safe loaders, input validation, or similar mitigations.
- DO report hardcoded secrets, API keys, or tokens that appear as literal strings in the code.
- DO report SQL queries built with string concatenation or f-strings.
- DO report uses of eval(), exec(), pickle.loads(), yaml.load() without Loader=SafeLoader, subprocess with shell=True and unsanitized input, os.system() with unsanitized input.
- DO report missing authentication checks on endpoints that modify or expose user data.
- Be specific. Point to the exact file and approximate line."""


def scan_backend(
    repo_content: str, api_key: str, verbose: bool = False, show_thinking: bool = True
) -> List[Dict]:
    """Scan repository code for security vulnerabilities using Claude Sonnet 4.5.

    Args:
        repo_content: The full text content of the repository from gitingest.
        api_key: Anthropic API key.
        verbose: If True, print debug information.
        show_thinking: If True, display Claude's thinking process in the CLI.

    Returns:
        A list of vulnerability findings, each as a dict with keys:
        id, title, class, file, line_range, description, source, sink
    """
    if not repo_content or len(repo_content) < 10:
        return []

    client = anthropic.Anthropic(api_key=api_key)

    try:
        thinking_text = ""
        result_text = ""
        display = ThinkingDisplay("Scanning...", "33") if show_thinking else None  # Yellow color

        # Use streaming to show thinking in real-time
        with client.messages.stream(
            model="claude-sonnet-4-5-20250929",
            max_tokens=16000,
            thinking={
                "type": "enabled",
                "budget_tokens": 5000,
            },
            messages=[
                {"role": "user", "content": f"{SECURITY_ANALYSIS_PROMPT}\n\n{repo_content}"},
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

        if verbose:
            click.echo(f"\n      [DEBUG] Backend scanner raw response:\n{result_text[:1000]}...")

        # Parse the JSON response
        findings = parse_findings(result_text)

        # Add source marker to each finding
        for finding in findings:
            finding["_source"] = "backend"

        return findings

    except Exception as e:
        if verbose:
            import traceback
            click.echo(f"      Warning: Backend scan failed: {e}")
            click.echo(f"      [DEBUG] Traceback:\n{traceback.format_exc()}")
        return []


def parse_findings(response_text: str) -> List[Dict]:
    """Parse the JSON response from the LLM.

    Args:
        response_text: The raw response text from Claude.

    Returns:
        A list of vulnerability findings, or empty list if parsing fails.
    """
    if not response_text:
        return []

    # Clean up the response text
    text = response_text.strip()

    # Remove markdown code fences if present
    if text.startswith("```"):
        # Find the end of the opening fence
        first_newline = text.find("\n")
        if first_newline != -1:
            text = text[first_newline + 1:]
        # Remove closing fence
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

    # Try to find JSON array in the text
    if not text.startswith("["):
        # Try to find the start of a JSON array
        start_idx = text.find("[")
        if start_idx != -1:
            text = text[start_idx:]

    if not text.endswith("]"):
        # Try to find the end of a JSON array
        end_idx = text.rfind("]")
        if end_idx != -1:
            text = text[:end_idx + 1]

    try:
        findings = json.loads(text)
        if isinstance(findings, list):
            return findings
        return []
    except json.JSONDecodeError:
        return []
