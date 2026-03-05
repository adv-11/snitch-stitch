"""Backend code security scanner using litellm (supports OpenAI, Anthropic, etc.)."""

import json
from typing import Dict, List

import click
import litellm

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
    repo_content: str, api_key: str, model: str = "gpt-4o", verbose: bool = False
) -> List[Dict]:
    """Scan repository code for security vulnerabilities using litellm.

    Args:
        repo_content: The full text content of the repository from gitingest.
        api_key: API key for the LLM provider.
        model: litellm model string (e.g. "gpt-4o", "claude-sonnet-4-5-20250929",
               "gemini/gemini-1.5-pro"). Defaults to "gpt-4o".
        verbose: If True, print debug information.

    Returns:
        A list of vulnerability findings, each as a dict with keys:
        id, title, class, file, line_range, description, source, sink
    """
    if not repo_content or len(repo_content) < 10:
        return []

    # Set the API key in litellm based on model prefix
    _set_api_key(model, api_key)

    try:
        result_text = ""

        click.echo("      Analyzing code...", nl=False)

        response = litellm.completion(
            model=model,
            messages=[
                {
                    "role": "user",
                    "content": f"{SECURITY_ANALYSIS_PROMPT}\n\n{repo_content}",
                }
            ],
            max_tokens=8000,
        )

        result_text = response.choices[0].message.content or ""
        click.echo(" done.")

        if verbose:
            click.echo(f"\n      [DEBUG] Backend scanner raw response:\n{result_text[:1000]}...")

        findings = parse_findings(result_text)

        for finding in findings:
            finding["_source"] = "backend"

        return findings

    except Exception as e:
        if verbose:
            import traceback
            click.echo(f"\n      Warning: Backend scan failed: {e}")
            click.echo(f"      [DEBUG] Traceback:\n{traceback.format_exc()}")
        else:
            click.echo(f"\n      Warning: Backend scan failed: {e}")
        return []


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
        # Default to OpenAI
        os.environ.setdefault("OPENAI_API_KEY", api_key)


def parse_findings(response_text: str) -> List[Dict]:
    """Parse the JSON response from the LLM."""
    if not response_text:
        return []

    text = response_text.strip()

    if text.startswith("```"):
        first_newline = text.find("\n")
        if first_newline != -1:
            text = text[first_newline + 1:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

    if not text.startswith("["):
        start_idx = text.find("[")
        if start_idx != -1:
            text = text[start_idx:]

    if not text.endswith("]"):
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