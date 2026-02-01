"""Frontend security scanner using rtrvr.ai browser automation."""

import json
from typing import Dict, List

import click
import requests

FRONTEND_SECURITY_TASK = """You are a security tester. You have a running web application at the URL provided. Your job is to probe it for common frontend security vulnerabilities by interacting with the application like a real user would, but testing for security edge cases.

Perform the following checks. For each one, navigate to the relevant page, attempt the action, and observe the result:

1. XSS (Cross-Site Scripting): Find any text input fields (search boxes, comment fields, profile name fields, any free-text input). Submit the string <script>alert('xss')</script> into each one. Check if the script executes (alert box appears) or if the raw HTML tags appear unescaped in the page. Report whether XSS is possible.

2. Authentication bypass: Check if there are pages that should require login (dashboard, profile, admin, settings, etc.). Try accessing them directly by URL without being logged in. Report whether you can access protected content without authenticating.

3. Admin access: Look for any admin panel, admin route, or admin-related URL (try /admin, /admin/login, /dashboard/admin, /api/admin). Try accessing it. If there is a login, try default credentials like admin/admin, admin/password. Report what you find.

4. IDOR (Insecure Direct Object Reference): If you can log in as a user, look at the URLs used to access user-specific resources (profile, orders, settings). Change the user ID or resource ID in the URL to a different number (e.g., change /user/1 to /user/2, or /orders/101 to /orders/102). Check if you can see another user's data. Report whether this works.

5. Missing input validation: Find any numeric fields, email fields, or fields with expected formats. Submit obviously invalid data (e.g., 99999999999 in an age field, "notanemail" in an email field, a 10000-character string in a name field). Check if the application crashes, returns a raw server error (500), or leaks internal details. Report what happens.

6. Database leakage: Being able to access unauthorized part of database by querying it and getting results and check for SQL Injections

After completing all checks, summarize your findings. For each issue found, describe: what you did, what you observed, and why it is a security problem. Return your findings as a JSON array with these keys per item:
- "id": short slug
- "title": one-line description  
- "class": one of xss, authz, idor, input_validation, secrets_exposure
- "description": what you did and what happened
- "url": the URL where the issue was found
- "steps": list of steps you took to reproduce it

Return ONLY the JSON array. No other text."""

RTRVR_ENDPOINT = "https://mcp.rtrvr.ai"


def scan_frontend(frontend_url: str, api_key: str, verbose: bool = False) -> List[Dict]:
    """Scan a running frontend for security vulnerabilities using rtrvr.ai.

    Args:
        frontend_url: URL of the running frontend (e.g., http://localhost:3000).
        api_key: rtrvr.ai API key.
        verbose: If True, print debug information.

    Returns:
        A list of vulnerability findings from the frontend scan.
    """
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "tool": "planner",
        "params": {
            "user_input": FRONTEND_SECURITY_TASK,
            "tab_urls": [frontend_url],
        },
    }

    try:
        if verbose:
            click.echo(f"\n      [DEBUG] Calling rtrvr.ai with URL: {frontend_url}")

        response = requests.post(
            RTRVR_ENDPOINT,
            headers=headers,
            json=payload,
            timeout=300,  # 5 minute timeout for browser automation
        )

        if verbose:
            click.echo(f"      [DEBUG] rtrvr.ai response status: {response.status_code}")

        if response.status_code != 200:
            click.echo(f"      Warning: rtrvr.ai returned status {response.status_code}")
            if verbose:
                click.echo(f"      [DEBUG] Response: {response.text[:500]}")
            return []

        result = response.json()

        if verbose:
            click.echo(f"      [DEBUG] rtrvr.ai response:\n{json.dumps(result, indent=2)[:1000]}...")

        # Extract findings from the response
        findings = parse_rtrvr_response(result, verbose=verbose)

        # Add source marker and URL to each finding
        for finding in findings:
            finding["_source"] = "frontend"
            if "url" not in finding:
                finding["url"] = frontend_url

        return findings

    except requests.exceptions.Timeout:
        click.echo("      Warning: rtrvr.ai request timed out.")
        return []
    except requests.exceptions.RequestException as e:
        click.echo(f"      Warning: Frontend scan failed: {e}")
        if verbose:
            import traceback
            click.echo(f"      [DEBUG] Traceback:\n{traceback.format_exc()}")
        return []
    except Exception as e:
        click.echo(f"      Warning: Frontend scan error: {e}")
        if verbose:
            import traceback
            click.echo(f"      [DEBUG] Traceback:\n{traceback.format_exc()}")
        return []


def parse_rtrvr_response(response: Dict, verbose: bool = False) -> List[Dict]:
    """Parse the response from rtrvr.ai to extract findings.

    Args:
        response: The JSON response from rtrvr.ai.
        verbose: If True, print debug information.

    Returns:
        A list of vulnerability findings.
    """
    # rtrvr.ai response structure may vary
    # Try to find the result text containing JSON
    result_text = None

    if isinstance(response, dict):
        # Try common response keys
        for key in ["result", "output", "text", "content", "response", "data"]:
            if key in response:
                result_text = response[key]
                break

        # If result_text is still a dict, try to go deeper
        if isinstance(result_text, dict):
            for key in ["text", "content", "output", "result"]:
                if key in result_text:
                    result_text = result_text[key]
                    break

    if result_text is None:
        # Maybe the response itself is the result
        result_text = json.dumps(response) if isinstance(response, dict) else str(response)

    if isinstance(result_text, list):
        # Already a list, might be the findings directly
        return result_text

    if not isinstance(result_text, str):
        result_text = str(result_text)

    # Try to extract JSON array from the text
    text = result_text.strip()

    # Remove markdown code fences if present
    if "```" in text:
        # Find JSON content between code fences
        parts = text.split("```")
        for part in parts:
            part = part.strip()
            if part.startswith("json"):
                part = part[4:].strip()
            if part.startswith("["):
                text = part
                break

    # Find the JSON array
    if "[" in text:
        start_idx = text.find("[")
        end_idx = text.rfind("]")
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            text = text[start_idx:end_idx + 1]

    try:
        findings = json.loads(text)
        if isinstance(findings, list):
            return findings
        return []
    except json.JSONDecodeError as e:
        if verbose:
            click.echo(f"      [DEBUG] Could not parse frontend scan results: {e}")
            click.echo(f"      [DEBUG] Text was: {text[:500]}...")
        return []
