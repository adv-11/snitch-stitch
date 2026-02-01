# snitch-stitch — Prompt for promptdriven.ai

## What we are building
A Python CLI package called snitch-stitch, published to PyPI. It is a security auditor for any Git repository. The user runs it once against a local repo path. The tool scans both the backend source code and the frontend running UI, finds real security vulnerabilities, scores them, and lets the user accept or reject LLM-generated code fixes that get written directly to disk.

## Package name and entry point
- **PyPI package name:** snitch-stitch
- **CLI command:** `snitch-stitch <repo-path> [options]`
- Single entry point. All flags are optional.

## Required environment variables (set by the user before running)

| Variable | Purpose |
|----------|---------|
| `OPENAI_API_KEY` | Used for all LLM calls (analysis, fix generation). The tool must exit with a clear error if this is missing. |
| `RTRVR_API_KEY` | Used for frontend browser scanning via rtrvr.ai. Optional — if missing, the tool skips frontend scanning and prints a notice. |

## Package structure
```
snitch_stitch/
├── __init__.py
├── cli.py              # Click-based entry point, argument parsing, orchestration of the 5 stages
├── ingest.py           # Calls gitingest to turn the local repo into a text blob
├── backend_scanner.py  # Sends the ingested code + a security analysis prompt to OpenAI
├── frontend_scanner.py # Calls rtrvr.ai /mcp endpoint to probe a running frontend for XSS, auth bypass, IDOR, etc.
├── ranker.py           # Takes raw findings from both scanners, assigns threat scores, sorts and deduplicates
├── fixer.py            # Sends each selected vulnerability + its surrounding code context to OpenAI to generate a patch
└── diff_display.py     # Renders unified diffs in the terminal with color (red for removals, green for additions). Prompts the user to accept or reject each diff. If accepted, writes the file to disk.
```

## Stage 1 — Ingest (ingest.py)
**What it does:** Converts the user's local repo into a single prompt-friendly text string.

**How:** Use the gitingest Python package as a library. It is a dependency of snitch-stitch.

```python
from gitingest import ingest

summary, tree, content = ingest("/path/to/local/repo")
# `content` is the full text blob of the repo, ready to be pasted into an LLM prompt.
# `tree` is the directory tree string.
# `summary` contains file count and size stats.
```

- This works on local directories directly. No GitHub URL needed.
- Store the returned content string. It gets passed to the backend scanner and the fixer later.
- If the repo is too large and gitingest truncates, print a warning but continue.

## Stage 2 — Backend scan (backend_scanner.py)
**What it does:** Sends the full repo text to OpenAI with a detailed security-analysis prompt. Gets back a structured list of findings.

**How it works:**
1. Construct a prompt (see below for the exact prompt text).
2. Call the OpenAI API (gpt-4o model). Pass the ingested repo content as the user message. The security prompt is the system message.
3. Parse the response. The LLM is instructed to return only a JSON array. Parse it. If parsing fails, print a warning and return an empty list.

**The system prompt to send to OpenAI for backend scanning:**

```
You are a security auditor. You are given the full source code of a software repository.

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
- Be specific. Point to the exact file and approximate line.
```

## Stage 3 — Frontend scan (frontend_scanner.py) — OPTIONAL
**What it does:** Uses rtrvr.ai to control a real browser session and probe a running frontend for security issues like XSS, broken authentication, IDOR, and missing access controls.

**When it runs:** Only if two conditions are met:
1. `RTRVR_API_KEY` environment variable is set.
2. The user passes a `--frontend-url` flag with a localhost URL (e.g., `http://localhost:3000`).

If either is missing, print a notice and skip this stage entirely.

**How it works:**

Make a POST request to the rtrvr.ai MCP endpoint.

The endpoint URL is:
```
https://mcp.rtrvr.ai
```

The request format:
```python
import requests

headers = {
    "Authorization": f"Bearer {RTRVR_API_KEY}",
    "Content-Type": "application/json"
}

payload = {
    "tool": "planner",
    "params": {
        "user_input": "<THE SECURITY TESTING TASK DESCRIPTION — see below>",
        "tab_urls": [frontend_url]  # e.g. ["http://localhost:3000"]
    }
}

response = requests.post("https://mcp.rtrvr.ai", headers=headers, json=payload)
result = response.json()
```

**The `user_input` field is a natural-language task description telling rtrvr.ai what to do in the browser. Use this task description:**

```
You are a security tester. You have a running web application at the URL provided. Your job is to probe it for common frontend security vulnerabilities by interacting with the application like a real user would, but testing for security edge cases.

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

Return ONLY the JSON array. No other text.
```

Parse the response from rtrvr.ai. The result text should contain a JSON array. Extract and parse it. If it fails to parse, return an empty list and print a warning.

## Stage 4 — Rank (ranker.py)
**What it does:** Takes the combined findings from the backend scanner and the frontend scanner, deduplicates them, scores each one, and returns a sorted list.

**Scoring formula (0–10):**

Each finding gets three sub-scores:

| Dimension | How to assign it | Values |
|-----------|------------------|--------|
| Exposure | `public_facing` if the sink is an HTTP endpoint or UI interaction. `local_only` if it is a script, config file, or CLI arg that requires local access. | public_facing = 5, local_only = 1 |
| Exploitability | `easy` if no authentication is required to trigger it AND the input is directly controllable. `moderate` if some setup is needed (e.g., must be logged in). `hard` if it requires chaining multiple steps or special access. | easy = 3, moderate = 2, hard = 1 |
| Impact | Based on the vulnerability class: `critical` for command_injection, deserialization, secrets_exposure. `high` for sqli, ssrf, authz, idor. `medium` for xss, path_traversal. `low` for input_validation. | critical = 4, high = 3, medium = 2, low = 1 |

**Final score** = min(10, exposure + exploitability + impact)

**Severity label:**
- 9–10 → Critical
- 7–8 → High
- 4–6 → Medium
- 1–3 → Low

**Output:** A list of findings sorted by score descending. Each item carries its original data plus score, severity, and the three sub-scores.

## Stage 5a — User selection
After ranking, print a numbered summary table to the terminal:

```
╔════╦══════════╦══════════════════════════════════════════╦════════╗
║  # ║ Severity ║ Title                                    ║ Score  ║
╠════╬══════════╬══════════════════════════════════════════╬════════╣
║  1 ║ Critical ║ SQL injection in /api/login              ║  10    ║
║  2 ║ High     ║ Hardcoded API key in config.py           ║   8    ║
║  3 ║ Medium   ║ XSS in search input                      ║   5    ║
╚════╩══════════╩══════════════════════════════════════════╩════════╝

Select vulnerabilities to fix (comma-separated numbers, or 'all'):
```

The user types numbers or `all`. The tool proceeds to fix only those.

## Stage 5b — Fix generation (fixer.py)
**What it does:** For each selected vulnerability, calls OpenAI to generate a minimal code patch.

**How:**

For each selected finding:
1. Extract the relevant file content from the ingested repo text. (Parse the gitingest output to find the section for the file referenced in `finding["file"]`.)
2. Send the file content + the finding details to OpenAI with this system prompt:

```
You are a code security fixer. You are given a specific security vulnerability and the full content of the file where it exists.

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

Return ONLY the JSON object. No markdown. No explanation.
```

3. Parse the response JSON. Extract `original_lines` and `fixed_lines`.

## Stage 5c — Diff display and apply (diff_display.py)
**What it does:** Shows the user a colored diff for each fix. If the user accepts, writes the change to disk.

**How:**

For each fix:
1. Read the actual file from disk at `<repo_path>/<finding["file"]>`.
2. Replace the `original_lines` substring with `fixed_lines` to produce the new file content.
3. Generate a unified diff between the old and new content using Python's `difflib.unified_diff`.
4. Print the diff to the terminal with color:
   - Lines starting with `-` (removals) → red (use ANSI code `\033[91m`)
   - Lines starting with `+` (additions) → green (use ANSI code `\033[92m`)
   - All other lines → default color
   - Reset color after each line with `\033[0m`
5. Print the finding title and severity above the diff as a header.
6. Prompt the user:
   ```
   Apply this fix? [y/n]:
   ```
   - If `y`: write the new file content to disk at the original path. Print a confirmation.
   - If `n`: skip this fix. Print "Skipped."
7. If the `original_lines` string is NOT found in the actual file (exact match fails), print an error: `"Could not locate the code block in <file>. Skipping this fix."` and move on.

## CLI flags

| Flag | Description | Default |
|------|-------------|---------|
| `<repo-path>` | (positional, required) Path to the local repository directory | — |
| `--frontend-url` | URL of a running frontend (e.g. `http://localhost:3000`). Enables frontend scanning. | None (frontend scan skipped) |
| `--fix-all` | Skip the selection prompt and attempt to fix everything | False |
| `--dry-run` | Show diffs but never write anything to disk. Ignore user accept/reject prompts. | False |
| `--verbose` | Print debug info (raw API responses, parsed JSON, etc.) | False |

## Dependencies (put in pyproject.toml)
- click
- openai
- requests
- gitingest

## pyproject.toml structure
Use a standard `pyproject.toml` with:
- `[build-system]` using setuptools
- `[project]` with name `snitch-stitch`, a version, description, `requires-python = ">=3.9"`, and the dependencies above
- `[project.scripts]` entry: `snitch-stitch = "snitch_stitch.cli:main"`

## Error handling rules
1. If `OPENAI_API_KEY` is not set: print `"Error: OPENAI_API_KEY environment variable is not set. Please set it and try again."` and exit with code 1.
2. If `RTRVR_API_KEY` is not set and `--frontend-url` is passed: print a notice saying frontend scanning is skipped, but continue with backend scanning.
3. If the OpenAI API call fails or returns unparseable JSON: print a warning with the raw response text (if `--verbose`) and continue with an empty findings list for that stage.
4. If the rtrvr.ai API call fails: same as above — warn and skip.
5. If gitingest fails on the repo path: print the error and exit with code 1.
6. If a file referenced in a finding does not exist on disk when applying a fix: print a warning and skip that fix.

## Flow summary (what the user sees when they run the command)

```
$ snitch-stitch ./my-project --frontend-url http://localhost:3000

[1/5] Ingesting repository...
      ✓ Ingested 47 files (82 KB)

[2/5] Scanning backend code...
      ✓ Found 4 backend vulnerabilities

[3/5] Scanning frontend...
      ✓ Found 2 frontend vulnerabilities

[4/5] Ranking findings...
      ✓ Ranked 6 findings

[5/5] Review and fix

╔════╦══════════╦══════════════════════════════════════════════╦═══════╗
║  # ║ Severity ║ Title                                        ║ Score ║
╠════╬══════════╬══════════════════════════════════════════════╬═══════╣
║  1 ║ Critical ║ SQL injection in /api/login                  ║  10   ║
║  2 ║ Critical ║ Hardcoded AWS key in settings.py             ║   9   ║
║  3 ║ High     ║ Command injection in file converter          ║   8   ║
║  4 ║ High     ║ Missing auth on /api/admin/users             ║   7   ║
║  5 ║ Medium   ║ XSS in search input                          ║   5   ║
║  6 ║ Low      ║ No input validation on age field             ║   3   ║
╚════╩══════════╩══════════════════════════════════════════════╩═══════╝

Select vulnerabilities to fix (comma-separated numbers, or 'all'):
> 1, 2, 3

--- Generating fix for: SQL injection in /api/login ---

 app/auth.py
─────────────────────────────────────────────
  def login(username, password):
-     query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
-     cursor.execute(query)
+     query = "SELECT * FROM users WHERE username = %s AND password = %s"
+     cursor.execute(query, (username, password))
      user = cursor.fetchone()
─────────────────────────────────────────────
Apply this fix? [y/n]: y
✓ Fixed: app/auth.py

--- Generating fix for: Hardcoded AWS key in settings.py ---
...
```

## Important implementation notes
1. **Do not add pytest or any test framework as a dependency.** This is a CLI tool, not a library that needs a test suite in the package.
2. **gitingest output parsing:** The `content` string returned by gitingest contains all file contents concatenated together with delimiters like `--- File: path/to/file.py ---`. When you need to extract a single file's content for the fixer, split on these delimiters.
3. **The fix application is a simple string replacement.** Read the file, find the `original_lines` substring, replace it with `fixed_lines`, write the file back. Use exact string matching — do not use fuzzy matching or line-number-based replacement.
4. **Color output:** Use ANSI escape codes directly. Do not add a dependency like colorama unless the user is on Windows and it is truly needed. For simplicity, just use ANSI codes.
5. **The tool modifies real files.** The `--dry-run` flag exists specifically so users can preview without risk. Make this obvious in the help text.
6. **Keep it simple.** This is a single-command CLI. No subcommands. No config files. No interactive setup wizard. Just run it, see the results, accept or reject fixes.
