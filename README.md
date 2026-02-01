# 🕸️snitch-stitch

A security auditor CLI for Git repositories. Scans both backend source code and running frontend UIs to find real security vulnerabilities, scores them by severity, and lets you accept or reject LLM-generated code fixes.

---

[![PyPI version](https://img.shields.io/pypi/v/snitch-stitch.svg)](https://pypi.org/project/snitch-stitch)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Installation

```bash
pip install snitch-stitch
```

Or install from source:

```bash
git clone https://github.com/snitch-stitch/snitch-stitch.git
cd snitch-stitch
pip install -e .
```

## Requirements

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENAI_API_KEY` | Yes | Used for all LLM calls (code analysis, fix generation) |
| `RTRVR_API_KEY` | No | Used for frontend browser scanning via rtrvr.ai |

Set these before running:

```bash
export OPENAI_API_KEY="sk-..."
export RTRVR_API_KEY="..."  # Optional, for frontend scanning
```

## Usage

```bash
snitch-stitch <repo-path> [options]
```

### Arguments

- `<repo-path>` - Path to the local repository directory to scan (required)

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--frontend-url URL` | URL of a running frontend (e.g., `http://localhost:3000`). Enables frontend scanning. | None |
| `--fix-all` | Skip the selection prompt and attempt to fix everything | False |
| `--dry-run` | Show diffs but never write anything to disk | False |
| `--verbose` | Print debug info (raw API responses, parsed JSON) | False |

### Examples

Scan a repository for backend vulnerabilities:

```bash
snitch-stitch ./my-project
```

Scan both backend and frontend:

```bash
snitch-stitch ./my-project --frontend-url http://localhost:3000
```

Preview fixes without applying them:

```bash
snitch-stitch ./my-project --dry-run
```

Automatically fix all vulnerabilities:

```bash
snitch-stitch ./my-project --fix-all
```

## How It Works

snitch-stitch runs through 5 stages:

### Stage 1: Ingest
Converts the repository into a text format suitable for LLM analysis using [gitingest](https://github.com/cyclotruc/gitingest).

### Stage 2: Backend Scan
Sends the code to OpenAI GPT-4o with a security analysis prompt. Identifies vulnerabilities like:
- SQL injection
- Command injection
- Path traversal
- Hardcoded secrets
- Missing authentication
- Insecure deserialization
- XSS vulnerabilities

### Stage 3: Frontend Scan (Optional)
If `--frontend-url` is provided and `RTRVR_API_KEY` is set, uses rtrvr.ai to control a real browser and probe the running application for:
- XSS (Cross-Site Scripting)
- Authentication bypass
- IDOR (Insecure Direct Object Reference)
- Missing input validation
- Admin panel access

### Stage 4: Rank
Scores each vulnerability (0-10) based on:
- **Exposure**: Public-facing (5) vs local-only (1)
- **Exploitability**: Easy (3) / Moderate (2) / Hard (1)
- **Impact**: Critical (4) / High (3) / Medium (2) / Low (1)

Severity labels: Critical (9-10), High (7-8), Medium (4-6), Low (1-3)

### Stage 5: Fix
For each selected vulnerability:
1. Generates a minimal code fix using OpenAI
2. Shows a colored diff (red for removals, green for additions)
3. Prompts you to accept or reject
4. Writes accepted fixes to disk

## Example Output

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
> 1, 2

--- Generating fix for: SQL injection in /api/login ---

 app/auth.py
──────────────────────────────────────────────────
  def login(username, password):
-     query = f"SELECT * FROM users WHERE username = '{username}'"
-     cursor.execute(query)
+     query = "SELECT * FROM users WHERE username = %s"
+     cursor.execute(query, (username,))
      user = cursor.fetchone()
──────────────────────────────────────────────────
Apply this fix? [y/n]: y
✓ Fixed: app/auth.py
```

## Vulnerability Classes Detected

| Class | Description |
|-------|-------------|
| `sqli` | SQL injection via string concatenation |
| `command_injection` | Shell command injection via os.system, subprocess |
| `path_traversal` | Directory traversal allowing file access |
| `ssrf` | Server-side request forgery |
| `deserialization` | Insecure deserialization (pickle, yaml) |
| `xss` | Cross-site scripting |
| `secrets_exposure` | Hardcoded API keys, passwords, tokens |
| `authz` | Missing or broken authorization |
| `idor` | Insecure direct object references |
| `input_validation` | Missing input validation |

## License

MIT
