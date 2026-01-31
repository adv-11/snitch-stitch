# snitch-stitch

A Python CLI security auditor for Git repositories. Scans both backend source code and running frontend UIs to find real security vulnerabilities, scores them by severity, and generates LLM-powered code fixes.

## Features

- **Static Code Analysis**: Scans backend source code using OpenAI GPT-4o to identify SQL injection, command injection, hardcoded secrets, and more
- **Dynamic Browser Testing**: Uses rtrvr.ai to probe running frontends for XSS, auth bypass, IDOR, and input validation issues
- **AI-Powered Fixes**: Generates minimal, targeted code patches using LLM analysis
- **Interactive Workflow**: Review findings, select vulnerabilities, and approve/reject fixes with colored diffs
- **Risk Scoring**: Ranks vulnerabilities by exposure, exploitability, and impact (0-10 scale)

## Prerequisites

- Python 3.9 or higher
- OpenAI API key (required)
- rtrvr.ai API key (optional, for frontend scanning)

## Installation

```bash
pip install snitch-stitch
```

Or install from source:

```bash
git clone https://github.com/adv-11/snitch-stitch.git
cd snitch-stitch
pip install -e .
```

## Configuration

Set the required environment variable:

```bash
export OPENAI_API_KEY="your-openai-api-key"
```

Optionally, for frontend scanning:

```bash
export RTRVR_API_KEY="your-rtrvr-api-key"
```

## Usage

Basic scan (backend only):

```bash
snitch-stitch /path/to/your/repo
```

Scan with frontend testing:

```bash
snitch-stitch /path/to/your/repo --frontend-url http://localhost:3000
```

Preview fixes without applying them:

```bash
snitch-stitch /path/to/your/repo --dry-run
```

Auto-fix all vulnerabilities:

```bash
snitch-stitch /path/to/your/repo --fix-all
```

Verbose output for debugging:

```bash
snitch-stitch /path/to/your/repo --verbose
```

## How It Works

### Stage 1: Ingest
Converts your repository into a text blob using gitingest, making it ready for LLM analysis.

### Stage 2: Backend Scan
Sends the ingested code to OpenAI GPT-4o with a security analysis prompt. Identifies:
- SQL injection
- Command injection
- Hardcoded secrets
- Path traversal
- Deserialization vulnerabilities
- Missing authentication checks
- And more

### Stage 3: Frontend Scan (Optional)
Uses rtrvr.ai to control a real browser and probe your running frontend for:
- XSS vulnerabilities
- Authentication bypass
- IDOR (Insecure Direct Object References)
- Missing input validation
- Admin access issues

### Stage 4: Rank
Scores each vulnerability (0-10) based on:
- **Exposure**: Is it public-facing or local-only?
- **Exploitability**: How easy is it to trigger?
- **Impact**: What's the severity class?

Severity labels: Critical (9-10), High (7-8), Medium (4-6), Low (1-3)

### Stage 5: Fix
- Shows you a ranked table of vulnerabilities
- You select which ones to fix
- For each, generates a minimal code patch
- Shows you a colored diff
- Applies the fix if you approve

## Architecture

```
snitch_stitch/
├── __init__.py          # Package marker
├── cli.py               # Click-based CLI orchestrator
├── ingest.py            # Repository → text conversion
├── backend_scanner.py   # OpenAI static analysis
├── frontend_scanner.py  # rtrvr.ai dynamic testing
├── ranker.py            # Vulnerability scoring
├── fixer.py             # AI patch generation
└── diff_display.py      # Interactive diff UI
```

## Development

This project uses PDD (Prompt-Driven Development) for code generation.

1. Clone the repository
2. Install dependencies: `pip install -e .`
3. Generate code from prompts: `pdd sync <module_name>`

## License

MIT

## Contributing

Contributions welcome! Please open an issue or PR.

## Security Notice

This tool modifies your code. Always:
- Review diffs carefully before accepting
- Use `--dry-run` first
- Keep backups or use version control
- Test fixes in a safe environment

The tool is designed to help you find and fix vulnerabilities, but LLM-generated fixes should be validated before deployment.
