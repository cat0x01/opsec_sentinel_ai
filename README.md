# OPSEC Sentinel AI

OPSEC Sentinel AI is a Python CLI tool for OPSEC and anonymity auditing.

It checks how your system, browser, network, and behavior may look to an outside observer, then produces reports with risk scoring and technical remediation steps.

It does not perform live exploitation.

## What It Checks

- DNS leaks
- WebRTC leaks
- IPv6 exposure
- Open local ports
- SSH hardening issues
- Browser fingerprint consistency
- Timezone and header mismatches
- Behavioral timing anomalies
- Sandbox / VM indicators
- Simulated deanonymization attack paths

## Install

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

Install the project:

```bash
pip install -e .
```

Install optional features:

```bash
pip install -e .[browser,system,pdf,ai]
```

Install Chromium for browser-based checks:

```bash
python -m playwright install chromium
```

## First Run

Run a standard scan and save reports in `./reports`:

```bash
opsec-sentinel --out-dir ./reports
```

This writes:

- `scan_results.json`
- `report.md`
- `report.html`

## AI Setup

If you want AI-generated analysis, create a local `.env` file:

```env
ANTHROPIC_API_KEY=your-key-here
```

Then run the tool normally:

```bash
opsec-sentinel --out-dir ./reports
```

Do not commit `.env` to Git.

## Modes

`normal`

- Best default mode
- General privacy and OPSEC auditing

`bugbounty`

- Better for mixed manual and automated workflows
- Enables live monitoring behavior more aggressively

`darknet`

- Strictest mode
- Treats leaks and fingerprint inconsistencies as higher risk

## Command Guide

Run a normal scan:

```bash
opsec-sentinel --mode normal --out-dir ./reports
```

Run a stricter scan for anonymity-sensitive use:

```bash
opsec-sentinel --mode darknet --out-dir ./reports
```

Run bug bounty mode with one live monitoring snapshot:

```bash
opsec-sentinel --mode bugbounty --monitor --out-dir ./reports
```

List all loaded plugins without running a scan:

```bash
opsec-sentinel --list-plugins
```

Write only JSON output:

```bash
opsec-sentinel --json --out-dir ./reports
```

Write only Markdown output:

```bash
opsec-sentinel --md --out-dir ./reports
```

Write only HTML output:

```bash
opsec-sentinel --html --out-dir ./reports
```

Write a PDF report:

```bash
opsec-sentinel --pdf --out-dir ./reports
```

Disable AI analysis:

```bash
opsec-sentinel --no-ai --out-dir ./reports
```

Disable browser checks:

```bash
opsec-sentinel --no-browser --out-dir ./reports
```

Test AI connectivity only:

```bash
opsec-sentinel --test-ai
```

Test AI with a custom message:

```bash
opsec-sentinel --test-ai --test-ai-message "Why is fast inference important?"
```

Show environment and key-loading diagnostics:

```bash
opsec-sentinel --debug-env
```

Use a specific `.env` file:

```bash
opsec-sentinel --dotenv /path/to/.env --out-dir ./reports
```

## Common Examples

Quick local audit:

```bash
opsec-sentinel --out-dir ./reports
```

Strict anonymity audit without AI:

```bash
opsec-sentinel --mode darknet --no-ai --monitor --out-dir ./reports
```

Generate only machine-readable output for automation:

```bash
opsec-sentinel --json --no-ai --out-dir ./reports
```

## Output Files

`scan_results.json`

- Raw structured results
- Good for automation or pipeline use

`report.md`

- Easy to read in a terminal or on GitHub

`report.html`

- Visual report for local review

`report.pdf`

- Optional export for sharing

## Environment Variables

Required only if you use AI:

```env
ANTHROPIC_API_KEY=your-key-here
```

Optional:

```env
ANTHROPIC_MODEL=claude-opus-4-1
OPSEC_MODE=normal
OPSEC_AI_ENABLED=true
OPSEC_BROWSER_ENABLED=true
OPSEC_MONITORING_ENABLED=false
OPSEC_RECON_ENABLED=true
OPSEC_PLUGIN_DIRS=/opt/opsec/plugins,/srv/team/plugins
OPSEC_TOR_CHECK_URL=
OPSEC_GEOIP_URL=
OPSEC_HEADER_CHECK_URL=
```

## Project Layout

`opsec_sentinel_ai/`

- Main source code

`tests/`

- Test suite

`docs/ARCHITECTURE.md`

- Technical architecture notes

## Troubleshooting

If AI analysis is skipped:

- Check that `ANTHROPIC_API_KEY` is set
- Run `opsec-sentinel --debug-env`

If browser checks fail:

- Install browser extras: `pip install -e .[browser]`
- Install Chromium: `python -m playwright install chromium`

If PDF export fails:

- Install PDF extras: `pip install -e .[pdf]`
- Make sure WeasyPrint system dependencies are installed

## Security Notes

- Keep secrets only in local `.env` files
- Do not commit API keys
- The attack simulation engine estimates risk only

## Architecture

Technical design notes are in [docs/ARCHITECTURE.md](/home/cat0x01/Desktop/MyTools/AI-OPSEC-Score/docs/ARCHITECTURE.md).
