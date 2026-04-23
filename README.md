# 🔍 AI Recon Agent

An AI-powered OSINT reconnaissance tool that performs automated domain reconnaissance and uses an LLM to analyze the collected data for security vulnerabilities — generating structured findings with severity ratings and remediation advice.

---

## What It Does

Give it a domain. It gathers OSINT data, runs it through an AI security analyst (LLaMA 3.3 70B via Groq), and produces a ranked findings report with evidence and fix recommendations.

**Recon capabilities:**
- **DNS resolution** — A records (IP addresses), MX records, TXT records
- **Subdomain enumeration** — via HackerTarget API, with automatic flagging of interesting subdomains (`admin`, `dev`, `staging`, `internal`, `test`, `backup`)
- **HTTP header analysis** — checks HSTS, X-Frame-Options, X-Content-Type-Options; tries HTTPS then falls back to HTTP
- **AI security analysis** — formats all collected data and sends it to LLaMA 3.3 70B, which returns structured JSON findings sorted by severity

**Output:**
- A readable Markdown report saved to `reports/`
- A raw JSON scan file for downstream processing or archiving

---

## Project Structure

```
AI_Recon/
└── recon_tool/
    ├── recon.py          # Main entry point — orchestrates the full scan
    ├── agent.py          # Formats recon data and calls the Groq/LLaMA API
    ├── reporter.py       # Generates the Markdown report and saves JSON output
    ├── requirements.txt  # Python dependencies
    └── .env              # API key configuration (not committed)
```

---

## Setup

### 1. Clone the repo

```bash
git clone <your-repo-url>
cd AI_Recon/recon_tool
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

Dependencies: `dnspython`, `requests`, `groq`, `python-dotenv`

### 3. Configure your API key

Create a `.env` file in `recon_tool/`:

```env
GROQ_API_KEY=your_groq_api_key_here
```

Get a free API key at [console.groq.com](https://console.groq.com).

> ⚠️ Never commit your `.env` file or API key to version control.

---

## Usage

Run a scan from inside the `recon_tool/` directory:

```bash
python recon.py <domain>
```

**Examples:**

```bash
python recon.py example.com
python recon.py github.com --output ../reports
```

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `domain` | *(required)* | Target domain to scan |
| `--output` | `reports` | Directory to save report and JSON files |

---

## Example Output

```
Domain: github.com

A Records:
- 4.237.22.38

MX Records:
- github-com.mail.protection.outlook.com

Interesting Subdomains:
- [!] admin.github.com  →  140.82.113.23
- [!] alive-staging.github.com  →  143.55.70.2

Security Observations:
- [✓] HSTS enabled
- [✓] Clickjacking protection enabled (X-Frame-Options)
- [✓] MIME sniffing protection enabled

AI Security Analysis:
Risk Summary: The domain has a robust security posture but some improvements can be made...

Findings:

[MEDIUM] Potential Subdomain Takeover
  → Some subdomains have different IP addresses, which could indicate takeover vulnerabilities.
  → Evidence: admin.github.com → 140.82.113.23
  → Fix: Verify the ownership and configuration of these subdomains.

[✓] Report saved to: reports/github.com_report_2026-04-23.md
[✓] JSON saved to:   reports/github.com_scan_2026-04-23.json
```

---

## Finding Severity Levels

| Severity | Meaning |
|----------|---------|
| 🔴 `CRITICAL` | Direct path to compromise |
| 🟠 `HIGH` | Significant exposure, likely exploitable |
| 🟡 `MEDIUM` | Weakens security posture |
| 🔵 `LOW` | Minor issue or best practice violation |
| ⚪ `INFO` | Notable but not a vulnerability |

---

## How It Works

1. **`recon.py`** parses the target domain and runs all recon functions in sequence, printing results to stdout as they arrive.
2. **`agent.py`** takes the collected data, formats it into a structured prompt, and sends it to LLaMA 3.3 70B via the Groq API. The model is instructed to return JSON only — no prose. The response is stripped of any markdown fences and parsed.
3. **`reporter.py`** renders the findings into a clean Markdown report and saves both the report and the raw scan data as JSON.

---

## Notes & Limitations

- Subdomain enumeration uses the free [HackerTarget API](https://hackertarget.com/), which rate-limits unauthenticated requests.
- The tool performs **passive OSINT only** — no active probing, exploitation, or port scanning.
- Always ensure you have permission before scanning a domain you do not own.
