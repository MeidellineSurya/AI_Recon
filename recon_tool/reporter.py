from datetime import date

SEVERITY_ICONS = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}

INTERESTING_KEYWORDS = {"staging", "internal", "admin", "dev", "test", "backup"}


def generate_report(domain, recon_data, analysis):
    """
    Takes:
      - domain: str
      - recon_data: the same dict passed to analyze_with_ai()
      - analysis: the parsed dict returned by analyze_with_ai()

    Returns: a markdown string
    """
    sections = []

    # ------------------------------------------------------------------ #
    # 1. Header
    # ------------------------------------------------------------------ #
    sections.append(f"# 🔍 OSINT Recon Report: `{domain}`")
    sections.append(f"**Date:** {date.today().strftime('%Y-%m-%d')}  ")
    sections.append("---\n")

    # ------------------------------------------------------------------ #
    # 2. Risk Summary
    # ------------------------------------------------------------------ #
    risk_summary = analysis.get("risk_summary", "No summary available.")
    sections.append("## Risk Summary\n")
    sections.append(f"> {risk_summary}\n")

    # ------------------------------------------------------------------ #
    # 3. Raw Recon Data
    # ------------------------------------------------------------------ #
    sections.append("## Recon Data\n")

    # IP addresses
    ips = recon_data.get("ips", [])
    sections.append("### IP Addresses")
    if ips:
        sections.append("\n".join(f"- `{ip}`" for ip in ips))
    else:
        sections.append("- None found")
    sections.append("")

    # MX records
    mx = recon_data.get("dns_records", {}).get("MX", [])
    sections.append("### MX Records")
    if mx:
        sections.append("\n".join(f"- `{r}`" for r in mx))
    else:
        sections.append("- None found")
    sections.append("")

    # Interesting subdomains only — full list would be noisy in a report
    subdomains = recon_data.get("subdomains", [])
    interesting = [
        s for s in subdomains
        if any(kw in s["subdomain"].lower() for kw in INTERESTING_KEYWORDS)
    ]
    sections.append("### Interesting Subdomains")
    if interesting:
        for entry in interesting:
            sections.append(f"- `{entry['subdomain']}` → `{entry['ip']}`")
    else:
        sections.append("- None flagged")
    sections.append("")

    # Security header flags
    flags = recon_data.get("header_flags", [])
    sections.append("### Security Header Observations")
    if flags:
        sections.append("\n".join(f"- {f}" for f in flags))
    else:
        sections.append("- No observations")
    sections.append("")

    # ------------------------------------------------------------------ #
    # 4. Findings
    # ------------------------------------------------------------------ #
    sections.append("## Findings\n")
    findings = analysis.get("findings", [])

    if not findings:
        sections.append("_No findings reported._\n")
    else:
        for f in findings:
            severity = f.get("severity", "info").lower()
            icon     = SEVERITY_ICONS.get(severity, "⚪")
            title    = f.get("title", "Untitled")

            sections.append(f"### {icon} {title}")
            sections.append(f"**Severity:** `{severity.upper()}`  ")
            sections.append(f"**Description:** {f.get('description', '')}  ")
            sections.append(f"**Evidence:** {f.get('evidence', '')}  ")
            sections.append(f"**Recommendation:** {f.get('recommendation', '')}  ")
            sections.append("")

    return "\n".join(sections)


def save_report(domain, content, output_dir="."):
    """
    Saves the markdown string to a file.
    Filename format: {output_dir}/{domain}_report_{date}.md
    Returns the filepath so main() can print it.
    """
    filepath = f"{output_dir}/{domain}_report_{date.today()}.md"
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    return filepath


def save_json(domain, recon_data, analysis, output_dir="."):
    """
    Save raw scan data as JSON.
    Filename: {output_dir}/{domain}_scan_{date}.json
    Returns filepath.
    """
    import json
    filepath = f"{output_dir}/{domain}_scan_{date.today()}.json"
    payload = {"domain": domain, "scan_date": str(date.today())} | recon_data | analysis
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(json.dumps(payload, indent=2))
    return filepath