import os
import json
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

SYSTEM_PROMPT = """
You are a professional penetration tester and security analyst.

You will be given OSINT recon data about a target domain including:
DNS records, HTTP headers, subdomains, and header analysis.

Your job is to identify security concerns and return them as JSON only.
No prose, no explanation outside the JSON structure.

Return exactly this format:
{
  "domain": "<domain>",
  "risk_summary": "<2 sentence overall assessment>",
  "findings": [
    {
      "title": "<short finding name>",
      "severity": "critical | high | medium | low | info",
      "description": "<what you found and why it matters>",
      "evidence": "<specific data point from the recon that supports this>",
      "recommendation": "<one concrete fix>"
    }
  ]
}

Severity guidelines:
- critical: direct path to compromise
- high: significant exposure, likely exploitable
- medium: weakens security posture
- low: minor issue, best practice violation
- info: notable but not a vulnerability

Sort findings by severity (critical first).
Never invent findings not supported by the provided data.
"""

INTERESTING_KEYWORDS = {"staging", "internal", "admin", "dev", "test", "backup"}


def format_recon_data(domain, recon_data):
    """
    Format recon_data dict into readable text for the LLM.
    Returns a string.

    Expected recon_data keys:
        ips         : list[str]
        dns_records : {"MX": list[str], "TXT": list[str]}
        headers     : dict[str, str]
        subdomains  : list[{"subdomain": str, "ip": str}]
        header_flags: list[str]   e.g. ["[!] HSTS not set", "[✓] MIME sniffing..."]
    """
    lines = [f"Domain: {domain}"]

    # --- A Records ---
    ips = recon_data.get("ips", [])
    lines.append("\nIP Addresses:")
    lines.extend(f"  {ip}" for ip in ips) if ips else lines.append("  None")

    # --- MX Records ---
    mx = recon_data.get("dns_records", {}).get("MX", [])
    lines.append("\nMX Records:")
    lines.extend(f"  {r}" for r in mx) if mx else lines.append("  None")

    # --- TXT Records ---
    txt = recon_data.get("dns_records", {}).get("TXT", [])
    lines.append("\nTXT Records:")
    lines.extend(f"  {r}" for r in txt) if txt else lines.append("  None")

    # --- HTTP Headers ---
    headers = recon_data.get("headers", {})
    lines.append("\nHTTP Headers:")
    if headers:
        for k, v in headers.items():
            lines.append(f"  {k}: {v}")
    else:
        lines.append("  None")

    # --- Subdomains (flag interesting ones) ---
    subdomains = recon_data.get("subdomains", [])
    lines.append("\nSubdomains Found:")
    if subdomains:
        for entry in subdomains:
            sub, ip = entry["subdomain"], entry["ip"]
            tag = " [INTERESTING]" if any(kw in sub.lower() for kw in INTERESTING_KEYWORDS) else ""
            lines.append(f"  {sub} → {ip}{tag}")
    else:
        lines.append("  None")

    # --- Header flag observations from analyze_headers() ---
    flags = recon_data.get("header_flags", [])
    lines.append("\nSecurity Header Observations:")
    lines.extend(f"  {f}" for f in flags) if flags else lines.append("  None")

    return "\n".join(lines)


def analyze_with_ai(domain, recon_data):
    """
    Send formatted recon data to Groq/LLaMA.
    Returns parsed dict or None on failure.
    """
    client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

    formatted = format_recon_data(domain, recon_data)

    try:
        response = client.chat.completions.create(
            model="llama3-70b-8192",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": formatted},
            ],
            temperature=0.2,  # low temp — we want consistent structured output
        )
    except Exception as e:
        print(f"[!] Groq API error: {e}")
        return None

    raw = response.choices[0].message.content.strip()

    # Strip ```json ... ``` fences if the model adds them
    if raw.startswith("```"):
        raw = raw.split("```", 2)[1]          # drop opening ```[json]
        if raw.startswith("json"):
            raw = raw[4:]                      # strip the "json" language tag
        raw = raw.rsplit("```", 1)[0]          # drop closing ```
        raw = raw.strip()

    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"[!] Failed to parse model response as JSON: {e}")
        print(f"    Raw response was:\n{raw}")
        return None