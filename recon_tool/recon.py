import dns.resolver
import requests
import sys
from agent import analyze_with_ai
from reporter import generate_report, save_report

def get_ip(domain):
    """
    Query A records for the domain.
    Returns a list of IP address strings.
    If lookup fails, return an empty list.
    """
    # 1. Create a dns.resolver.Resolver()
    # 2. Call .resolve(domain, 'A')
    # 3. Loop over the result — each item has a .address attribute
    # 4. Wrap in try/except — what exceptions might dnspython raise?
    resolver = dns.resolver.Resolver()
    try:
        answers = resolver.resolve(domain, "A")
        return [record.address for record in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return []


def get_dns_records(domain):
    """
    Query MX and TXT records for the domain.
    Returns a dict: {"MX": [...], "TXT": [...]}
    Each list contains strings.
    """
    # 1. Build an empty results dict first
    # 2. For MX: each record has .exchange (the mail server hostname)
    # 3. For TXT: each record has .strings (a list of bytes — decode to utf-8)
    # 4. If a record type doesn't exist, store an empty list — don't crash
    resolver = dns.resolver.Resolver()
    results = {"MX": [], "TXT": []}

    try:
        mx_answers = resolver.resolve(domain, "MX")
        results["MX"] = [str(record.exchange).rstrip(".") for record in mx_answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        results["MX"] = []

    try:
        txt_answers = resolver.resolve(domain, "TXT")
        decoded_txt = []
        for record in txt_answers:
            decoded_parts = [part.decode("utf-8", errors="replace") for part in record.strings]
            decoded_txt.append("".join(decoded_parts))
        results["TXT"] = decoded_txt
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        results["TXT"] = []

    return results


def get_http_headers(domain):
    """
    Make a HEAD request to the domain.
    Try HTTPS first, fall back to HTTP.
    Returns a dict of headers, or empty dict on failure.
    """
    # 1. Try: requests.head(f"https://{domain}", timeout=5)
    # 2. Except: try http:// instead
    # 3. requests.head() returns a Response object — .headers is a dict-like object
    # 4. Convert to a plain dict before returning
    try:
        response = requests.head(f"https://{domain}", timeout=5, allow_redirects=True)
        return dict(response.headers)
    except requests.RequestException:
        try:
            response = requests.head(f"http://{domain}", timeout=5, allow_redirects=True)
            return dict(response.headers)
        except requests.RequestException:
            return {}


def analyze_headers(headers):
    """
    Check HTTP headers for common security issues.
    Prints each observation and returns them as a list of strings.
    """
    normalized = {k.lower(): v for k, v in headers.items()}
    flags = []

    def flag(msg):
        print(msg)
        flags.append(msg)

    if "strict-transport-security" in normalized:
        flag("[✓] HSTS enabled")
    else:
        flag("[!] HSTS not set — HTTPS not enforced")

    if "x-frame-options" in normalized:
        flag("[✓] Clickjacking protection enabled (X-Frame-Options)")
    else:
        csp = normalized.get("content-security-policy", "")
        if "frame-ancestors" in csp.lower():
            flag("[✓] Clickjacking protection enabled (CSP frame-ancestors)")
        else:
            flag("[!] Clickjacking protection missing")

    if "x-content-type-options" in normalized:
        flag("[✓] MIME sniffing protection enabled")
    else:
        flag("[!] MIME sniffing protection missing")

    return flags


def get_subdomains(domain):
    """
    Fetch subdomains using HackerTarget API.
    Returns a list of dicts: [{"subdomain": ..., "ip": ...}]
    If the request fails or returns an error, return an empty list.
    """
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.RequestException:
        return []

    results = []
    for line in response.text.splitlines():
        # Skip empty lines and HackerTarget error responses
        if not line or line.startswith("error"):
            return []
        parts = line.split(",")
        if len(parts) != 2:
            continue
        subdomain, ip = parts[0].strip(), parts[1].strip()
        if subdomain and ip:
            results.append({"subdomain": subdomain, "ip": ip})

    return results


def main():
    # 1. Check len(sys.argv) — exit if no domain argument given
    # 2. Call all three functions
    # 3. Print results clearly
    if len(sys.argv) < 2:
        print("Usage: python recon.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]

    ips = get_ip(domain)
    dns_records = get_dns_records(domain)
    headers = get_http_headers(domain)
    subdomains = get_subdomains(domain)

    print(f"Domain: {domain}")
    print("\nA Records:")
    if ips:
        for ip in ips:
            print(f"- {ip}")
    else:
        print("- None")

    print("\nMX Records:")
    if dns_records["MX"]:
        for mx in dns_records["MX"]:
            print(f"- {mx}")
    else:
        print("- None")

    print("\nTXT Records:")
    if dns_records["TXT"]:
        for txt in dns_records["TXT"]:
            print(f"- {txt}")
    else:
        print("- None")

    print("\nHTTP Headers:")
    if headers:
        for key, value in headers.items():
            print(f"- {key}: {value}")
    else:
        print("- None")

    print("\nSubdomains Found:")
    if subdomains:
        for entry in subdomains:
            print(f"- {entry['subdomain']}  →  {entry['ip']}")
    else:
        print("- None")

    INTERESTING_KEYWORDS = {"staging", "internal", "admin", "dev", "test", "backup"}
    interesting = [
        entry for entry in subdomains
        if any(kw in entry["subdomain"].lower() for kw in INTERESTING_KEYWORDS)
    ]
    print("\nInteresting Subdomains:")
    if interesting:
        for entry in interesting:
            print(f"- [!] {entry['subdomain']}  →  {entry['ip']}")
    else:
        print("- None found")

    print("\nSecurity Observations:")
    header_flags = analyze_headers(headers)

    # --- AI Analysis ---
    recon_data = {
        "ips":          ips,
        "dns_records":  dns_records,
        "headers":      headers,
        "subdomains":   subdomains,
        "header_flags": header_flags,
    }

    print("\nAI Security Analysis:")
    analysis = analyze_with_ai(domain, recon_data)

    if not analysis:
        print("  [!] AI analysis failed or returned no data.")
        return

    print(f"Risk Summary: {analysis.get('risk_summary', 'N/A')}")

    findings = analysis.get("findings", [])
    if not findings:
        print("\nFindings:\n  None reported.")
        return

    print("\nFindings:")
    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 99))

    for f in findings:
        severity    = f.get("severity", "info").upper()
        title       = f.get("title", "Untitled")
        description = f.get("description", "")
        evidence    = f.get("evidence", "")
        fix         = f.get("recommendation", "")

        print(f"\n[{severity}] {title}")
        if description:
            print(f"  → {description}")
        if evidence:
            print(f"  → Evidence: {evidence}")
        if fix:
            print(f"  → Fix: {fix}")

    report_md = generate_report(domain, recon_data, analysis)
    filename  = save_report(domain, report_md)
    print(f"\n[✓] Report saved to: {filename}")

if __name__ == "__main__":
    main()