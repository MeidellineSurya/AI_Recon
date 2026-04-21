import dns.resolver
import requests
import sys

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
    Print simple security observations from HTTP headers.
    """
    normalized = {k.lower(): v for k, v in headers.items()}

    if "strict-transport-security" in normalized:
        print("[✓] HSTS enabled")
    else:
        print("[!] HSTS not set — HTTPS not enforced")

    if "x-frame-options" in normalized:
        print("[✓] Clickjacking protection enabled (X-Frame-Options)")
    else:
        csp = normalized.get("content-security-policy", "")
        if "frame-ancestors" in csp.lower():
            print("[✓] Clickjacking protection enabled (CSP frame-ancestors)")
        else:
            print("[!] Clickjacking protection missing")

    if "x-content-type-options" in normalized:
        print("[✓] MIME sniffing protection enabled")
    else:
        print("[!] MIME sniffing protection missing")


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

    print("\nSecurity Observations:")
    analyze_headers(headers)

if __name__ == "__main__":
    main()