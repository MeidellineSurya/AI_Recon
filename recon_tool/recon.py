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


def main():
    # 1. Check len(sys.argv) — exit if no domain argument given
    # 2. Call all three functions
    # 3. Print results clearly


if __name__ == "__main__":
    main()