# 🔍 OSINT Recon Report: `github.com`
**Date:** 2026-04-23  
---

## Risk Summary

> The domain github.com has a robust security posture with several security headers enabled, but there are some potential issues with subdomain configuration and HTTP header settings. Overall, the risk is relatively low, but some improvements can be made to further enhance security.

## Recon Data

### IP Addresses
- `4.237.22.38`

### MX Records
- `github-com.mail.protection.outlook.com`

### Interesting Subdomains
- `admin.github.com` → `140.82.113.23`
- `alive-staging.github.com` → `143.55.70.2`
- `developer.github.com` → `185.199.110.153`
- `developers.github.com` → `185.199.110.153`
- `docs-internal.github.com` → `140.82.113.22`

### Security Header Observations
- [✓] HSTS enabled
- [✓] Clickjacking protection enabled (X-Frame-Options)
- [✓] MIME sniffing protection enabled

## Findings

### 🟡 Potential Subdomain Takeover
**Severity:** `MEDIUM`  
**Description:** Some subdomains (e.g., admin.github.com, alive-staging.github.com, developer.github.com, developers.github.com, docs-internal.github.com) have different IP addresses, which could indicate potential subdomain takeover vulnerabilities.  
**Evidence:** Subdomains with different IP addresses  
**Recommendation:** Verify the ownership and configuration of these subdomains to prevent potential takeover attacks.  

### 🔵 Insecure X-XSS-Protection Header
**Severity:** `LOW`  
**Description:** The X-XSS-Protection header is set to 0, which disables XSS protection. This is not recommended as it can leave the application vulnerable to XSS attacks.  
**Evidence:** X-XSS-Protection: 0  
**Recommendation:** Set the X-XSS-Protection header to 1; mode=block to enable XSS protection.  

### 🔵 Missing Content-Security-Policy (CSP) Directives
**Severity:** `LOW`  
**Description:** The Content-Security-Policy header is present, but some directives (e.g., 'object-src', 'upgrade-insecure-requests') are missing or not properly configured.  
**Evidence:** Content-Security-Policy: default-src 'none'; ...  
**Recommendation:** Review and update the CSP directives to ensure they are properly configured and aligned with the application's security requirements.  
