#!/usr/bin/env python3
"""
SecAudit - Web Security Headers & SSL/TLS Auditor
Author : Md Hamzah (@hamzahethical)
GitHub : https://github.com/hamzahethical/SecAudit
"""

import sys
import ssl
import socket
import json
import datetime
import argparse
import urllib.request
import urllib.error

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None

BANNER = r"""
  ____             _             _ _ _
 / ___|  ___  ___/ \  _   _  __| (_) |_
 \___ \ / _ \/ __/ _ \| | | |/ _` | | __|
  ___) |  __/ (_| (_) | |_| | (_| | | |_
 |____/ \___|\___\___/ \__,_|\__,_|_|\__|

  Web Security Headers & SSL/TLS Auditor
  Author: Md Hamzah (@hamzahethical)
"""

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Forces HTTPS connections (HSTS)",
        "severity": "HIGH",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    },
    "Content-Security-Policy": {
        "description": "Prevents XSS and data injection attacks",
        "severity": "HIGH",
        "recommendation": "Add a CSP header to restrict content sources."
    },
    "X-Frame-Options": {
        "description": "Prevents Clickjacking attacks",
        "severity": "MEDIUM",
        "recommendation": "Add: X-Frame-Options: SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing",
        "severity": "MEDIUM",
        "recommendation": "Add: X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "description": "Controls referrer information sent with requests",
        "severity": "LOW",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "description": "Controls browser features (camera, mic, geolocation)",
        "severity": "LOW",
        "recommendation": "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()"
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (deprecated but still checked)",
        "severity": "LOW",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block (use CSP instead)"
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Prevents cross-origin window attacks",
        "severity": "MEDIUM",
        "recommendation": "Add: Cross-Origin-Opener-Policy: same-origin"
    },
    "Cross-Origin-Resource-Policy": {
        "description": "Prevents cross-origin resource leakage",
        "severity": "MEDIUM",
        "recommendation": "Add: Cross-Origin-Resource-Policy: same-site"
    }
}

DANGEROUS_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]

SEVERITY_COLORS = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}
SEVERITY_WEIGHT = {"HIGH": 30, "MEDIUM": 15, "LOW": 5}


def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def fetch_headers(url):
    req = urllib.request.Request(url, headers={"User-Agent": "SecAudit/1.0 (Security Scanner)"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return dict(resp.headers), resp.status, resp.url
    except urllib.error.HTTPError as e:
        return dict(e.headers), e.code, url
    except Exception as e:
        return None, None, str(e)


def check_ssl(hostname, port=443):
    result = {
        "valid": False, "expiry": None, "issuer": None,
        "subject": None, "version": None, "days_left": None,
        "error": None, "expired": False, "self_signed": False
    }
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, port), timeout=10),
                             server_hostname=hostname) as s:
            cert = s.getpeercert()
            result["valid"] = True
            result["version"] = s.version()
            expiry_str = cert.get("notAfter", "")
            if expiry_str:
                expiry = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                result["expiry"] = expiry.strftime("%Y-%m-%d")
                result["days_left"] = (expiry - datetime.datetime.utcnow()).days
                result["expired"] = result["days_left"] < 0
            issuer = dict(x[0] for x in cert.get("issuer", []))
            subject = dict(x[0] for x in cert.get("subject", []))
            result["issuer"] = issuer.get("organizationName", issuer.get("commonName", "Unknown"))
            result["subject"] = subject.get("commonName", "Unknown")
            result["self_signed"] = result["issuer"] == result["subject"]
    except ssl.SSLCertVerificationError as e:
        result["error"] = f"SSL Verification Failed: {e}"
    except Exception as e:
        result["error"] = str(e)
    return result


def calculate_score(missing_headers, response_headers, ssl_result):
    score = 100
    for h, info in SECURITY_HEADERS.items():
        if h not in {k.title() if isinstance(k, str) else k for k in response_headers}:
            score -= SEVERITY_WEIGHT[info["severity"]]
    for dh in DANGEROUS_HEADERS:
        if dh.lower() in [k.lower() for k in response_headers]:
            score -= 5
    if ssl_result.get("error") or ssl_result.get("expired"):
        score -= 20
    elif ssl_result.get("self_signed"):
        score -= 10
    elif ssl_result.get("days_left", 999) < 30:
        score -= 5
    return max(0, score)


def grade(score):
    if score >= 90: return "A+", "green"
    if score >= 80: return "A",  "green"
    if score >= 70: return "B",  "yellow"
    if score >= 60: return "C",  "yellow"
    if score >= 50: return "D",  "orange3"
    return "F", "red"


def print_banner():
    if RICH:
        console.print(Panel(Text(BANNER, style="bold cyan"), border_style="cyan"))
    else:
        print(BANNER)


def audit(url, json_out=False, output_file=None):
    url = normalize_url(url)
    hostname = url.split("//", 1)[1].split("/")[0]
    
    if not json_out:
        print_banner()
        if RICH:
            console.print(f"\n[bold white]Target:[/bold white] [cyan]{url}[/cyan]")
            console.print(f"[bold white]Host:[/bold white]   [cyan]{hostname}[/cyan]")
            console.print(f"[bold white]Time:[/bold white]   [cyan]{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/cyan]\n")

    # 1. Fetch HTTP Headers
    if not json_out and RICH:
        console.print("[bold yellow]◆ Fetching HTTP Response Headers...[/bold yellow]")
    response_headers, status_code, final_url = fetch_headers(url)

    report = {
        "target": url,
        "host": hostname,
        "timestamp": datetime.datetime.now().isoformat(),
        "status_code": status_code,
        "final_url": final_url,
        "missing_headers": [],
        "present_headers": [],
        "dangerous_headers": [],
        "ssl": {},
        "score": 0,
        "grade": ""
    }

    if response_headers is None:
        if RICH:
            console.print(f"[red]✗ Could not connect to {url}[/red]")
        else:
            print(f"ERROR: Could not connect to {url}")
        return

    response_headers_lower = {k.lower(): v for k, v in response_headers.items()}

    # 2. Check Security Headers
    missing = []
    present = []
    for header, info in SECURITY_HEADERS.items():
        found = header.lower() in response_headers_lower
        if found:
            present.append({"header": header, "value": response_headers_lower[header.lower()]})
        else:
            missing.append({"header": header, **info})

    report["missing_headers"] = missing
    report["present_headers"] = present

    # 3. Check Dangerous Headers
    dangerous_found = []
    for dh in DANGEROUS_HEADERS:
        if dh.lower() in response_headers_lower:
            dangerous_found.append({"header": dh, "value": response_headers_lower[dh.lower()]})
    report["dangerous_headers"] = dangerous_found

    # 4. SSL Check
    if url.startswith("https://"):
        if not json_out and RICH:
            console.print("[bold yellow]◆ Checking SSL/TLS Certificate...[/bold yellow]")
        ssl_result = check_ssl(hostname)
    else:
        ssl_result = {"error": "HTTP only - no SSL/TLS"}
    report["ssl"] = ssl_result

    # 5. Score & Grade
    score = calculate_score(missing, response_headers, ssl_result)
    g, g_color = grade(score)
    report["score"] = score
    report["grade"] = g

    if json_out:
        out = json.dumps(report, indent=2)
        print(out)
        if output_file:
            with open(output_file, "w") as f:
                f.write(out)
        return

    # ─── Rich Output ─────────────────────────────────────────────
    if RICH:
        # Score Panel
        score_color = g_color
        console.print(Panel(
            f"[bold {score_color}]Security Score: {score}/100   Grade: {g}[/bold {score_color}]",
            border_style=score_color, title="[bold white]Overall Result[/bold white]"
        ))

        # Present Headers Table
        if present:
            t = Table(title="✅ Present Security Headers", box=box.ROUNDED, border_style="green")
            t.add_column("Header", style="green bold", no_wrap=True)
            t.add_column("Value", style="white")
            for h in present:
                val = h["value"]
                if len(val) > 60: val = val[:57] + "..."
                t.add_row(h["header"], val)
            console.print(t)

        # Missing Headers Table
        if missing:
            t = Table(title="❌ Missing Security Headers", box=box.ROUNDED, border_style="red")
            t.add_column("Header", style="bold white", no_wrap=True)
            t.add_column("Severity", justify="center")
            t.add_column("Description", style="dim")
            t.add_column("Fix / Recommendation", style="cyan")
            for h in missing:
                sev_color = SEVERITY_COLORS[h["severity"]]
                t.add_row(
                    h["header"],
                    f"[{sev_color}]{h['severity']}[/{sev_color}]",
                    h["description"],
                    h["recommendation"]
                )
            console.print(t)

        # Dangerous Headers
        if dangerous_found:
            t = Table(title="⚠️  Information-Leaking Headers (Remove These)", box=box.ROUNDED, border_style="yellow")
            t.add_column("Header", style="yellow bold")
            t.add_column("Leaked Value", style="red")
            for dh in dangerous_found:
                t.add_row(dh["header"], dh["value"])
            console.print(t)

        # SSL Table
        t = Table(title="🔒 SSL / TLS Certificate", box=box.ROUNDED, border_style="blue")
        t.add_column("Property", style="bold cyan", no_wrap=True)
        t.add_column("Value")
        if ssl_result.get("error"):
            t.add_row("Status", f"[red]✗ {ssl_result['error']}[/red]")
        else:
            days = ssl_result.get("days_left", "?")
            days_style = "green" if isinstance(days, int) and days > 30 else "red"
            t.add_row("Status",   "[green]✓ Valid[/green]")
            t.add_row("Protocol", ssl_result.get("version", "?"))
            t.add_row("Issuer",   ssl_result.get("issuer", "?"))
            t.add_row("Subject",  ssl_result.get("subject", "?"))
            t.add_row("Expires",  ssl_result.get("expiry", "?"))
            t.add_row("Days Left", f"[{days_style}]{days}[/{days_style}]")
            if ssl_result.get("self_signed"):
                t.add_row("Warning", "[red]⚠ Self-signed certificate detected![/red]")
        console.print(t)

    else:
        # Fallback plain output
        print(f"\nScore: {score}/100 | Grade: {g}")
        print("\nMissing Headers:")
        for h in missing:
            print(f"  [{h['severity']}] {h['header']} - {h['description']}")
        print("\nSSL:", ssl_result)

    if output_file:
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)
        if RICH:
            console.print(f"\n[green]✓ Report saved to {output_file}[/green]")


def main():
    parser = argparse.ArgumentParser(
        description="SecAudit - Web Security Headers & SSL/TLS Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python secaudit.py -u example.com
  python secaudit.py -u https://google.com
  python secaudit.py -u example.com --json
  python secaudit.py -u example.com -o report.json
        """
    )
    parser.add_argument("-u", "--url",    required=True, help="Target URL or domain (e.g. example.com)")
    parser.add_argument("--json",         action="store_true", help="Output raw JSON report")
    parser.add_argument("-o", "--output", help="Save JSON report to file")
    args = parser.parse_args()
    audit(args.url, json_out=args.json, output_file=args.output)


if __name__ == "__main__":
    main()
