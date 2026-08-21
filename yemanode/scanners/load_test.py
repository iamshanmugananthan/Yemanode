"""
Load Testing & Rate Limit Security Scanner for Yemanode.
Performs controlled concurrent load testing to audit API rate limiting,
throughput (RPS), status code distribution, latency percentiles (P50/P95/P99),
and resilience against resource exhaustion (CWE-799 / OWASP API4:2023).
"""
import time
import statistics
import concurrent.futures
import requests

from .. import report

DEFAULT_CONCURRENCY = 10
DEFAULT_TOTAL_REQUESTS = 100
TIMEOUT = 6


def _execute_single_request(url, method="GET", headers=None, data=None, json_data=None, timeout=TIMEOUT):
    start = time.perf_counter()
    headers = headers or {}
    if "User-Agent" not in headers:
        headers["User-Agent"] = "Yemanode-RateLimit-Auditor/2.0"

    try:
        resp = requests.request(
            method=method.upper(),
            url=url,
            headers=headers,
            data=data,
            json=json_data,
            timeout=timeout,
            allow_redirects=True,
            verify=False
        )
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return {
            "status_code": resp.status_code,
            "elapsed_ms": elapsed_ms,
            "headers": dict(resp.headers),
            "error": None,
        }
    except requests.RequestException as e:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return {
            "status_code": 0,
            "elapsed_ms": elapsed_ms,
            "headers": {},
            "error": str(e),
        }


def run_load_test(url: str, method: str = "GET", total_requests: int = 100,
                  concurrency: int = 10, timeout: int = TIMEOUT,
                  headers: dict = None, data=None, json_data=None):
    """
    Executes controlled concurrent requests against the target API to audit rate limiting
    and compute performance/reliability metrics.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    total_requests = max(1, min(total_requests, 5000))
    concurrency = max(1, min(concurrency, 100))

    start_time = time.perf_counter()
    results = []

    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [
            executor.submit(_execute_single_request, url, method, headers, data, json_data, timeout)
            for _ in range(total_requests)
        ]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    total_duration_sec = time.perf_counter() - start_time
    total_duration_sec = max(total_duration_sec, 0.001)

    # Compute Statistics
    status_counts = {}
    latencies = []
    rate_limit_headers_detected = set()
    first_429_index = None

    for idx, r in enumerate(results, start=1):
        sc = r["status_code"]
        status_counts[sc] = status_counts.get(sc, 0) + 1
        latencies.append(r["elapsed_ms"])

        if sc == 429 and first_429_index is None:
            first_429_index = idx

        for h in r.get("headers", {}):
            hl = h.lower()
            if "ratelimit" in hl or "retry-after" in hl or "x-rate-limit" in hl:
                rate_limit_headers_detected.add(h)

    latencies.sort()
    count = len(latencies)
    avg_latency = statistics.mean(latencies) if latencies else 0.0
    median_latency = statistics.median(latencies) if latencies else 0.0
    min_latency = latencies[0] if latencies else 0.0
    max_latency = latencies[-1] if latencies else 0.0
    p95_latency = latencies[int(count * 0.95)] if count > 0 else 0.0
    p99_latency = latencies[int(count * 0.99)] if count > 0 else 0.0
    rps = count / total_duration_sec

    # Evaluate Security Findings
    findings = []
    
    # 1. Unrestricted Resource Consumption (No rate limiting)
    num_429 = status_counts.get(429, 0)
    num_2xx = sum(v for k, v in status_counts.items() if 200 <= k < 300)
    num_5xx = sum(v for k, v in status_counts.items() if 500 <= k < 600)

    if total_requests >= 50 and num_429 == 0 and not rate_limit_headers_detected:
        findings.append({
            "type": "[API Rate Limiting] No Throttling or Rate Limiting Enforced Under High Concurrency",
            "severity": "high",
            "target": url,
            "cwe": "CWE-799",
            "owasp": "API4:2023-Unrestricted Resource Consumption",
            "cvss": 7.5,
            "detail": f"{total_requests} concurrent requests at {rps:.1f} RPS returned {num_2xx} successful responses with zero 429 throttling.",
            "fix": "Configure API Gateway rate limiting / usage plans (e.g. token bucket / leaky bucket algorithm) to prevent denial of service.",
        })
    elif num_429 > 0:
        findings.append({
            "type": f"[API Rate Limiting Verified] Rate Limiting Active (HTTP 429 Triggered at {num_429}/{total_requests} requests)",
            "severity": "info",
            "target": url,
            "cwe": "CWE-799",
            "owasp": "API4:2023-Unrestricted Resource Consumption",
            "cvss": 0.0,
            "detail": f"Target responded with HTTP 429 (Too Many Requests). Rate limiting successfully throttled excess requests.",
            "fix": "Rate limiting is functioning as expected. Ensure legitimate user quotas and Retry-After headers are configured appropriately.",
        })

    # 2. Server Errors Under Load (5xx)
    if num_5xx > 0:
        findings.append({
            "type": f"[API Stability] Server Internal Errors ({num_5xx} HTTP 5xx responses) Under Concurrent Load",
            "severity": "high",
            "target": url,
            "cwe": "CWE-400",
            "owasp": "API4:2023-Unrestricted Resource Consumption",
            "cvss": 7.5,
            "detail": f"{num_5xx} of {total_requests} requests caused server-side exceptions or timeouts (HTTP 5xx).",
            "fix": "Check database connection pooling, thread contention, and auto-scaling rules under peak loads.",
        })

    # 3. High Latency Degradation
    if p95_latency > 3000:
        findings.append({
            "type": f"[API Performance Degradation] High P95 Latency ({p95_latency:.1f}ms) Under Load",
            "severity": "medium",
            "target": url,
            "cwe": "CWE-400",
            "owasp": "API4:2023-Unrestricted Resource Consumption",
            "cvss": 5.3,
            "detail": f"P95 response time rose to {p95_latency:.1f} ms during concurrent testing.",
            "fix": "Implement caching, optimize query bottlenecks, and configure CDN/Gateway caching layers.",
        })

    return {
        "target": url,
        "method": method.upper(),
        "total_requests": total_requests,
        "concurrency": concurrency,
        "duration_sec": total_duration_sec,
        "rps": rps,
        "status_counts": status_counts,
        "latencies": {
            "min_ms": min_latency,
            "max_ms": max_latency,
            "avg_ms": avg_latency,
            "median_ms": median_latency,
            "p95_ms": p95_latency,
            "p99_ms": p99_latency,
        },
        "rate_limit_headers": list(rate_limit_headers_detected),
        "first_429_index": first_429_index,
        "findings": findings,
    }


def write_load_test_report(output_path, test_results):
    """
    Generates a Markdown report summarizing load test metrics and rate limit audit findings.
    """
    url = test_results["target"]
    method = test_results["method"]
    total = test_results["total_requests"]
    concurrency = test_results["concurrency"]
    duration = test_results["duration_sec"]
    rps = test_results["rps"]
    status_counts = test_results["status_counts"]
    lat = test_results["latencies"]
    rl_headers = test_results["rate_limit_headers"]
    findings = test_results["findings"]

    lines = []
    lines.append(f"# ⚡ API Load & Rate Limit Test Report — `{url}`")
    lines.append("")
    lines.append(f"**Target URL:** `{method} {url}`")
    lines.append(f"**Concurrency:** {concurrency} workers | **Total Requests:** {total}")
    lines.append(f"**Total Time:** {duration:.2f}s | **Throughput:** `{rps:.1f} req/sec`")
    lines.append("")
    lines.append("## 📊 Performance & Latency Summary")
    lines.append("")
    lines.append("| Metric | Latency (ms) |")
    lines.append("|---|---:|")
    lines.append(f"| Minimum Latency | {lat['min_ms']:.2f} ms |")
    lines.append(f"| Average Latency | {lat['avg_ms']:.2f} ms |")
    lines.append(f"| Median (P50) | {lat['median_ms']:.2f} ms |")
    lines.append(f"| 95th Percentile (P95) | {lat['p95_ms']:.2f} ms |")
    lines.append(f"| 99th Percentile (P99) | {lat['p99_ms']:.2f} ms |")
    lines.append(f"| Maximum Latency | {lat['max_ms']:.2f} ms |")
    lines.append("")
    lines.append("## 🚦 HTTP Response Status Code Breakdown")
    lines.append("")
    lines.append("| Status Code | Count | Percentage |")
    lines.append("|---|---:|---:|")
    for code, count in sorted(status_counts.items(), key=lambda x: str(x[0])):
        desc = "Success" if 200 <= code < 300 else ("Rate Limited (429)" if code == 429 else ("Server Error" if 500 <= code < 600 else ("Connection Failed" if code == 0 else "Client Error")))
        pct = (count / total) * 100.0
        lines.append(f"| `{code}` ({desc}) | {count} | {pct:.1f}% |")
    lines.append("")

    lines.append("## 🛡️ Rate Limit & Security Audit Findings")
    lines.append("")
    if rl_headers:
        lines.append(f"**Detected Rate Limiting Headers:** `{', '.join(rl_headers)}`")
    else:
        lines.append("**Detected Rate Limiting Headers:** `None detected`")
    lines.append("")

    if not findings:
        lines.append("No rate limit or load stability issues detected.")
    else:
        for f in report._sorted(findings):
            sev = f.get("severity", "info")
            cwe = f.get("cwe", "CWE-799")
            owasp = f.get("owasp", "API4:2023-Unrestricted Resource Consumption")
            cvss = f.get("cvss", report.DEFAULT_CVSS_MAP.get(sev, 0.0))
            lines.append(f"### {report.SEVERITY_ICON[sev]} [{sev.upper()}] {f['type']}")
            lines.append("")
            lines.append(f"- **Standards:** `{cwe}` | `{owasp}` | **CVSS:** `{cvss}`")
            if f.get("detail"):
                lines.append(f"- **Detail:** {f['detail']}")
            if f.get("fix"):
                lines.append(f"- **Remediation:** {f['fix']}")
            lines.append("")

    lines.append("---")
    lines.append("_Generated by Yemanode v2 — API Load & Rate Limit Testing Engine._")

    return report._write(output_path, "\n".join(lines))
