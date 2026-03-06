#!/usr/bin/env python3
"""
APIsec NG - Security Scan Script

Triggers and monitors a security scan on the APIsec NG platform.
Authenticates via PAT, initiates a scan, polls for status, and reports results.

Requirements:
    - requests (pip install requests)

Environment Variables:
    APISEC_TOKEN - APIsec NG Personal Access Token (PAT)

Examples:
    # Scan by IDs
    python ng_apisec_scan.py --application-id <uuid> --instance-id <uuid>

    # Scan by application name
    python ng_apisec_scan.py --application-name "My API"

    # Authenticated scan with reporting
    python ng_apisec_scan.py --application-id <uuid> --instance-id <uuid> \
        --auth-id <uuid> --timeout 900 --reporting
"""

import argparse
import json
import os
import sys
import time

try:
    import requests
except ImportError:
    print("ERROR: Missing dependency 'requests'. Install with: pip install requests")
    sys.exit(1)


API_BASE = "https://api.apisecapps.com"


def get_headers(token):
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def resolve_application(token, application_name):
    """
    Look up an application by name via GET /v1/applications.
    Returns (applicationId, instanceId) for the first instance found.
    """
    headers = get_headers(token)
    url = f"{API_BASE}/v1/applications?include=metadata"

    while url:
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code != 200:
            print(f"Failed to list applications: {resp.status_code} - {resp.text}")
            sys.exit(1)

        data = resp.json()
        apps = data.get("applications", [])

        for app in apps:
            if app.get("applicationName") == application_name:
                app_id = app.get("applicationId")
                instances = app.get("instances", [])
                if not instances:
                    print(f"Application '{application_name}' found (ID: {app_id}) but has no instances.")
                    sys.exit(1)
                inst_id = instances[0].get("instanceId")
                print(f"Resolved: applicationId={app_id}, instanceId={inst_id}")
                return app_id, inst_id

        next_token = data.get("nextToken")
        if next_token:
            url = f"{API_BASE}/v1/applications?include=metadata&nextToken={next_token}"
        else:
            url = None

    print(f"Application '{application_name}' not found.")
    sys.exit(1)


def initiate_scan(token, app_id, instance_id, auth_id=None, endpoint_ids=None):
    """
    Start a security scan.
    POST /v1/applications/{appId}/instances/{instanceId}/scan
    Body: { endpointIds: [...], scanWithAuthId: "" }
    """
    headers = get_headers(token)
    url = f"{API_BASE}/v1/applications/{app_id}/instances/{instance_id}/scan"

    body = {
        "endpointIds": endpoint_ids or [],
        "scanWithAuthId": auth_id or "",
    }

    print(f"Initiating scan on application {app_id}, instance {instance_id}...")
    if auth_id:
        print(f"  Auth ID: {auth_id}")
    if endpoint_ids:
        print(f"  Targeting {len(endpoint_ids)} endpoints")
    else:
        print("  Scanning all endpoints")

    resp = requests.post(url, headers=headers, json=body, timeout=60)

    if resp.status_code not in (200, 201):
        print(f"Failed to initiate scan: {resp.status_code} - {resp.text}")
        sys.exit(1)

    data = resp.json()
    scan_id = data.get("scanId")
    if not scan_id:
        print(f"Unexpected response (no scanId): {json.dumps(data, indent=2)}")
        sys.exit(1)

    print(f"Scan initiated. scanId: {scan_id}")
    return scan_id


def poll_scan_status(token, app_id, instance_id, scan_id, timeout_seconds):
    """
    Poll GET /v1/applications/{appId}/instances/{instanceId}/scans/{scanId}
    until status == "Complete" or timeout.
    """
    headers = get_headers(token)
    url = f"{API_BASE}/v1/applications/{app_id}/instances/{instance_id}/scans/{scan_id}"

    print("Polling for scan status...")
    start_time = time.time()

    while True:
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            if resp.status_code != 200:
                print(f"Failed to get scan status: {resp.status_code} - {resp.text}")
                sys.exit(1)

            data = resp.json()
            status = data.get("status", "Unknown")
            elapsed = int(time.time() - start_time)

            vulns = data.get("vulnerabilities", [])
            vuln_count = len(vulns) if vulns else 0

            print(f"  Status: {status}, Vulnerabilities: {vuln_count}, Elapsed: {elapsed}s")

            if status == "Complete":
                print("Scan completed.")
                return data

            if elapsed > timeout_seconds:
                print(f"Timeout: scan did not complete within {timeout_seconds}s")
                return data

            print("  Waiting 15 seconds...")
            time.sleep(15)

        except requests.exceptions.RequestException as e:
            print(f"Error polling scan status: {e}")
            sys.exit(1)


def get_detections(token, app_id, instance_id):
    """
    Get vulnerability detections.
    GET /v1/applications/{appId}/instances/{instanceId}/detections
    """
    headers = get_headers(token)
    url = (
        f"{API_BASE}/v1/applications/{app_id}/instances/{instance_id}"
        f"/detections?include=metadata&slim=true&excludeDetectionsWithStatus=DISMISSED"
    )

    resp = requests.get(url, headers=headers, timeout=30)
    if resp.status_code != 200:
        print(f"Failed to get detections: {resp.status_code} - {resp.text}")
        return []

    return resp.json()


def print_scan_summary(scan_data):
    """Print a summary of scan results from the scan status response."""
    vulns = scan_data.get("vulnerabilities", [])
    if not vulns:
        print("No vulnerabilities found.")
        return 0

    severity_counts = {}
    total_findings = 0
    for endpoint_vuln in vulns:
        findings = endpoint_vuln.get("scanFindings", [])
        for finding in findings:
            total_findings += 1
            result = finding.get("testResult", {})
            qualifier = result.get("cvssQualifier", "Unknown")
            severity_counts[qualifier] = severity_counts.get(qualifier, 0) + 1

    print(f"\nVulnerability Summary: {total_findings} findings across {len(vulns)} endpoints")
    for severity in ["Critical", "High", "Medium", "Low", "Info", "Unknown"]:
        count = severity_counts.get(severity, 0)
        if count > 0:
            print(f"  {severity}: {count}")

    return total_findings


def main():
    global API_BASE

    print("=" * 60)
    print("APIsec NG - Security Scan")
    print("=" * 60)

    parser = argparse.ArgumentParser(
        description="APIsec NG Security Scan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--application-id", type=str, help="Application ID")
    parser.add_argument("--instance-id", type=str, help="Instance ID")
    parser.add_argument("--application-name", type=str, help="Application name (lookup by name)")
    parser.add_argument("--auth-id", type=str, help="Auth credential ID for authenticated scan")
    parser.add_argument("--timeout", type=int, default=600, help="Scan timeout in seconds (default: 600)")
    parser.add_argument("-r", "--reporting", action="store_true", help="Show detailed detection report")
    parser.add_argument("--hostname", type=str, default=None, help=f"API base URL (default: {API_BASE})")

    args = parser.parse_args()

    if args.hostname:
        API_BASE = args.hostname.rstrip("/")

    token = os.environ.get("APISEC_TOKEN")
    if not token:
        print("ERROR: APISEC_TOKEN environment variable is required.")
        sys.exit(1)

    app_id = args.application_id
    inst_id = args.instance_id

    if not app_id:
        if not args.application_name:
            print("ERROR: --application-id/--instance-id or --application-name is required.")
            sys.exit(1)
        app_id, inst_id = resolve_application(token, args.application_name)

    if not inst_id:
        print("ERROR: --instance-id is required when using --application-id.")
        sys.exit(1)

    print(f"Application ID: {app_id}")
    print(f"Instance ID:    {inst_id}")
    print(f"Timeout:        {args.timeout}s")
    print("=" * 60)

    scan_id = initiate_scan(token, app_id, inst_id, auth_id=args.auth_id)
    scan_data = poll_scan_status(token, app_id, inst_id, scan_id, args.timeout)

    status = scan_data.get("status", "Unknown")
    total_findings = print_scan_summary(scan_data)

    if args.reporting:
        print("\n" + "-" * 60)
        print("Detailed Detection Report")
        print("-" * 60)
        detections = get_detections(token, app_id, inst_id)
        print(json.dumps(detections, indent=2))

    print("\n" + "=" * 60)
    if status == "Complete":
        if total_findings > 0:
            print(f"Scan COMPLETED - {total_findings} vulnerabilities found")
            print("=" * 60)
            sys.exit(1)
        else:
            print("Scan COMPLETED - No vulnerabilities found")
            print("=" * 60)
    else:
        print(f"Scan did not complete (status: {status})")
        print("=" * 60)
        sys.exit(1)


if __name__ == "__main__":
    main()
