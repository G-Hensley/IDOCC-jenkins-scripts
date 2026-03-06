# NG APIsec Jenkins Scripts Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Rewrite the IDOCC customer's APIsec CG Jenkins scripts for the NG platform, using PAT auth and the new Application/Instance/Scan API model.

**Architecture:** Two Python CLI scripts (`ng_apisec_upload.py` for OAS management, `ng_apisec_scan.py` for scan orchestration) wrapped by three Groovy Jenkins shared library functions. Auth is a single PAT token passed via `APISEC_TOKEN` env var. All NG API calls go through `https://api.apisecapps.com/v1/...`.

**Tech Stack:** Python 3.6+ with `requests`, Groovy (Jenkins shared library), NG APIsec REST API.

**Design doc:** `docs/plans/2026-03-05-ng-migration-design.md`

**Reference:** Postman collection at `APIsecNG_INT_Endpoints.postman_collection_v1.2(1).json`

---

## Task 1: Create ng-scripts directory and ng_apisec_upload.py

**Files:**
- Create: `ng-scripts/ng_apisec_upload.py`

**Step 1: Create directory**

```bash
mkdir -p ng-scripts
```

**Step 2: Write ng_apisec_upload.py**

This script handles two modes: creating a new application from an OpenAPI spec, or reloading the spec on an existing application.

```python
#!/usr/bin/env python3
"""
APIsec NG - OpenAPI Upload / Reload Script

Manages OpenAPI specifications on the APIsec NG platform.
Two modes:
  --create: Create a new application from an OAS file or URL
  --reload: Reload the spec on an existing application instance

Requirements:
    - requests (pip install requests)

Environment Variables:
    APISEC_TOKEN - APIsec NG Personal Access Token (PAT)

Examples:
    # Create new app from URL
    python ng_apisec_upload.py --create --name "My API" --oas-url https://example.com/openapi.json

    # Create new app from file
    python ng_apisec_upload.py --create --name "My API" --oas-file ./openapi.yml

    # Reload spec on existing app by IDs
    python ng_apisec_upload.py --reload --application-id <uuid> --instance-id <uuid> --oas-url https://...

    # Reload spec on existing app by name
    python ng_apisec_upload.py --reload --application-name "My API" --oas-file ./openapi.yml
"""

import argparse
import json
import os
import sys

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
    }


def resolve_application(token, application_name):
    """
    Look up an application by name via GET /v1/applications.
    Returns (applicationId, instanceId) for the first instance found.
    Paginates using nextToken.
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


def create_application(token, name, oas_url=None, oas_file=None):
    """
    Create a new application from an OpenAPI spec.
    POST /v1/applications/oas (multipart form)
    """
    headers = get_headers(token)
    form_data = {
        "applicationName": (None, name),
        "origin": (None, "TENANT_PORTAL"),
    }

    if oas_url:
        form_data["oasUrl"] = (None, oas_url)
    elif oas_file:
        if not os.path.isfile(oas_file):
            print(f"OAS file not found: {oas_file}")
            sys.exit(1)
        form_data["fileUpload"] = (os.path.basename(oas_file), open(oas_file, "rb"))
    else:
        print("ERROR: Either --oas-url or --oas-file is required for --create mode.")
        sys.exit(1)

    # requests needs files= for multipart, not data=
    # Remove Accept header to let requests set multipart content-type
    post_headers = {"Authorization": f"Bearer {token}"}

    print(f"Creating application '{name}'...")
    resp = requests.post(
        f"{API_BASE}/v1/applications/oas",
        headers=post_headers,
        files=form_data,
        timeout=60,
    )

    if resp.status_code not in (200, 201):
        print(f"Failed to create application: {resp.status_code} - {resp.text}")
        sys.exit(1)

    result = resp.json()
    app_id = result.get("applicationId")
    host_urls = result.get("hostUrls", [])

    print(f"Application created successfully.")
    print(f"  applicationId: {app_id}")
    print(f"  hostUrls: {host_urls}")
    print(json.dumps(result, indent=2))

    return result


def reload_spec(token, app_id, instance_id, oas_url=None, oas_file=None):
    """
    Reload the OpenAPI spec on an existing application instance.
    POST /v1/applications/{appId}/instances/{instanceId}/reload-spec (multipart form)
    """
    form_data = {
        "overwriteVal": (None, "true"),
        "overwriteEndpointConfig": (None, "true"),
        "deleteEndpoints": (None, "true"),
    }

    if oas_url:
        form_data["oasUrl"] = (None, oas_url)
    elif oas_file:
        if not os.path.isfile(oas_file):
            print(f"OAS file not found: {oas_file}")
            sys.exit(1)
        form_data["fileUpload"] = (os.path.basename(oas_file), open(oas_file, "rb"))
    else:
        print("ERROR: Either --oas-url or --oas-file is required for --reload mode.")
        sys.exit(1)

    post_headers = {"Authorization": f"Bearer {token}"}

    url = f"{API_BASE}/v1/applications/{app_id}/instances/{instance_id}/reload-spec"
    print(f"Reloading spec for application {app_id}, instance {instance_id}...")

    resp = requests.post(url, headers=post_headers, files=form_data, timeout=60)

    if resp.status_code not in (200, 201):
        print(f"Failed to reload spec: {resp.status_code} - {resp.text}")
        sys.exit(1)

    print("Spec reloaded successfully.")
    try:
        result = resp.json()
        print(json.dumps(result, indent=2))
        return result
    except ValueError:
        return {}


def main():
    print("=" * 60)
    print("APIsec NG - OpenAPI Upload")
    print("=" * 60)

    parser = argparse.ArgumentParser(
        description="APIsec NG OpenAPI Upload / Reload",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--create", action="store_true", help="Create a new application from OAS")
    mode_group.add_argument("--reload", action="store_true", help="Reload spec on existing application")

    parser.add_argument("--name", type=str, help="Application name (required for --create)")
    parser.add_argument("--oas-url", type=str, help="URL to OpenAPI spec")
    parser.add_argument("--oas-file", type=str, help="Path to OpenAPI spec file")
    parser.add_argument("--application-id", type=str, help="Application ID (for --reload)")
    parser.add_argument("--instance-id", type=str, help="Instance ID (for --reload)")
    parser.add_argument("--application-name", type=str, help="Application name for lookup (for --reload)")
    parser.add_argument("--hostname", type=str, default=API_BASE, help=f"API base URL (default: {API_BASE})")

    args = parser.parse_args()

    # Allow overriding API base
    global API_BASE
    API_BASE = args.hostname.rstrip("/")

    # Get token
    token = os.environ.get("APISEC_TOKEN")
    if not token:
        print("ERROR: APISEC_TOKEN environment variable is required.")
        sys.exit(1)

    if args.create:
        if not args.name:
            print("ERROR: --name is required for --create mode.")
            sys.exit(1)
        create_application(token, args.name, oas_url=args.oas_url, oas_file=args.oas_file)

    elif args.reload:
        app_id = args.application_id
        inst_id = args.instance_id

        if not app_id:
            lookup_name = args.application_name or args.name
            if not lookup_name:
                print("ERROR: --application-id/--instance-id or --application-name is required for --reload.")
                sys.exit(1)
            app_id, inst_id = resolve_application(token, lookup_name)

        if not inst_id:
            print("ERROR: --instance-id is required when using --application-id.")
            sys.exit(1)

        reload_spec(token, app_id, inst_id, oas_url=args.oas_url, oas_file=args.oas_file)

    print("=" * 60)
    print("APIsec NG - OpenAPI Upload Complete")
    print("=" * 60)


if __name__ == "__main__":
    main()
```

**Step 3: Verify script syntax**

Run: `python3 -c "import py_compile; py_compile.compile('ng-scripts/ng_apisec_upload.py', doraise=True)"`
Expected: No output (clean compile)

**Step 4: Commit**

```bash
git add ng-scripts/ng_apisec_upload.py
git commit -m "feat: add ng_apisec_upload.py for NG OpenAPI management"
```

---

## Task 2: Create ng_apisec_scan.py

**Files:**
- Create: `ng-scripts/ng_apisec_scan.py`

**Step 1: Write ng_apisec_scan.py**

This script triggers a scan, polls for completion, and optionally reports detections.

```python
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

    # Count by severity
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
    parser.add_argument("--hostname", type=str, default=API_BASE, help=f"API base URL (default: {API_BASE})")

    args = parser.parse_args()

    global API_BASE
    API_BASE = args.hostname.rstrip("/")

    # Get token
    token = os.environ.get("APISEC_TOKEN")
    if not token:
        print("ERROR: APISEC_TOKEN environment variable is required.")
        sys.exit(1)

    # Resolve application
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

    # Initiate scan
    scan_id = initiate_scan(token, app_id, inst_id, auth_id=args.auth_id)

    # Poll for completion
    scan_data = poll_scan_status(token, app_id, inst_id, scan_id, args.timeout)

    # Print summary from scan response
    status = scan_data.get("status", "Unknown")
    total_findings = print_scan_summary(scan_data)

    # Detailed report
    if args.reporting:
        print("\n" + "-" * 60)
        print("Detailed Detection Report")
        print("-" * 60)
        detections = get_detections(token, app_id, inst_id)
        print(json.dumps(detections, indent=2))

    # Final summary
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
```

**Step 2: Verify script syntax**

Run: `python3 -c "import py_compile; py_compile.compile('ng-scripts/ng_apisec_scan.py', doraise=True)"`
Expected: No output (clean compile)

**Step 3: Commit**

```bash
git add ng-scripts/ng_apisec_scan.py
git commit -m "feat: add ng_apisec_scan.py for NG security scanning"
```

---

## Task 3: Create apisecUploadOpenAPI.groovy for NG

**Files:**
- Create: `ng-scripts/apisecUploadOpenAPI.groovy`

**Step 1: Write the Groovy wrapper**

This mirrors the CG version but uses the NG Python script and PAT auth.

```groovy
#!/usr/bin/env groovy

/**
 * APISec NG - OpenAPI Upload
 *
 * Generates an OpenAPI specification (if needed) and uploads it to APIsec NG.
 * Supports creating new applications or reloading specs on existing ones.
 *
 * @param config Map with the following options:
 *   - applicationName (required unless applicationId provided): Application name
 *   - applicationId (optional): Existing application ID (for reload)
 *   - instanceId (optional): Existing instance ID (for reload, required with applicationId)
 *   - mode (optional, default: 'reload'): 'create' or 'reload'
 *   - openapiFile (optional): Path to pre-generated OpenAPI file
 *   - oasUrl (optional): URL to OpenAPI spec
 *   - generateScript (optional, default: 'generate:swagger'): npm script to generate OpenAPI
 *   - container (optional, default: 'nodejs'): Container for npm operations
 *   - pythonContainer (optional, default: 'python'): Container for Python script execution
 *   - token (optional): APIsec NG PAT (falls back to APISEC_TOKEN env var)
 *   - hostname (optional, default: 'https://api.apisecapps.com'): API base URL
 *   - skipIfNoScript (optional, default: true): Skip silently if no generate script
 *   - openapiPattern (optional, default: '*-openapi.yml'): Pattern to find generated OpenAPI file
 *   - npmInstallArgs (optional, default: '--legacy-peer-deps --no-package-lock'): npm install args
 *   - scriptPath (optional): Custom path to ng_apisec_upload.py script
 */
def call(Map config = [:]) {
    if (!config.applicationName && !config.applicationId) {
        error "apisecUploadOpenAPI: 'applicationName' or 'applicationId' is required"
    }

    def applicationName = config.applicationName ?: null
    def applicationId = config.applicationId ?: null
    def instanceId = config.instanceId ?: null
    def mode = config.mode ?: 'reload'
    def openapiFile = config.openapiFile ?: null
    def oasUrl = config.oasUrl ?: null
    def generateScript = config.generateScript ?: 'generate:swagger'
    def container = config.container ?: 'nodejs'
    def pythonContainer = config.pythonContainer ?: 'python'
    def token = config.token ?: null
    def hostname = config.hostname ?: 'https://api.apisecapps.com'
    def skipIfNoScript = config.skipIfNoScript != null ? config.skipIfNoScript : true
    def openapiPattern = config.openapiPattern ?: '*-openapi.yml'
    def npmInstallArgs = config.npmInstallArgs ?: '--legacy-peer-deps --no-package-lock'
    def scriptPath = config.scriptPath ?: null

    echo "========================================"
    echo "APIsec NG - OpenAPI Upload"
    echo "========================================"
    echo "Application: ${applicationName ?: applicationId}"
    echo "Mode: ${mode}"
    echo "API Host: ${hostname}"

    // If no pre-existing OpenAPI file or URL, try to generate
    if (!openapiFile && !oasUrl) {
        echo "No openapiFile or oasUrl provided - checking for ${generateScript} script"

        def hasSwaggerScript = false
        if (fileExists('package.json')) {
            def packageJson = readJSON file: 'package.json'
            hasSwaggerScript = packageJson?.scripts?.containsKey(generateScript)
        } else {
            echo "SKIP: No package.json found"
            if (skipIfNoScript) return false
            else error "No package.json found and skipIfNoScript is false"
        }

        if (!hasSwaggerScript) {
            echo "SKIP: No '${generateScript}' script in package.json"
            if (skipIfNoScript) return false
            else error "No ${generateScript} script found and skipIfNoScript is false"
        }

        echo "Generating OpenAPI specification..."
        container(container) {
            sh """
                set -e
                npm install ${npmInstallArgs}
                npm run ${generateScript}
                OPENAPI_FILE=\$(find . -maxdepth 1 -name "${openapiPattern}" | head -1)
                if [ -n "\$OPENAPI_FILE" ] && [ -f "\$OPENAPI_FILE" ]; then
                    echo "OpenAPI spec generated: \$OPENAPI_FILE"
                else
                    echo "ERROR: Failed to generate OpenAPI spec"
                    exit 1
                fi
            """
        }

        openapiFile = sh(
            script: "find . -maxdepth 1 -name '${openapiPattern}' | head -1 | sed 's|^\\./||'",
            returnStdout: true
        ).trim()

        if (!openapiFile) {
            error "Failed to find generated OpenAPI file matching: ${openapiPattern}"
        }
    }

    // Determine script path
    def uploadScript = scriptPath
    if (!uploadScript) {
        def possiblePaths = [
            "${WORKSPACE}/resources/scripts/ng_apisec_upload.py",
            "${env.LIBRARY_PATH}/resources/scripts/ng_apisec_upload.py",
            "ng_apisec_upload.py"
        ]
        for (path in possiblePaths) {
            if (fileExists(path)) {
                uploadScript = path
                break
            }
        }
        if (!uploadScript || !fileExists(uploadScript)) {
            echo "Extracting ng_apisec_upload.py from library resources..."
            def scriptContent = libraryResource('scripts/ng_apisec_upload.py')
            writeFile file: 'ng_apisec_upload.py', text: scriptContent
            uploadScript = 'ng_apisec_upload.py'
        }
    }

    // Build command
    def envVars = []
    if (token) {
        envVars.add("APISEC_TOKEN=${token}")
    }

    def cmd = "python3 ${uploadScript}"

    if (mode == 'create') {
        cmd += " --create --name '${applicationName}'"
    } else {
        cmd += " --reload"
        if (applicationId) {
            cmd += " --application-id ${applicationId} --instance-id ${instanceId}"
        } else {
            cmd += " --application-name '${applicationName}'"
        }
    }

    if (oasUrl) {
        cmd += " --oas-url '${oasUrl}'"
    } else if (openapiFile) {
        cmd += " --oas-file ${openapiFile}"
    }

    cmd += " --hostname ${hostname}"

    container(pythonContainer) {
        withEnv(envVars) {
            sh cmd
        }
    }

    echo "========================================"
    echo "APIsec NG - OpenAPI Upload Complete"
    echo "========================================"
    return true
}
```

**Step 2: Commit**

```bash
git add ng-scripts/apisecUploadOpenAPI.groovy
git commit -m "feat: add apisecUploadOpenAPI.groovy Jenkins wrapper for NG"
```

---

## Task 4: Create apisecScan.groovy for NG

**Files:**
- Create: `ng-scripts/apisecScan.groovy`

**Step 1: Write the Groovy wrapper**

```groovy
#!/usr/bin/env groovy

/**
 * APISec NG - Security Scan
 *
 * Runs an APIsec NG security scan on an application instance.
 *
 * @param config Map with the following options:
 *   - applicationName (required unless applicationId provided): Application name
 *   - applicationId (optional): Application ID
 *   - instanceId (optional): Instance ID (required with applicationId)
 *   - container (optional, default: 'python'): Container for Python execution
 *   - token (optional): APIsec NG PAT (falls back to APISEC_TOKEN env var)
 *   - authId (optional): Auth credential ID for authenticated scans
 *   - hostname (optional, default: 'https://api.apisecapps.com'): API base URL
 *   - timeout (optional, default: 600): Scan timeout in seconds
 *   - failOnError (optional, default: false): Fail pipeline if vulnerabilities found
 *   - showReport (optional, default: false): Show detailed detection report
 *   - scriptPath (optional): Custom path to ng_apisec_scan.py script
 */
def call(Map config = [:]) {
    if (!config.applicationName && !config.applicationId) {
        error "apisecScan: 'applicationName' or 'applicationId' is required"
    }

    def applicationName = config.applicationName ?: null
    def applicationId = config.applicationId ?: null
    def instanceId = config.instanceId ?: null
    def container = config.container ?: 'python'
    def token = config.token ?: null
    def authId = config.authId ?: null
    def hostname = config.hostname ?: 'https://api.apisecapps.com'
    def timeout = config.timeout ?: 600
    def failOnError = config.failOnError ?: false
    def showReport = config.showReport ?: false
    def scriptPath = config.scriptPath ?: null

    echo "========================================"
    echo "APIsec NG - Security Scan"
    echo "========================================"
    echo "Application: ${applicationName ?: applicationId}"
    echo "API Host: ${hostname}"
    echo "Timeout: ${timeout}s"
    echo "Fail on Error: ${failOnError}"
    echo "========================================"

    // Determine script path
    def scanScript = scriptPath
    if (!scanScript) {
        def possiblePaths = [
            "${WORKSPACE}/resources/scripts/ng_apisec_scan.py",
            "${env.LIBRARY_PATH}/resources/scripts/ng_apisec_scan.py",
            "ng_apisec_scan.py"
        ]
        for (path in possiblePaths) {
            if (fileExists(path)) {
                scanScript = path
                break
            }
        }
        if (!scanScript || !fileExists(scanScript)) {
            echo "Extracting ng_apisec_scan.py from library resources..."
            def scriptContent = libraryResource('scripts/ng_apisec_scan.py')
            writeFile file: 'ng_apisec_scan.py', text: scriptContent
            scanScript = 'ng_apisec_scan.py'
        }
    }

    def envVars = []
    if (token) {
        envVars.add("APISEC_TOKEN=${token}")
    }

    def cmd = "python3 ${scanScript}"
    if (applicationId) {
        cmd += " --application-id ${applicationId} --instance-id ${instanceId}"
    } else {
        cmd += " --application-name '${applicationName}'"
    }
    if (authId) {
        cmd += " --auth-id ${authId}"
    }
    cmd += " --timeout ${timeout}"
    cmd += " --hostname ${hostname}"
    if (showReport) {
        cmd += " --reporting"
    }

    def scanPassed = true

    container(container) {
        withEnv(envVars) {
            def exitCode = sh(script: cmd, returnStatus: true)
            if (exitCode != 0) {
                scanPassed = false
                if (failOnError) {
                    error "APIsec NG security scan failed or found vulnerabilities"
                } else {
                    echo "WARNING: APIsec NG scan found issues (exit code: ${exitCode})"
                }
            }
        }
    }

    echo "========================================"
    if (scanPassed) {
        echo "APIsec NG Security Scan - PASSED"
    } else {
        echo "APIsec NG Security Scan - ISSUES FOUND"
    }
    echo "========================================"

    return scanPassed
}
```

**Step 2: Commit**

```bash
git add ng-scripts/apisecScan.groovy
git commit -m "feat: add apisecScan.groovy Jenkins wrapper for NG"
```

---

## Task 5: Create apisecComplete.groovy for NG

**Files:**
- Create: `ng-scripts/apisecComplete.groovy`

**Step 1: Write the orchestrator**

```groovy
#!/usr/bin/env groovy

/**
 * APISec NG Complete - Full API Security Testing Workflow
 *
 * Orchestrates the complete APIsec NG workflow: OpenAPI upload + security scan.
 *
 * @param config Map with the following options:
 *   - applicationName (required unless applicationId provided): Application name
 *   - applicationId (optional): Application ID
 *   - instanceId (optional): Instance ID
 *
 *   Upload Options:
 *   - enableUpload (optional, default: true): Enable OpenAPI upload step
 *   - mode (optional, default: 'reload'): 'create' or 'reload'
 *   - openapiFile (optional): Path to OpenAPI file
 *   - oasUrl (optional): URL to OpenAPI spec
 *   - generateScript (optional, default: 'generate:swagger'): npm generate script
 *   - nodejsContainer (optional, default: 'nodejs'): Container for npm operations
 *   - openapiPattern (optional, default: '*-openapi.yml'): Pattern for generated file
 *   - npmInstallArgs (optional): npm install arguments
 *
 *   Scan Options:
 *   - enableScan (optional, default: true): Enable scan step
 *   - authId (optional): Auth credential ID for authenticated scans
 *   - timeout (optional, default: 600): Scan timeout in seconds
 *   - failOnError (optional, default: false): Fail pipeline on vulnerabilities
 *   - showReport (optional, default: false): Show detailed report
 *
 *   Common Options:
 *   - pythonContainer (optional, default: 'python'): Container for Python execution
 *   - token (optional): APIsec NG PAT (falls back to APISEC_TOKEN env var)
 *   - hostname (optional, default: 'https://api.apisecapps.com'): API base URL
 *   - scanOnlyForEnv (optional, default: ['dev']): Envs where scan runs
 *   - currentEnv (optional): Current environment name
 */
def call(Map config = [:]) {
    if (!config.applicationName && !config.applicationId) {
        error "apisecComplete: 'applicationName' or 'applicationId' is required"
    }

    def applicationName = config.applicationName ?: null
    def applicationId = config.applicationId ?: null
    def instanceId = config.instanceId ?: null

    def enableUpload = config.enableUpload != null ? config.enableUpload : true
    def mode = config.mode ?: 'reload'
    def openapiFile = config.openapiFile ?: null
    def oasUrl = config.oasUrl ?: null
    def generateScript = config.generateScript ?: 'generate:swagger'
    def nodejsContainer = config.nodejsContainer ?: 'nodejs'
    def openapiPattern = config.openapiPattern ?: '*-openapi.yml'
    def npmInstallArgs = config.npmInstallArgs ?: '--legacy-peer-deps --no-package-lock'

    def enableScan = config.enableScan != null ? config.enableScan : true
    def authId = config.authId ?: null
    def timeout = config.timeout ?: 600
    def failOnError = config.failOnError ?: false
    def showReport = config.showReport ?: false

    def pythonContainer = config.pythonContainer ?: 'python'
    def token = config.token ?: null
    def hostname = config.hostname ?: 'https://api.apisecapps.com'
    def scanOnlyForEnv = config.scanOnlyForEnv ?: ['dev']
    def currentEnv = config.currentEnv ?: env.ENV ?: env.ENVIRONMENT ?: null

    def results = [
        uploadSuccess: false,
        scanSuccess: false,
        uploadSkipped: false,
        scanSkipped: false
    ]

    echo "========================================"
    echo "APIsec NG Complete Security Testing"
    echo "========================================"
    echo "Application: ${applicationName ?: applicationId}"
    echo "API Host: ${hostname}"
    echo "Current Environment: ${currentEnv ?: 'not specified'}"
    echo "Upload Enabled: ${enableUpload}"
    echo "Scan Enabled: ${enableScan}"
    if (enableScan) {
        echo "Scan Only For: ${scanOnlyForEnv.join(', ')}"
    }
    echo "========================================"

    // Step 1: Upload OpenAPI spec
    if (enableUpload) {
        echo "\n--- Step 1: Upload OpenAPI Specification ---"
        try {
            results.uploadSuccess = apisecUploadOpenAPI([
                applicationName: applicationName,
                applicationId: applicationId,
                instanceId: instanceId,
                mode: mode,
                openapiFile: openapiFile,
                oasUrl: oasUrl,
                generateScript: generateScript,
                container: nodejsContainer,
                pythonContainer: pythonContainer,
                token: token,
                hostname: hostname,
                skipIfNoScript: true,
                openapiPattern: openapiPattern,
                npmInstallArgs: npmInstallArgs
            ])
            if (!results.uploadSuccess) {
                results.uploadSkipped = true
            }
        } catch (Exception e) {
            echo "OpenAPI upload failed: ${e.message}"
            if (failOnError) throw e
        }
    } else {
        echo "\n--- Step 1: Upload (DISABLED) ---"
        results.uploadSkipped = true
    }

    // Step 2: Security Scan
    if (enableScan) {
        echo "\n--- Step 2: Security Scan ---"

        def shouldRunScan = true
        if (currentEnv && scanOnlyForEnv) {
            shouldRunScan = scanOnlyForEnv.contains(currentEnv)
            if (!shouldRunScan) {
                echo "SKIP: Scan only for environments: ${scanOnlyForEnv.join(', ')}"
                results.scanSkipped = true
            }
        }

        if (shouldRunScan) {
            try {
                results.scanSuccess = apisecScan([
                    applicationName: applicationName,
                    applicationId: applicationId,
                    instanceId: instanceId,
                    container: pythonContainer,
                    token: token,
                    authId: authId,
                    hostname: hostname,
                    timeout: timeout,
                    failOnError: failOnError,
                    showReport: showReport
                ])
            } catch (Exception e) {
                echo "Scan failed: ${e.message}"
                if (failOnError) throw e
            }
        }
    } else {
        echo "\n--- Step 2: Security Scan (DISABLED) ---"
        results.scanSkipped = true
    }

    // Summary
    echo "\n========================================"
    echo "APIsec NG Complete - Summary"
    echo "========================================"
    echo "Upload: ${results.uploadSkipped ? 'SKIPPED' : (results.uploadSuccess ? 'SUCCESS' : 'FAILED')}"
    echo "Scan:   ${results.scanSkipped ? 'SKIPPED' : (results.scanSuccess ? 'PASSED' : 'ISSUES FOUND')}"
    echo "========================================"

    return results
}
```

**Step 2: Commit**

```bash
git add ng-scripts/apisecComplete.groovy
git commit -m "feat: add apisecComplete.groovy Jenkins orchestrator for NG"
```

---

## Task 6: Manual integration testing checklist

This task has no code. Verify the scripts work against the NG platform:

1. **Upload - Create mode:** `APISEC_TOKEN=<pat> python3 ng-scripts/ng_apisec_upload.py --create --name "Test App" --oas-url https://raw.githubusercontent.com/apisec-inc/crAPI/refs/heads/main/crapi_oas_test.json`
2. **Upload - Reload mode:** `APISEC_TOKEN=<pat> python3 ng-scripts/ng_apisec_upload.py --reload --application-name "Test App" --oas-url https://raw.githubusercontent.com/apisec-inc/crAPI/refs/heads/main/crapi_oas_test.json`
3. **Scan by name:** `APISEC_TOKEN=<pat> python3 ng-scripts/ng_apisec_scan.py --application-name "Test App" --timeout 120`
4. **Scan by IDs:** `APISEC_TOKEN=<pat> python3 ng-scripts/ng_apisec_scan.py --application-id <id> --instance-id <id> --reporting`
5. **Error cases:** Missing token, invalid app name, bad IDs
