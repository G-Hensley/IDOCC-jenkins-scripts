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


def add_instances(token, app_id, app_name, host_urls):
    """
    Create instances for an application using the host URLs from the OAS.
    POST /v1/applications/{appId}/instances/batch
    """
    headers = get_headers(token)
    headers["Content-Type"] = "application/json"
    url = f"{API_BASE}/v1/applications/{app_id}/instances/batch"

    items = []
    for i, host_url in enumerate(host_urls):
        items.append({
            "hostUrl": host_url,
            "instanceName": app_name if len(host_urls) == 1 else f"{app_name}-{i+1}",
        })

    body = {"instanceRequestItems": items}

    print(f"Creating {len(items)} instance(s) for application {app_id}...")
    resp = requests.post(url, headers=headers, json=body, timeout=60)

    if resp.status_code not in (200, 201):
        print(f"Failed to create instances: {resp.status_code} - {resp.text}")
        sys.exit(1)

    print("Instance(s) created successfully.")
    # Fetch the app to show the new instance IDs
    app_resp = requests.get(
        f"{API_BASE}/v1/applications/{app_id}?include=metadata",
        headers=get_headers(token),
        timeout=30,
    )
    if app_resp.status_code == 200:
        app_data = app_resp.json()
        instances = app_data.get("instances", [])
        for inst in instances:
            print(f"  instanceId: {inst.get('instanceId')}, hostUrl: {inst.get('hostUrl')}")


def create_application(token, name, oas_url=None, oas_file=None):
    """
    Create a new application from an OpenAPI spec.
    POST /v1/applications/oas (multipart form)
    """
    form_data = {
        "applicationName": (None, name),
        "origin": (None, "TENANT_PORTAL"),
    }

    file_handle = None
    if oas_url:
        form_data["oasUrl"] = (None, oas_url)
    elif oas_file:
        if not os.path.isfile(oas_file):
            print(f"OAS file not found: {oas_file}")
            sys.exit(1)
        file_handle = open(oas_file, "rb")
        form_data["fileUpload"] = (os.path.basename(oas_file), file_handle)
    else:
        print("ERROR: Either --oas-url or --oas-file is required for --create mode.")
        sys.exit(1)

    post_headers = {"Authorization": f"Bearer {token}"}

    try:
        print(f"Creating application '{name}'...")
        resp = requests.post(
            f"{API_BASE}/v1/applications/oas",
            headers=post_headers,
            files=form_data,
            timeout=60,
        )
    finally:
        if file_handle:
            file_handle.close()

    if resp.status_code not in (200, 201):
        print(f"Failed to create application: {resp.status_code} - {resp.text}")
        sys.exit(1)

    result = resp.json()
    app_id = result.get("applicationId")
    host_urls = result.get("hostUrls", [])

    print(f"Application created successfully.")
    print(f"  applicationId: {app_id}")
    print(f"  hostUrls: {host_urls}")

    # Step 2: Create instances from the host URLs returned by the API
    if app_id and host_urls:
        add_instances(token, app_id, name, host_urls)
    else:
        print("WARNING: No hostUrls returned — instance must be created manually.")

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

    file_handle = None
    if oas_url:
        form_data["oasUrl"] = (None, oas_url)
    elif oas_file:
        if not os.path.isfile(oas_file):
            print(f"OAS file not found: {oas_file}")
            sys.exit(1)
        file_handle = open(oas_file, "rb")
        form_data["fileUpload"] = (os.path.basename(oas_file), file_handle)
    else:
        print("ERROR: Either --oas-url or --oas-file is required for --reload mode.")
        sys.exit(1)

    post_headers = {"Authorization": f"Bearer {token}"}

    url = f"{API_BASE}/v1/applications/{app_id}/instances/{instance_id}/reload-spec"
    print(f"Reloading spec for application {app_id}, instance {instance_id}...")

    try:
        resp = requests.post(url, headers=post_headers, files=form_data, timeout=60)
    finally:
        if file_handle:
            file_handle.close()

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
    global API_BASE

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

    API_BASE = args.hostname.rstrip("/")

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
