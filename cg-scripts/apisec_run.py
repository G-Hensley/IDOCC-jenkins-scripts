#!/usr/bin/env python3
"""
APISec Security Scan Script

Triggers and monitors an APISec security scan for a specified project.
This script authenticates with APISec, starts a scan job, polls for status,
and reports the final results.

Requirements:
    - requests (pip install requests)

Usage:
    python apisec_run.py -p <project_name>

Environment Variables:
    APISEC_USERNAME - APISec username (alternative to --username)
    APISEC_PASSWORD - APISec password/API key (alternative to --password)

Example:
    # Using environment variables
    export APISEC_USERNAME="user@example.com"
    export APISEC_PASSWORD="your-api-key"
    python apisec_run.py -p my-api-project

    # Using command line arguments
    python apisec_run.py -p my-api-project \
        --username user@example.com --password your-api-key

    # With custom profile and timeout
    python apisec_run.py -p my-api-project --profile Master --timeout 900
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


def get_token(host, username, password):
    """
    Authenticate with APISec and return a JWT token.

    Args:
        host: APISec hostname (e.g., https://cloud.apisec.ai)
        username: APISec username
        password: APISec password/API key

    Returns:
        JWT token string

    Raises:
        SystemExit: If authentication fails
    """
    data = {
        "username": username,
        "password": password
    }
    headers = {
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(host + '/login', data=json.dumps(data), headers=headers, timeout=30)
        if response.status_code == 200:
            token_data = json.loads(response.text)
            return token_data['token']
        else:
            print(f"Authentication Error: {response.status_code} - {response.text}")
            sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"Authentication Error: Failed to connect to APISec - {e}")
        sys.exit(1)


def run_job(host, token, project, profile):
    """
    Start an APISec security scan job.

    Args:
        host: APISec hostname
        token: JWT token
        project: APISec project name
        profile: Scan profile name (e.g., 'Master')

    Returns:
        Job data dictionary containing job ID

    Raises:
        SystemExit: If job fails to start
    """
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }

    print(f'Starting APISec scan on project: {project}')
    print(f'Using profile: {profile}')

    try:
        response = requests.post(
            host + f'/api/v1/runs/project/{project}?jobName={profile}&region=&categories=&emailReport=&reportType',
            headers=headers,
            timeout=60
        )

        if response.status_code not in (200, 201):
            print(f"Failed to start scan: {response.status_code} - {response.text}")
            sys.exit(1)

        data = json.loads(response.text)
        return data

    except requests.exceptions.RequestException as e:
        print(f"Failed to start scan: {e}")
        sys.exit(1)


def get_job_status(host, token, job_id, status_timeout):
    """
    Poll APISec for scan job status until completion or timeout.

    Args:
        host: APISec hostname
        token: JWT token
        job_id: APISec job ID to monitor
        status_timeout: Maximum seconds to wait for job completion

    Returns:
        Final job status data dictionary

    Raises:
        SystemExit: If API calls fail
    """
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }

    print('Polling APISec for status updates...')
    start_time = time.time()
    data = None

    while True:
        try:
            response = requests.get(host + f'/api/v1/runs/{job_id}', headers=headers, timeout=30)
            if response.status_code != 200:
                print(f"Failed to get job status: {response.status_code} - {response.text}")
                sys.exit(1)

            data = json.loads(response.text)
            status = data['data']['task']['status']
            run_time = time.time() - start_time

            if status == 'COMPLETED':
                break
            elif run_time > status_timeout:
                print(f'Timeout: Giving up after {status_timeout} seconds')
                break

            total_tests = data['data']['task'].get('totalTests', 0)
            failed_tests = data['data']['task'].get('failedTests', 0)
            run_id = data['data'].get('runId', 'N/A')

            print(f'Status: {status}, Total Tests: {total_tests}, Failed: {failed_tests}, '
                  f'Run ID: {run_id}, Elapsed: {int(run_time)}s')

            print('Waiting 15 seconds before next poll...')
            time.sleep(15)

        except requests.exceptions.RequestException as e:
            print(f"Error polling job status: {e}")
            sys.exit(1)
        except KeyError as e:
            print(f"Unexpected response format: missing key {e}")
            if data:
                print(f"Response data: {json.dumps(data, indent=2)}")
            sys.exit(1)

    if data:
        try:
            cicd_status = data['data']['ciCdStatus'].split(':')[7]
            print(f'\nAPISec status page: {host}{cicd_status}')
        except (KeyError, IndexError):
            pass

    return data


def report_summary(run_id, env_id, token, host):
    """
    Get vulnerability summary report for a completed scan.

    Args:
        run_id: APISec run ID
        env_id: Environment ID
        token: JWT token
        host: APISec hostname

    Returns:
        Vulnerability summary data or empty list on failure
    """
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }

    try:
        response = requests.get(
            f'{host}/api/v1/projects/{run_id}/auto-suggestions/category-counts/active?envId={env_id}',
            headers=headers,
            timeout=30
        )
        if response.status_code == 200:
            return json.loads(response.text)
        else:
            print(f"Failed to get vulnerability summary: {response.status_code} - {response.text}")
            return []
    except requests.exceptions.RequestException as e:
        print(f"Failed to get vulnerability summary: {e}")
        return []


def main():
    """Main entry point for the APISec security scan script."""
    print("=" * 60)
    print("APISec Security Scan")
    print("=" * 60)

    parser = argparse.ArgumentParser(
        description='Run APISec security scan on a project',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Using environment variables for credentials
  export APISEC_USERNAME="user@example.com"
  export APISEC_PASSWORD="your-api-key"
  python apisec_run.py -p my-api

  # Using command line arguments
  python apisec_run.py -p my-api --username user@example.com --password your-api-key

  # With custom profile and extended timeout
  python apisec_run.py -p my-api --profile Master --timeout 900 --reporting
        """
    )
    parser.add_argument(
        '-p', '--project',
        type=str,
        required=True,
        help='APISec project name (REQUIRED)'
    )
    parser.add_argument(
        '--username',
        default=None,
        type=str,
        help='APISec username (or use APISEC_USERNAME env var)'
    )
    parser.add_argument(
        '--password',
        default=None,
        type=str,
        help='APISec password (or use APISEC_PASSWORD env var)'
    )
    parser.add_argument(
        '--profile',
        default="Master",
        type=str,
        help='APISec scan profile (default: Master)'
    )
    parser.add_argument(
        '--hostname',
        default="https://cloud.apisec.ai",
        type=str,
        help='APISec hostname (default: https://cloud.apisec.ai)'
    )
    parser.add_argument(
        '-r', '--reporting',
        action='store_true',
        default=False,
        help='Display detailed vulnerability report at the end'
    )
    parser.add_argument(
        '-t', '--timeout',
        default=600,
        type=int,
        help='Scan timeout in seconds (default: 600)'
    )

    args = parser.parse_args()

    # Get credentials from args or environment variables
    # Support both APISEC_* and apisec_* for flexibility
    if args.username is None:
        args.username = os.environ.get("APISEC_USERNAME") or os.environ.get("apisec_username")
        if not args.username:
            print('ERROR: You must provide "--username" OR set APISEC_USERNAME environment variable')
            sys.exit(1)

    if args.password is None:
        args.password = os.environ.get("APISEC_PASSWORD") or os.environ.get("apisec_password")
        if not args.password:
            print('ERROR: You must provide "--password" OR set APISEC_PASSWORD environment variable')
            sys.exit(1)

    print(f"Project: {args.project}")
    print(f"Profile: {args.profile}")
    print(f"Hostname: {args.hostname}")
    print(f"Timeout: {args.timeout}s")
    print("=" * 60)

    print("\nAuthenticating to APISec...")
    token = get_token(args.hostname, args.username, args.password)
    print("Authentication successful.\n")

    job_data = run_job(args.hostname, token, args.project, args.profile)

    if 'data' not in job_data or 'id' not in job_data.get('data', {}):
        print("Failed to start scan: unexpected response format")
        print(f"Response: {json.dumps(job_data, indent=2)}")
        sys.exit(1)

    job_id = job_data['data']['id']
    print(f"Scan job started with ID: {job_id}\n")

    job_status = get_job_status(args.hostname, token, job_id, args.timeout)

    if args.reporting and job_status:
        try:
            project_id = job_status['data']['job']['id']
            env_id = job_status['data']['job']['environment']['id']
            print("\nFetching vulnerability summary...")
            vulnerabilities = report_summary(project_id, env_id, token, args.hostname)
            print(json.dumps(vulnerabilities, indent=2))
        except KeyError as e:
            print(f"Could not fetch vulnerability summary: missing key {e}")

    print("\n" + "=" * 60)
    if job_status and job_status.get('data', {}).get('task', {}).get('status') == 'COMPLETED':
        failed_tests = job_status.get('data', {}).get('task', {}).get('failedTests', 0)
        total_tests = job_status.get('data', {}).get('task', {}).get('totalTests', 0)
        print(f"Scan completed: {total_tests} tests run, {failed_tests} failed")
        if failed_tests > 0:
            print("WARNING: Some security tests failed!")
        print("=" * 60)
    else:
        print("Scan did not complete within timeout period")
        print("=" * 60)
        sys.exit(1)


if __name__ == "__main__":
    main()
