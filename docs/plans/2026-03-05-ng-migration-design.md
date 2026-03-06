# NG APIsec Jenkins Scripts Migration Design

**Date:** 2026-03-05
**Status:** Approved
**Context:** IDOCC customer migrating from APIsec CG (cloud.apisec.ai) to NG (apisecapps.com)

## Background

The customer uses Jenkins pipeline scripts to automate API security testing via APIsec's CG platform. The CG platform is being retired in favor of NG. The API surface, authentication model, and data model have all changed significantly.

## CG Scripts Inventory

| File | Type | Purpose |
|------|------|---------|
| SoftramsLatest.sh | Bash | Multi-env Okta OAuth2 -> JWT auth for CMS 4innovation (dev/test/impl) |
| SoftramsAuthLatest.sh | Bash | Same auth flow, hardcoded to impl |
| apisecRun.txt | Python | Original scan runner (auth, trigger, poll, report) |
| apisec_run.txt / .py | Python | Polished scan runner with better error handling |
| devops_apisec_upload_openapi.txt | Python | Parse OpenAPI -> extract endpoints -> batch upload to APIsec |
| apisecUploadOpenAPI.groovy | Groovy | Jenkins shared lib: generate OpenAPI + upload via Python |
| apisecScan.groovy | Groovy | Jenkins shared lib: run security scan via Python |
| apisecComplete.groovy | Groovy | Jenkins shared lib: orchestrate upload + scan with env filtering |

## Key Platform Differences

### Authentication

- **CG:** `POST /login` with username/password -> JWT token. Some deployments also use multi-step Okta OAuth2 flow (the Softrams bash scripts).
- **NG:** AWS Cognito SRP for browser auth, but **Personal Access Tokens (PAT)** for CI/CD. PAT is a self-contained JWT with scoped permissions, used as `Authorization: Bearer <PAT>`.
- **Impact:** All auth scripts (bash + `get_token()`) are eliminated. Single `APISEC_TOKEN` env var replaces username + password.

### API Base URL

- **CG:** `https://cloud.apisec.ai` (per-deployment)
- **NG:** `https://api.apisecapps.com` (shared, tenant isolation via token's `custom:tenantId`)

### Data Model

- **CG:** Flat: Project -> Endpoints, Project -> Runs
- **NG:** Hierarchical: Application -> Instance -> Endpoints/Scans/Detections
- **Impact:** All API calls now require both `applicationId` and `instanceId`.

### API Endpoints

| CG Endpoint | NG Endpoint |
|-------------|-------------|
| `POST /login` | None (PAT) |
| `POST /api/v1/runs/project/{name}` | `POST /v1/applications/{appId}/instances/{instId}/scan` |
| `GET /api/v1/runs/{jobId}` | `GET /v1/applications/{appId}/instances/{instId}/scans/{scanId}` |
| `GET /api/v1/projects` | `GET /v1/applications?include=metadata` |
| `POST /api/v1/endpoint/project/{id}` | `POST /v1/applications/{appId}/instances/{instId}/add-endpoints` |
| N/A | `POST /v1/applications/oas` (create app from OpenAPI) |
| N/A | `POST /v1/applications/{id}/instances/{instId}/reload-spec` |
| `GET .../auto-suggestions/category-counts/active` | `GET .../detections?include=metadata&slim=true` |
| N/A | `GET .../owasp-coverage` |

### Response Differences

- **Scan status:** NG embeds `vulnerabilities[]` inline with CVSS scores and OWASP tags. CG required a separate `report_summary()` call.
- **Scan completion:** NG uses `status: "Complete"`. CG used `task.status: "COMPLETED"`.
- **Endpoint IDs:** NG base64-encodes `METHOD:/path` (e.g., `R0VUOi8uLi4=`). CG used plain `method:/path`.

## NG Scripts Design

### File Structure

```
ng-scripts/
  ng_apisec_upload.py        # Create app from OAS or reload spec
  ng_apisec_scan.py          # Trigger scan + poll + report detections
  apisecUploadOpenAPI.groovy  # Jenkins shared lib wrapper for upload
  apisecScan.groovy           # Jenkins shared lib wrapper for scan
  apisecComplete.groovy       # Jenkins shared lib orchestrator
```

### ng_apisec_upload.py

Two operational modes:

**Create mode** (`--create`):
1. `POST /v1/applications/oas` with `applicationName` + (`oasUrl` | `fileUpload`) + `origin=TENANT_PORTAL`
2. Returns `{ applicationId, hostUrls }`
3. Optionally batch-add instances via `POST /v1/applications/{appId}/instances/batch`

**Reload mode** (`--reload`):
1. Resolve target: accept `--application-id`/`--instance-id` directly, or lookup by `--application-name` via `GET /v1/applications?include=metadata`
2. `POST /v1/applications/{appId}/instances/{instId}/reload-spec` with `oasUrl` or `fileUpload`

CLI interface:
```
python ng_apisec_upload.py --create --name "My API" --oas-url https://...
python ng_apisec_upload.py --create --name "My API" --oas-file ./openapi.yml
python ng_apisec_upload.py --reload --application-id <uuid> --instance-id <uuid> --oas-url https://...
python ng_apisec_upload.py --reload --application-name "My API" --oas-file ./openapi.yml
```

Environment: `APISEC_TOKEN` (required)

### ng_apisec_scan.py

Flow: Initiate -> Poll -> Report

1. **Initiate:** `POST /v1/applications/{appId}/instances/{instId}/scan`
   - Body: `{ endpointIds: [], scanWithAuthId: "" }` (empty = all endpoints, unauthenticated)
   - Optional: `--auth-id <uuid>` for authenticated scans, `--endpoint-ids` for targeted scans
   - Response: `{ scanId }`

2. **Poll:** `GET /v1/applications/{appId}/instances/{instId}/scans/{scanId}`
   - Poll every 15s until `status == "Complete"` or `--timeout` exceeded
   - Log progress: status, vulnerability count

3. **Report (optional):** `GET /v1/applications/{appId}/instances/{instId}/detections?include=metadata&slim=true&excludeDetectionsWithStatus=DISMISSED`
   - Full detection details with OWASP tags, CVSS, remediation

CLI interface:
```
python ng_apisec_scan.py --application-id <uuid> --instance-id <uuid>
python ng_apisec_scan.py --application-name "My API"
python ng_apisec_scan.py --application-id <uuid> --instance-id <uuid> \
  --auth-id <uuid> --timeout 900 --reporting
```

Environment: `APISEC_TOKEN` (required)

Exit codes: 0 = scan passed, 1 = vulnerabilities found or error

### Groovy Jenkins Wrappers

#### apisecUploadOpenAPI.groovy

Same structure as CG version. Key parameter changes:
- `token` replaces `username`/`password` (falls back to `APISEC_TOKEN` env var)
- `hostname` defaults to `https://api.apisecapps.com`
- `applicationId`/`instanceId` replace `projectName` (or `applicationName` for lookup)
- Retains: `openapiFile`, `generateScript`, `container`, `skipIfNoScript`, `openapiPattern`

#### apisecScan.groovy

Key parameter changes:
- `token` replaces `username`/`password`
- `applicationId`/`instanceId` replace `projectName`
- `authId` added for authenticated scans
- `profile` removed (NG doesn't use scan profiles the same way)
- Retains: `timeout`, `failOnError`, `showReport`, `container`

#### apisecComplete.groovy

Orchestrates upload + scan. Same env-filtering logic as CG.
- `enableUpload`, `enableScan`, `scanOnlyForEnv`, `currentEnv` retained
- Auth simplified to single `token` parameter

### Application Name Lookup

When `--application-name` is provided instead of IDs:
1. `GET /v1/applications?include=metadata` (paginated with `nextToken`)
2. Match by name
3. Use first instance, or accept `--instance-index` to pick specific one
4. Fail with clear error if not found or ambiguous

### Dependencies

Python scripts require:
- `requests` (HTTP client)
- Python 3.6+ (f-strings)

No new dependencies vs CG. Removed: `pyyaml` (no longer parsing OpenAPI client-side).
