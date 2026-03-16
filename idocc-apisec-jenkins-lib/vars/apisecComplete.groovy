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
