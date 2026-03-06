#!/usr/bin/env groovy

/**
 * APISec Complete - Full API Security Testing Workflow
 *
 * Orchestrates the complete APISec workflow including OpenAPI upload and security scanning.
 * This is the recommended function for most use cases as it handles both steps with
 * environment-aware execution.
 *
 * @param config Map with the following options:
 *   - projectName (required): APISec project name
 *
 *   Upload Options:
 *   - enableUpload (optional, default: true): Enable OpenAPI upload step
 *   - openapiFile (optional): Path to pre-generated OpenAPI file
 *   - generateScript (optional, default: 'generate:swagger'): npm script to generate OpenAPI
 *   - nodejsContainer (optional, default: 'nodejs'): Container for npm operations
 *   - openapiPattern (optional, default: '*-openapi.yml'): Pattern to find generated OpenAPI file
 *   - npmInstallArgs (optional, default: '--legacy-peer-deps --no-package-lock'): npm install args
 *
 *   Scan Options:
 *   - enableScan (optional, default: true): Enable security scan step
 *   - profile (optional, default: 'Master'): APISec scan profile
 *   - timeout (optional, default: 600): Scan timeout in seconds
 *   - failOnError (optional, default: false): Fail pipeline if scan finds issues
 *   - showReport (optional, default: false): Display detailed vulnerability report
 *
 *   Common Options:
 *   - pythonContainer (optional, default: 'python'): Container for Python script execution
 *   - username (optional): APISec username (falls back to APISEC_USERNAME env var)
 *   - password (optional): APISec password (falls back to APISEC_PASSWORD env var)
 *   - hostname (optional, default: 'https://cloud.apisec.ai'): APISec hostname
 *   - scanOnlyForEnv (optional, default: ['dev']): Only run scan for these environments
 *   - currentEnv (optional): Current environment name (for scanOnlyForEnv filtering)
 *
 * @return Map with results: [uploadSuccess: Boolean, scanSuccess: Boolean]
 *
 * Example usage:
 *   // Basic usage - upload and scan
 *   apisecComplete([
 *     projectName: 'my-api-service'
 *   ])
 *
 *   // With environment filtering
 *   apisecComplete([
 *     projectName: 'my-api-service',
 *     currentEnv: params.ENV,
 *     scanOnlyForEnv: ['dev', 'test'],
 *     failOnError: true
 *   ])
 *
 *   // Upload only (no scan)
 *   apisecComplete([
 *     projectName: 'my-api-service',
 *     enableScan: false
 *   ])
 *
 *   // Scan only (no upload)
 *   apisecComplete([
 *     projectName: 'my-api-service',
 *     enableUpload: false
 *   ])
 */
def call(Map config = [:]) {
    // Validate required parameters
    if (!config.projectName) {
        error "apisecComplete: 'projectName' is required"
    }

    // Set defaults
    def projectName = config.projectName

    // Upload options
    def enableUpload = config.enableUpload != null ? config.enableUpload : true
    def openapiFile = config.openapiFile ?: null
    def generateScript = config.generateScript ?: 'generate:swagger'
    def nodejsContainer = config.nodejsContainer ?: 'nodejs'
    def openapiPattern = config.openapiPattern ?: '*-openapi.yml'
    def npmInstallArgs = config.npmInstallArgs ?: '--legacy-peer-deps --no-package-lock'

    // Scan options
    def enableScan = config.enableScan != null ? config.enableScan : true
    def profile = config.profile ?: 'Master'
    def timeout = config.timeout ?: 600
    def failOnError = config.failOnError ?: false
    def showReport = config.showReport ?: false

    // Common options
    def pythonContainer = config.pythonContainer ?: 'python'
    def username = config.username ?: null
    def password = config.password ?: null
    def hostname = config.hostname ?: 'https://cloud.apisec.ai'
    def scanOnlyForEnv = config.scanOnlyForEnv ?: ['dev']
    def currentEnv = config.currentEnv ?: env.ENV ?: env.ENVIRONMENT ?: null

    def results = [
        uploadSuccess: false,
        scanSuccess: false,
        uploadSkipped: false,
        scanSkipped: false
    ]

    echo "========================================"
    echo "APISec Complete Security Testing"
    echo "========================================"
    echo "Project: ${projectName}"
    echo "APISec Host: ${hostname}"
    echo "Current Environment: ${currentEnv ?: 'not specified'}"
    echo "Upload Enabled: ${enableUpload}"
    echo "Scan Enabled: ${enableScan}"
    if (enableScan) {
        echo "Scan Only For Environments: ${scanOnlyForEnv.join(', ')}"
    }
    echo "========================================"

    // Step 1: Upload OpenAPI spec
    if (enableUpload) {
        echo "\n--- Step 1: Upload OpenAPI Specification ---"

        try {
            results.uploadSuccess = apisecUploadOpenAPI([
                projectName: projectName,
                openapiFile: openapiFile,
                generateScript: generateScript,
                container: nodejsContainer,
                pythonContainer: pythonContainer,
                username: username,
                password: password,
                hostname: hostname,
                skipIfNoScript: true,
                openapiPattern: openapiPattern,
                npmInstallArgs: npmInstallArgs
            ])

            if (!results.uploadSuccess) {
                echo "OpenAPI upload was skipped (no generate script or package.json)"
                results.uploadSkipped = true
            }
        } catch (Exception e) {
            echo "OpenAPI upload failed: ${e.message}"
            if (failOnError) {
                throw e
            }
        }
    } else {
        echo "\n--- Step 1: Upload OpenAPI Specification (DISABLED) ---"
        results.uploadSkipped = true
    }

    // Step 2: Run APISec Security Scan
    if (enableScan) {
        echo "\n--- Step 2: APISec Security Scan ---"

        // Check if we should run scan for this environment
        def shouldRunScan = true
        if (currentEnv && scanOnlyForEnv) {
            shouldRunScan = scanOnlyForEnv.contains(currentEnv)
            if (!shouldRunScan) {
                echo "SKIP: Security scan is only enabled for environments: ${scanOnlyForEnv.join(', ')}"
                echo "Reason: Current environment '${currentEnv}' is not in the list"
                results.scanSkipped = true
            }
        }

        if (shouldRunScan) {
            try {
                results.scanSuccess = apisecScan([
                    projectName: projectName,
                    container: pythonContainer,
                    username: username,
                    password: password,
                    profile: profile,
                    hostname: hostname,
                    timeout: timeout,
                    failOnError: failOnError,
                    showReport: showReport
                ])
            } catch (Exception e) {
                echo "Security scan failed: ${e.message}"
                if (failOnError) {
                    throw e
                }
            }
        }
    } else {
        echo "\n--- Step 2: APISec Security Scan (DISABLED) ---"
        results.scanSkipped = true
    }

    // Summary
    echo "\n========================================"
    echo "APISec Complete - Summary"
    echo "========================================"
    if (enableUpload) {
        if (results.uploadSkipped) {
            echo "OpenAPI Upload: SKIPPED"
        } else if (results.uploadSuccess) {
            echo "OpenAPI Upload: SUCCESS"
        } else {
            echo "OpenAPI Upload: FAILED"
        }
    } else {
        echo "OpenAPI Upload: DISABLED"
    }

    if (enableScan) {
        if (results.scanSkipped) {
            echo "Security Scan: SKIPPED"
        } else if (results.scanSuccess) {
            echo "Security Scan: PASSED"
        } else {
            echo "Security Scan: ISSUES FOUND"
        }
    } else {
        echo "Security Scan: DISABLED"
    }
    echo "========================================"

    return results
}
