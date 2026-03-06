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
