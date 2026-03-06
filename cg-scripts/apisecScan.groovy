#!/usr/bin/env groovy

/**
 * APISec Security Scan
 *
 * Runs an APISec security scan on a project and optionally fails the build
 * if vulnerabilities are found.
 *
 * @param config Map with the following options:
 *   - projectName (required): APISec project name
 *   - container (optional, default: 'python'): Container name for Python script execution
 *   - username (optional): APISec username (falls back to APISEC_USERNAME env var)
 *   - password (optional): APISec password (falls back to APISEC_PASSWORD env var)
 *   - profile (optional, default: 'Master'): APISec scan profile
 *   - hostname (optional, default: 'https://cloud.apisec.ai'): APISec hostname
 *   - timeout (optional, default: 600): Scan timeout in seconds
 *   - failOnError (optional, default: false): Fail pipeline if scan finds issues
 *   - showReport (optional, default: false): Display detailed vulnerability report
 *   - scriptPath (optional): Custom path to apisec_run.py script
 *
 * @return Boolean - true if scan passed, false if vulnerabilities found
 *
 * Example usage:
 *   apisecScan([
 *     projectName: 'my-api-service',
 *     container: 'python',
 *     profile: 'Master',
 *     timeout: 900
 *   ])
 *
 *   // Fail build on security issues
 *   apisecScan([
 *     projectName: 'my-api-service',
 *     failOnError: true,
 *     showReport: true
 *   ])
 */
def call(Map config = [:]) {
    // Validate required parameters
    if (!config.projectName) {
        error "apisecScan: 'projectName' is required"
    }

    // Set defaults
    def projectName = config.projectName
    def container = config.container ?: 'python'
    def username = config.username ?: null
    def password = config.password ?: null
    def profile = config.profile ?: 'Master'
    def hostname = config.hostname ?: 'https://cloud.apisec.ai'
    def timeout = config.timeout ?: 600
    def failOnError = config.failOnError ?: false
    def showReport = config.showReport ?: false
    def scriptPath = config.scriptPath ?: null

    echo "========================================"
    echo "APISec Security Scan"
    echo "========================================"
    echo "Project: ${projectName}"
    echo "Profile: ${profile}"
    echo "APISec Host: ${hostname}"
    echo "Timeout: ${timeout}s"
    echo "Fail on Error: ${failOnError}"
    echo "========================================"

    // Determine script path
    def scanScript = scriptPath
    if (!scanScript) {
        // Try to find the script in common locations
        def possiblePaths = [
            "${WORKSPACE}/resources/scripts/apisec_run.py",
            "${env.LIBRARY_PATH}/resources/scripts/apisec_run.py",
            "apisec_run.py"
        ]
        for (path in possiblePaths) {
            if (fileExists(path)) {
                scanScript = path
                break
            }
        }

        // If not found, use libraryResource to extract it
        if (!scanScript || !fileExists(scanScript)) {
            echo "Extracting apisec_run.py from library resources..."
            def scriptContent = libraryResource('scripts/apisec_run.py')
            writeFile file: 'apisec_run.py', text: scriptContent
            scanScript = 'apisec_run.py'
        }
    }

    echo "Using scan script: ${scanScript}"

    // Build environment variables for credentials
    def envVars = []
    if (username) {
        envVars.add("APISEC_USERNAME=${username}")
    }
    if (password) {
        envVars.add("APISEC_PASSWORD=${password}")
    }

    // Build command arguments
    def reportFlag = showReport ? '-r' : ''

    def scanPassed = true

    // Run APISec scan
    container(container) {
        withEnv(envVars) {
            def exitCode = sh(
                script: """
                    echo "Starting APISec security scan..."
                    python3 ${scanScript} \\
                        -p ${projectName} \\
                        --profile ${profile} \\
                        --hostname ${hostname} \\
                        --timeout ${timeout} \\
                        ${reportFlag}
                """,
                returnStatus: true
            )

            if (exitCode != 0) {
                scanPassed = false
                if (failOnError) {
                    error "APISec security scan failed or found vulnerabilities"
                } else {
                    echo "WARNING: APISec security scan found issues (exit code: ${exitCode})"
                    echo "Build will continue as failOnError is set to false"
                }
            }
        }
    }

    echo "========================================"
    if (scanPassed) {
        echo "APISec Security Scan Complete - PASSED"
    } else {
        echo "APISec Security Scan Complete - ISSUES FOUND"
    }
    echo "========================================"

    return scanPassed
}
