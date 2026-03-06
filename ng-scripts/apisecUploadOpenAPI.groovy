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
