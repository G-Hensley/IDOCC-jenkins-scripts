#!/usr/bin/env groovy

/**
 * APISec OpenAPI Upload
 *
 * Generates an OpenAPI specification (if needed) and uploads it to APISec.
 * This function can either use a pre-existing OpenAPI file or generate one
 * using an npm script (e.g., 'generate:swagger').
 *
 * @param config Map with the following options:
 *   - projectName (required): APISec project name
 *   - openapiFile (optional): Path to pre-generated OpenAPI file. If not provided,
 *                             will attempt to generate using generateScript
 *   - generateScript (optional, default: 'generate:swagger'): npm script to generate OpenAPI
 *   - container (optional, default: 'nodejs'): Container name for npm operations
 *   - pythonContainer (optional, default: 'python'): Container name for Python script execution
 *   - username (optional): APISec username (falls back to APISEC_USERNAME env var)
 *   - password (optional): APISec password (falls back to APISEC_PASSWORD env var)
 *   - hostname (optional, default: 'https://cloud.apisec.ai'): APISec hostname
 *   - skipIfNoScript (optional, default: true): Skip silently if no generate script in package.json
 *   - openapiPattern (optional, default: '*-openapi.yml'): Pattern to find generated OpenAPI file
 *   - npmInstallArgs (optional, default: '--legacy-peer-deps --no-package-lock'): npm install arguments
 *   - scriptPath (optional): Custom path to apisec_upload_openapi.py script
 *
 * @return Boolean - true if upload succeeded, false if skipped
 *
 * Example usage:
 *   apisecUploadOpenAPI([
 *     projectName: 'my-api-service',
 *     container: 'nodejs',
 *     pythonContainer: 'awscli'
 *   ])
 *
 *   // With pre-existing OpenAPI file
 *   apisecUploadOpenAPI([
 *     projectName: 'my-api-service',
 *     openapiFile: 'docs/openapi.yaml',
 *     pythonContainer: 'python'
 *   ])
 */
def call(Map config = [:]) {
    // Validate required parameters
    if (!config.projectName) {
        error "apisecUploadOpenAPI: 'projectName' is required"
    }

    // Set defaults
    def projectName = config.projectName
    def openapiFile = config.openapiFile ?: null
    def generateScript = config.generateScript ?: 'generate:swagger'
    def container = config.container ?: 'nodejs'
    def pythonContainer = config.pythonContainer ?: 'python'
    def username = config.username ?: null
    def password = config.password ?: null
    def hostname = config.hostname ?: 'https://cloud.apisec.ai'
    def skipIfNoScript = config.skipIfNoScript != null ? config.skipIfNoScript : true
    def openapiPattern = config.openapiPattern ?: '*-openapi.yml'
    def npmInstallArgs = config.npmInstallArgs ?: '--legacy-peer-deps --no-package-lock'
    def scriptPath = config.scriptPath ?: null

    echo "========================================"
    echo "APISec OpenAPI Upload"
    echo "========================================"
    echo "Project: ${projectName}"
    echo "APISec Host: ${hostname}"

    // If no pre-existing OpenAPI file, check for generate script
    if (!openapiFile) {
        echo "No openapiFile provided - checking for ${generateScript} script in package.json"

        def hasSwaggerScript = false
        if (fileExists('package.json')) {
            def packageJson = readJSON file: 'package.json'
            hasSwaggerScript = packageJson?.scripts?.containsKey(generateScript)
        } else {
            echo "SKIP: No package.json found in workspace"
            echo "Reason: Cannot generate OpenAPI spec without package.json"
            if (skipIfNoScript) {
                return false
            } else {
                error "No package.json found and skipIfNoScript is false"
            }
        }

        if (!hasSwaggerScript) {
            echo "SKIP: Service does not have '${generateScript}' script in package.json"
            echo "Reason: No script available to generate OpenAPI specification"
            if (skipIfNoScript) {
                return false
            } else {
                error "No ${generateScript} script found and skipIfNoScript is false"
            }
        }

        echo "Found '${generateScript}' script - generating OpenAPI specification"

        // Generate OpenAPI spec in the nodejs container
        container(container) {
            sh """
                set -e
                echo "Installing dependencies..."
                npm install ${npmInstallArgs}

                echo "Generating OpenAPI specification..."
                npm run ${generateScript}

                # Find generated OpenAPI file
                OPENAPI_FILE=\$(find . -maxdepth 1 -name "${openapiPattern}" | head -1)

                if [ -n "\$OPENAPI_FILE" ] && [ -f "\$OPENAPI_FILE" ]; then
                    echo "OpenAPI spec generated: \$OPENAPI_FILE"
                    echo "File size: \$(wc -l < \$OPENAPI_FILE) lines"
                    ls -lh \$OPENAPI_FILE
                else
                    echo "ERROR: Failed to generate OpenAPI spec (${openapiPattern} not found)"
                    exit 1
                fi
            """
        }

        // Find the generated file for the upload step
        openapiFile = sh(
            script: "find . -maxdepth 1 -name '${openapiPattern}' | head -1 | sed 's|^\\./||'",
            returnStdout: true
        ).trim()

        if (!openapiFile) {
            error "Failed to find generated OpenAPI file matching pattern: ${openapiPattern}"
        }

        echo "Using generated OpenAPI file: ${openapiFile}"
    } else {
        echo "Using provided OpenAPI file: ${openapiFile}"

        if (!fileExists(openapiFile)) {
            error "Specified OpenAPI file not found: ${openapiFile}"
        }
    }

    // Determine script path
    def uploadScript = scriptPath
    if (!uploadScript) {
        // Try to find the script in common locations
        def possiblePaths = [
            "${WORKSPACE}/resources/scripts/apisec_upload_openapi.py",
            "${env.LIBRARY_PATH}/resources/scripts/apisec_upload_openapi.py",
            "apisec_upload_openapi.py"
        ]
        for (path in possiblePaths) {
            if (fileExists(path)) {
                uploadScript = path
                break
            }
        }

        // If not found, use libraryResource to extract it
        if (!uploadScript || !fileExists(uploadScript)) {
            echo "Extracting apisec_upload_openapi.py from library resources..."
            def scriptContent = libraryResource('scripts/apisec_upload_openapi.py')
            writeFile file: 'apisec_upload_openapi.py', text: scriptContent
            uploadScript = 'apisec_upload_openapi.py'
        }
    }

    echo "Using upload script: ${uploadScript}"

    // Build environment variables for credentials
    def envVars = []
    if (username) {
        envVars.add("APISEC_USERNAME=${username}")
    }
    if (password) {
        envVars.add("APISEC_PASSWORD=${password}")
    }

    // Upload to APISec
    container(pythonContainer) {
        withEnv(envVars) {
            sh """
                echo "Uploading OpenAPI spec to APISec..."
                python3 ${uploadScript} \\
                    -p ${projectName} \\
                    -f ${openapiFile} \\
                    --hostname ${hostname}

                echo "OpenAPI spec uploaded to APISec successfully"
            """
        }
    }

    echo "========================================"
    echo "APISec OpenAPI Upload Complete"
    echo "========================================"

    return true
}
