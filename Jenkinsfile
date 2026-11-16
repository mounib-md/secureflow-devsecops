
node {
    withEnv([
        'JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64',
        'PATH+JAVA=/usr/lib/jvm/java-17-openjdk-amd64/bin'
    ]) {

        // ==========================================
        // 1. CHECKOUT GITHUB
        // ==========================================
        stage('Checkout') {
            git branch: 'main',
                url: 'https://github.com/mounib-md/secureflow-devsecops.git'
        }

        // ==========================================
        // 2. SECRET SCANNING - GITLEAKS
        // ==========================================
        stage('Secret Scan - Gitleaks') {
            sh '''
                /usr/local/bin/gitleaks git . --redact
            '''
        }

        // ==========================================
        // 3. BUILD & UNIT TESTS - MAVEN
        // ==========================================
        stage('Build & Test') {
            sh '''
                chmod +x mvnw
                ./mvnw clean verify
            '''

            junit allowEmptyResults: false,
                  testResults: 'target/surefire-reports/*.xml'
        }

        // ==========================================
        // 4. STATIC ANALYSIS - SONARQUBE
        // ==========================================
        stage('SonarQube Analysis') {
            withSonarQubeEnv('SonarQube-Local') {
                sh '''
                    ./mvnw \
                      org.sonarsource.scanner.maven:sonar-maven-plugin:5.9.0.7382:sonar \
                      -Dsonar.projectKey=SecureFlow \
                      -Dsonar.projectName=SecureFlow
                '''
            }
        }

        // ==========================================
        // 5. SONARQUBE QUALITY GATE
        // ==========================================
        stage('SonarQube Quality Gate') {
            timeout(time: 5, unit: 'MINUTES') {
                def qg = waitForQualityGate abortPipeline: false

                echo "SonarQube Quality Gate: ${qg.status}"

                if (qg.status != 'OK') {
                    unstable("Quality Gate: ${qg.status}")
                }
            }
        }

        // ==========================================
        // 6. TRIVY FILESYSTEM SCANNING
        // ==========================================
        stage('Trivy Filesystem Scan') {
            try {
                sh '''
                    mkdir -p reports

                    trivy fs . \
                      --scanners vuln,misconfig \
                      --severity HIGH,CRITICAL \
                      --skip-dirs target \
                      --format json \
                      --output reports/trivy-fs.json \
                      --exit-code 0

                    echo "Trivy filesystem scan completed."
                '''
            } finally {
                archiveArtifacts(
                    artifacts: 'reports/trivy-fs.json',
                    allowEmptyArchive: false,
                    fingerprint: true
                )
            }
        }

stage('Trivy Image Scan') {
    try {
        sh '''
            mkdir -p reports

            trivy image \
              --image-src remote \
              --scanners vuln \
              --severity HIGH,CRITICAL \
              --format json \
              --output reports/trivy-image.json \
              --exit-code 0 \
              --no-progress \
              anisbengaji/student-management:latest

            echo "Trivy image scan completed."
        '''
    } finally {
        archiveArtifacts(
            artifacts: 'reports/trivy-image.json',
            allowEmptyArchive: false,
            fingerprint: true
        )
    }
}

stage('OWASP ZAP API Connection') {
    withCredentials([
        string(credentialsId: 'zap-api-key', variable: 'ZAP_API_KEY')
    ]) {
        sh '''
            set +x

            curl --fail --silent --show-error \
              --noproxy '*' \
              --max-time 15 \
              -H "X-ZAP-API-Key: $ZAP_API_KEY" \
              http://127.0.0.1:8090/JSON/core/view/version/
        '''
    }
}

stage('OWASP ZAP DAST Scan') {
    try {
        timeout(time: 8, unit: 'MINUTES') {
            withCredentials([
                string(
                    credentialsId: 'zap-api-key',
                    variable: 'ZAP_API_KEY'
                )
            ]) {
                sh '''
                    set +x
                    mkdir -p reports

                    python3 - <<'PY'
import json
import os
import time
import urllib.parse
import urllib.request

API = "http://127.0.0.1:8090"
TARGET = "http://127.0.0.1:8089/student/students/getAllStudents"
KEY = os.environ["ZAP_API_KEY"]

def request(path, params=None):
    url = API + path
    if params:
        url += "?" + urllib.parse.urlencode(params)

    req = urllib.request.Request(
        url,
        headers={"X-ZAP-API-Key": KEY}
    )

    with urllib.request.urlopen(req, timeout=20) as response:
        return response.read()

def api_json(path, params=None):
    result = json.loads(request(path, params))
    if "code" in result and "message" in result:
        raise RuntimeError(result["message"])
    return result

print("Starting ZAP spider...", flush=True)

result = api_json(
    "/JSON/spider/action/scan/",
    {"url": TARGET, "recurse": "false"}
)

scan_id = result["scan"]
print("Spider ID:", scan_id, flush=True)

deadline = time.monotonic() + 240

while True:
    status = api_json(
        "/JSON/spider/view/status/",
        {"scanId": scan_id}
    )["status"]

    print("Spider progress:", status + "%", flush=True)

    if status == "100":
        break

    if time.monotonic() >= deadline:
        raise TimeoutError("ZAP spider timed out")

    time.sleep(5)

print("Waiting for passive scanning...", flush=True)

while True:
    remaining = int(
        api_json(
            "/JSON/pscan/view/recordsToScan/"
        )["recordsToScan"]
    )

    print("Passive scan queue:", remaining, flush=True)

    if remaining == 0:
        break

    if time.monotonic() >= deadline:
        raise TimeoutError("ZAP passive scan timed out")

    time.sleep(5)

reports = {
    "reports/zap-dast.html": "/OTHER/core/other/htmlreport/",
    "reports/zap-dast.json": "/OTHER/core/other/jsonreport/",
    "reports/zap-dast.xml": "/OTHER/core/other/xmlreport/"
}

for filename, endpoint in reports.items():
    data = request(endpoint)
    if not data:
        raise RuntimeError("Empty ZAP report: " + filename)

    with open(filename, "wb") as f:
        f.write(data)

    print("Generated:", filename, flush=True)

print("ZAP DAST scan completed.", flush=True)
PY
                '''
            }
        }
    } finally {
        archiveArtifacts(
            artifacts: 'reports/zap-dast.*',
            allowEmptyArchive: true,
            fingerprint: true
        )
    }
}




stage('DefectDojo Security Reports Upload') {
    withCredentials([
        string(
            credentialsId: 'defectdojo-api-token',
            variable: 'DD_API_TOKEN'
        )
    ]) {
        sh '''
            set +x
            set -eu

            DD_URL="http://127.0.0.1:8081"
            ENGAGEMENT_ID="1"

            upload_report() {
                SCAN_TYPE="$1"
                TEST_TITLE="$2"
                REPORT_FILE="$3"

                if [ ! -s "$REPORT_FILE" ]; then
                    echo "ERROR: Missing report: $REPORT_FILE"
                    exit 1
                fi

                echo "Uploading: $TEST_TITLE"

                RESPONSE_FILE=$(mktemp)

                HTTP_CODE=$(curl --silent --show-error --noproxy '*' --max-time 120 --output "$RESPONSE_FILE" --write-out '%{http_code}' --request POST "$DD_URL/api/v2/reimport-scan/" --header "Authorization: Token $DD_API_TOKEN" --form-string "engagement=$ENGAGEMENT_ID" --form-string "product_name=SecureFlow" --form-string "engagement_name=SecureFlow CI/CD Security" --form-string "scan_type=$SCAN_TYPE" --form-string "test_title=$TEST_TITLE" --form-string "minimum_severity=Info" --form-string "active=true" --form-string "verified=false" --form-string "close_old_findings=false" --form "file=@$REPORT_FILE")

                echo "DefectDojo HTTP status: $HTTP_CODE"

                case "$HTTP_CODE" in
                    200|201)
                        echo "SUCCESS: $TEST_TITLE"
                        ;;
                    *)
                        echo "ERROR: DefectDojo import failed"
                        cat "$RESPONSE_FILE"
                        rm -f "$RESPONSE_FILE"
                        exit 1
                        ;;
                esac

                rm -f "$RESPONSE_FILE"
            }

            upload_report "Trivy Scan" "Trivy Filesystem Scan" "reports/trivy-fs.json"

            upload_report "Trivy Scan" "Trivy Image Scan" "reports/trivy-image.json"

            upload_report "ZAP Scan" "OWASP ZAP DAST" "reports/zap-dast.xml"

            echo "All security reports uploaded successfully."
        '''
    }
}

stage('SonarQube Issues Export') {
    withCredentials([
        string(
            credentialsId: 'sonarqube-token',
            variable: 'SONAR_TOKEN'
        )
    ]) {
        sh '''
            set +x
            set -eu

            mkdir -p reports

            HTTP_CODE=$(curl --silent --show-error \
                --noproxy '*' \
                --max-time 30 \
                -o reports/sonarqube-issues.json \
                -w '%{http_code}' \
                -H "Authorization: Bearer $SONAR_TOKEN" \
                "http://127.0.0.1:9000/api/issues/search?projects=SecureFlow&ps=500")

            echo "SonarQube HTTP status: $HTTP_CODE"

            if [ "$HTTP_CODE" != "200" ]; then
                echo "SonarQube API request failed"
                exit 1
            fi

            python3 -m json.tool reports/sonarqube-issues.json > /dev/null

            python3 -c 'import json; d=json.load(open("reports/sonarqube-issues.json")); print("Total issues:", d.get("total")); print("Issues exported:", len(d.get("issues", [])))'
        '''

        archiveArtifacts artifacts: 'reports/sonarqube-issues.json',
                         fingerprint: true
    }
}



stage('DefectDojo SonarQube Upload') {
    withCredentials([
        string(
            credentialsId: 'defectdojo-api-token',
            variable: 'DD_API_TOKEN'
        )
    ]) {
        sh '''
            set +x
            set -eu

            REPORT="reports/sonarqube-issues.json"

            if [ ! -s "$REPORT" ]; then
                echo "ERROR: SonarQube report missing"
                exit 1
            fi

            echo "Reimporting SonarQube report to DefectDojo..."

            RESPONSE=$(mktemp)
            trap 'rm -f "$RESPONSE"' EXIT

            HTTP_CODE=$(curl --silent --show-error --noproxy '*' --max-time 120 --output "$RESPONSE" --write-out '%{http_code}' --request POST "http://127.0.0.1:8081/api/v2/reimport-scan/" --header "Authorization: Token $DD_API_TOKEN" --form-string "engagement=1" --form-string "product_name=SecureFlow" --form-string "engagement_name=SecureFlow CI/CD Security" --form-string "scan_type=SonarQube Scan" --form-string "test_title=SonarQube SAST Scan" --form-string "minimum_severity=Info" --form-string "active=true" --form-string "verified=false" --form-string "close_old_findings=false" --form "file=@$REPORT")

            echo "DefectDojo SonarQube HTTP status: $HTTP_CODE"

            case "$HTTP_CODE" in
                200|201)
                    echo "SUCCESS: SonarQube report reimported"
                    ;;
                *)
                    echo "ERROR: SonarQube reimport failed"
                    cat "$RESPONSE"
                    exit 1
                    ;;
            esac
        '''
    }
}



    }
}
