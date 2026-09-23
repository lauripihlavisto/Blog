// Blog: security design, steps 1-2. Initial report-collection mode.
// Requires Linux agent, local Docker, Java and Jenkins tool 'Dependency-Check'.
pipeline {
    agent any
    options {
        skipDefaultCheckout(true)
        disableConcurrentBuilds()
        timestamps()
        timeout(time: 120, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '10'))
    }
    parameters {
        booleanParam(name: 'USE_NVD_KEY', defaultValue: false,
            description: 'Use optional Secret text credential: nvd-api-key')
    }
    environment {
        TRIVY_IMAGE = 'aquasec/trivy:0.74.0'
        NIKTO_IMAGE = 'ghcr.io/sullo/nikto:2.6.1'
    }
    stages {
        stage('Checkout') {
            steps {
                deleteDir()
                checkout scm
                script {
                    def resource = env.BUILD_TAG.toLowerCase().replaceAll('[^a-z0-9_.-]', '-')
                    env.SCAN_NETWORK = "${resource}-net"
                    env.TEST_CONTAINER = "${resource}-app"
                    env.BLOG_IMAGE = "blog-security:${resource}"
                }
                sh 'docker info >/dev/null'
            }
        }
        stage('Build Docker image') {
            steps {
                // Use the existing project Dockerfile; no new unit tests in steps 1-2.
                sh 'docker build --pull -t "$BLOG_IMAGE" .'
                sh 'mkdir -p reports/dependency-check'
            }
        }
        stage('Trivy filesystem') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE', catchInterruptions: false) {
                    sh '''
                        docker run --rm \
                          -v "$WORKSPACE:/src:ro" \
                          -v "$WORKSPACE/reports:/reports" \
                          -v blog-trivy-cache:/root/.cache/ \
                          "$TRIVY_IMAGE" fs \
                          --scanners vuln,misconfig,secret \
                          --skip-dirs /src/.git --skip-dirs /src/reports \
                          --exit-code 0 --format json \
                          --output /reports/trivy-filesystem.json /src
                        test -s reports/trivy-filesystem.json
                    '''
                }
            }
        }
        stage('Trivy container image') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE', catchInterruptions: false) {
                    sh '''
                        docker run --rm \
                          -v /var/run/docker.sock:/var/run/docker.sock \
                          -v "$WORKSPACE/reports:/reports" \
                          -v blog-trivy-cache:/root/.cache/ \
                          "$TRIVY_IMAGE" image --scanners vuln \
                          --exit-code 0 --format json \
                          --output /reports/trivy-image.json "$BLOG_IMAGE"
                        test -s reports/trivy-image.json
                    '''
                }
            }
        }
        stage('OWASP Dependency-Check') {
            options { timeout(time: 90, unit: 'MINUTES') }
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE', catchInterruptions: false) {
                    script {
                        def args = '--project Blog --scan . --exclude "**/reports/**" --format XML --format HTML --out reports/dependency-check'
                        if (params.USE_NVD_KEY) {
                            dependencyCheck odcInstallation: 'Dependency-Check',
                                additionalArguments: args,
                                nvdCredentialsId: 'nvd-api-key', stopBuild: true
                        } else {
                            dependencyCheck odcInstallation: 'Dependency-Check',
                                additionalArguments: args, stopBuild: true
                        }
                    }
                    sh 'test -s reports/dependency-check/dependency-check-report.xml'
                    dependencyCheckPublisher pattern: 'reports/dependency-check/dependency-check-report.xml',
                        skipNoReportFiles: false
                }
            }
        }
        stage('Start isolated test application') {
            steps {
                sh '''
                    docker network create "$SCAN_NETWORK"
                    docker run -d --name "$TEST_CONTAINER" \
                      --network "$SCAN_NETWORK" --network-alias blog "$BLOG_IMAGE"
                '''
                // Check the HTTP service inside the test container with Node's built-in HTTP client.
                timeout(time: 2, unit: 'MINUTES') {
                    retry(12) {
                        sleep(time: 5, unit: 'SECONDS')
                        sh '''
                            docker exec "$TEST_CONTAINER" node -e '
                              const http = require("http");
                              const req = http.get("http://127.0.0.1:3000/auth/login", res => {
                                res.resume();
                                process.exit(res.statusCode === 200 ? 0 : 1);
                              });
                              req.setTimeout(5000, () => { req.destroy(); process.exit(1); });
                              req.on("error", () => process.exit(1));
                            '
                        '''
                    }
                }
            }
        }
        stage('Nikto HTTP scan') {
            options { timeout(time: 20, unit: 'MINUTES') }
            steps {
                sh '''
                    docker run --rm --name "$TEST_CONTAINER-nikto" \
                      --network "$SCAN_NETWORK" \
                      --user "$(id -u):$(id -g)" \
                      -v "$WORKSPACE/reports:/tmp/reports" \
                      "$NIKTO_IMAGE" -h http://blog:3000 \
                      -Format htm -output /tmp/reports/nikto.html
                    test -s reports/nikto.html
                '''
            }
        }
        stage('Security review required') {
            steps {
                unstable('Reports collected. Manual security review required; this pipeline does not deploy.')
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'reports/**/*', allowEmptyArchive: true
        }
        cleanup {
            script {
                if (env.TEST_CONTAINER) {
                    // Remove only resources belonging to this build; existing 'blog' stays running.
                    sh '''
                        docker rm -f "$TEST_CONTAINER-nikto" "$TEST_CONTAINER" || true
                        docker network rm "$SCAN_NETWORK" || true
                        docker image rm "$BLOG_IMAGE" || true
                    '''
                }
            }
        }
    }
}
