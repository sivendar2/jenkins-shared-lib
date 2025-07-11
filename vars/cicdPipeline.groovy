def call() {
    pipeline {
        agent any

        environment {
            AWS_REGION = 'us-east-1'
            ECR_REPO = '...'
            IMAGE_TAG = 'latest'
            SONAR_HOST_URL = '...'
            SONAR_PROJECT_KEY = 'employee-department-1'
            SONAR_TOKEN = credentials('sonar-token-jenkins')
        }

        stages {
            stage('Checkout') {
                steps {
                    git branch: 'main', url: 'https://github.com/sivendar2/employee-department-1.git'
                }
            }

            stage('Semgrep Scan & Autofix') {
                steps {
                    script {
                        org.devsecops.SemgrepHandler.runScanWithAutofix()
                    }
                }
            }

            stage('Create PR') {
                steps {
                    script {
                        org.devsecops.GitHandler.createAutofixPR()
                    }
                }
            }

            // Add other stages: Docker, ECR, ECS deploy, etc.
        }
    }
}
