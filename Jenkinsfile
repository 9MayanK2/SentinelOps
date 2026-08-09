pipeline {
    agent any

    options {
        timestamps()
        buildDiscarder(logRotator(numToKeepStr: '30'))
    }

    environment {

    PROJECT_NAME = "SentinelOps"

    PYTHONPATH = "."

    AWS_REGION = "us-east-1"
    AWS_ACCOUNT_ID = "284064534086"

    EKS_CLUSTER = "sentinelops-dev-eks"
    IMAGE_TAG = "build-${BUILD_NUMBER}"
    BACKEND_REPOSITORY = "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/sentinelops-backend"
    FRONTEND_REPOSITORY = "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/sentinelops-frontend"
    BACKEND_IMAGE = "${BACKEND_REPOSITORY}:${IMAGE_TAG}"
    FRONTEND_IMAGE = "${FRONTEND_REPOSITORY}:${IMAGE_TAG}"
    }

    stages {

        /********************************************************************
         * Stage 1 : Checkout Source
         ********************************************************************/
        stage('Checkout Source Code') {
            steps {
                echo '========== CHECKOUT SOURCE =========='
                checkout scm
            }
        }

        stage('Install Python Dependencies') {
            steps {
                echo '========== INSTALLING PYTHON REQUIREMENTS =========='
                sh 'pip3 install --user -r requirements.txt || pip install -r requirements.txt || true'
            }
        }

        /********************************************************************
         * Stage 2 : Generate Backend Environment
         ********************************************************************/
        stage('Generate Backend Environment') {
            steps {
                echo '========== GENERATING .ENV =========='
                withCredentials([
                    string(credentialsId: 'MONGO_URL', variable: 'MONGO_URL'),
                    string(credentialsId: 'JWT_SECRET', variable: 'JWT_SECRET'),
                    string(credentialsId: 'EMAIL_USER', variable: 'EMAIL_USER'),
                    string(credentialsId: 'EMAIL_PASS', variable: 'EMAIL_PASS')
                ]) {
                    sh '''
                    cat > app/server/.env <<EOF
PORT=5000
MONGO_URL=${MONGO_URL}
JWT_SECRET=${JWT_SECRET}
EMAIL_USER=${EMAIL_USER}
EMAIL_PASS=${EMAIL_PASS}
EOF
                    '''
                }
            }
        }

        /********************************************************************
         * Stage 3 : Cleanup Previous Build
         ********************************************************************/
        stage('Cleanup Previous Deployment') {
            steps {
                echo '========== CLEANUP =========='
                sh '''
                docker compose down --remove-orphans || true
                docker image prune -f || true
                '''
            }
        }

        /********************************************************************
         * Stage 4 : Pre-Build Security
         ********************************************************************/
        stage('Pre-Build Security Scans') {
            parallel {
                stage('Gitleaks Secrets Scan') {
                    steps {
                        echo '========== GITLEAKS =========='
                        sh './security/run_pipeline.sh pre-build gitleaks'
                    }
                }

                stage('Hadolint Dockerfile Scan') {
                    steps {
                        echo '========== HADOLINT =========='
                        sh './security/run_pipeline.sh pre-build hadolint'
                    }
                }
            }
        }

        /********************************************************************
         * Stage 5 : Build Images
         ********************************************************************/
        stage('Build Docker Images') {
            steps {
                echo '========== BUILDING DOCKER IMAGES =========='
                sh '''
                docker compose build
                echo "Tagging Backend..."

                docker tag \
                sentinelops-backend:latest \
                sentinelops-backend:${IMAGE_TAG}

                echo "Tagging Frontend..."

                docker tag \
                sentinelops-frontend:latest \
                sentinelops-frontend:${IMAGE_TAG}

                docker images
                '''
            }
        }

        /********************************************************************
         * Stage 6 : Trivy Scan
         ********************************************************************/
        stage('Trivy Container Scan') {
            steps {
                echo '========== TRIVY =========='
                sh './security/run_pipeline.sh post-build trivy'
            }
        }

        /********************************************************************
         * Stage 7 : Start Containers
         ********************************************************************/
        stage('Start MERN Application') {
            steps {
                echo '========== STARTING APPLICATION =========='
                sh 'docker compose up -d --force-recreate'
            }
        }

        /********************************************************************
         * Stage 8 : Health Check
         ********************************************************************/
        stage('Application Health Check') {
            steps {
                echo '========== WAITING FOR BACKEND =========='
                sh '''
                for i in {1..30}
                do
                    if curl -fs http://localhost:5000/health > /dev/null
                    then
                        echo "Backend is healthy."
                        exit 0
                    fi
                    echo "Waiting for backend..."
                    sleep 5
                done
                echo "Backend failed to start."
                exit 1
                '''
            }
        }

        /********************************************************************
         * Stage 9 : OWASP ZAP
         ********************************************************************/
        stage('OWASP ZAP DAST Scan') {
            steps {
                echo '========== OWASP ZAP =========='
                sh './security/run_pipeline.sh dast zap'
            }
        }

        /********************************************************************
         * Stage 10 : Generate Security Reports
         ********************************************************************/
        stage('Generate Security Reports') {
            steps {
                echo '========== GENERATING REPORTS =========='
                sh './security/run_pipeline.sh report'
            }
        }

        /********************************************************************
         * Stage 11 : Security Gate Evaluation
         ********************************************************************/
        stage('Security Gate Evaluation') {
            steps {
                echo '========== SECURITY GATE EVALUATION =========='
                sh './security/run_pipeline.sh gate --soft-fail'
            }
        }

        /********************************************************************
         * Stage 12 : Cosign PKI Digital Signing (Post-Gate)
         ********************************************************************/
        stage('Cosign PKI Digital Signing') {
            steps {
                echo '========== COSIGN DIGITAL SIGNING =========='
                sh './security/run_pipeline.sh sign'
            }
        }

        /********************************************************************
         * Stage 13 : Cosign Signature Verification (Post-Gate)
         ********************************************************************/
        stage('Verify Digital Signatures') {
            steps {
                echo '========== SIGNATURE VERIFICATION =========='
                sh './security/run_pipeline.sh verify'
            }
        }

        /********************************************************************
         * Stage 14 : Publish Images to Amazon ECR (Reserved)
         ********************************************************************/
        stage('Login to Amazon ECR') {

            steps {

                sh '''
                aws ecr get-login-password \
                --region ${AWS_REGION} | \
                docker login \
                --username AWS \
                --password-stdin \
                ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com
                '''
            }
        }

        /********************************************************************
         * Stage 15 : Push Images to Amazon ECR (Reserved)
         ********************************************************************/
        stage('Push Images to Amazon ECR') {

            steps {

                sh '''

                docker tag sentinelops-backend:${IMAGE_TAG} ${BACKEND_IMAGE}

                docker tag sentinelops-frontend:${IMAGE_TAG} ${FRONTEND_IMAGE}

                docker push ${BACKEND_IMAGE}

                docker push ${FRONTEND_IMAGE}

                docker tag sentinelops-backend:${IMAGE_TAG} ${BACKEND_REPOSITORY}:latest

                docker tag sentinelops-frontend:${IMAGE_TAG} ${FRONTEND_REPOSITORY}:latest

                docker push ${BACKEND_REPOSITORY}:latest

                docker push ${FRONTEND_REPOSITORY}:latest

                '''
            }
        }

        stage('Verify Images in Amazon ECR') {

            steps {

                sh '''

                aws ecr describe-images \
                --repository-name sentinelops-backend \
                --image-ids imageTag=${IMAGE_TAG}

                aws ecr describe-images \
                --repository-name sentinelops-frontend \
                --image-ids imageTag=${IMAGE_TAG}

                '''
            }
        }
         /********************************************************************
         * Stage 16 : Deploy to Amazon EKS (Reserved)
         ********************************************************************/
        
        stage('Deploy to Amazon EKS') {

            steps {

                sh '''

                aws eks update-kubeconfig \
                --region ${AWS_REGION} \
                --name ${EKS_CLUSTER}

                bash deployment/deploy.sh ${IMAGE_TAG}

                '''
            }
        }

        /********************************************************************
         * Stage 17 : Verify kubernetes to rollout
         ********************************************************************/
        
        stage('Verify Kubernetes Rollout') {

            steps {

                sh '''

                kubectl rollout status \
                deployment/backend \
                -n sentinelops \
                --timeout=5m

                kubectl rollout status deployment/frontend \
                -n sentinelops \
                --timeout=5m

                '''
            }
        }

    }

    /********************************************************************
     * POST ACTIONS
     ********************************************************************/
    post {
        always {
            echo '========== CLEANING UP =========='
            sh '''

            docker-compose down --remove-orphans || true
            docker image prune -f || true
            
            '''
            echo '========== ARCHIVING REPORTS & SIGNATURES =========='
            archiveArtifacts artifacts: 'compliance/reports/**/*', allowEmptyArchive: true
            archiveArtifacts artifacts: 'compliance/master_reports/**/*', allowEmptyArchive: true
            archiveArtifacts artifacts: 'compliance/logs/**/*', allowEmptyArchive: true
            archiveArtifacts artifacts: 'compliance/reports/signing/**/*', allowEmptyArchive: true
        }

        success {
            echo '''
==================================================
      SENTINELOPS PIPELINE COMPLETED SUCCESSFULLY
==================================================
            '''
        }

        failure {

            echo '========== DEPLOYMENT FAILED =========='

            sh '''
            echo "Rolling back Kubernetes Deployment..."

            bash deployment/rollback.sh || true
            kubectl get pods -n sentinelops
            '''
            echo '''
==================================================
      SENTINELOPS PIPELINE FAILED
==================================================
            '''
        }
    }
}
