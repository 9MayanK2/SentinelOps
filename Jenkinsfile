pipeline {
    agent any

    options {
        timestamps()
        buildDiscarder(logRotator(numToKeepStr: '30'))
    }

    environment {
        PROJECT_NAME = "SentinelOps"
        PYTHONPATH = "."
        PATH = "${WORKSPACE}/.venv/bin:${env.PATH}"

        AWS_REGION = "us-east-1"
        AWS_ACCOUNT_ID = "284064534086"

        EKS_CLUSTER = "sentinelops-dev-eks"
        IMAGE_TAG = "build-${BUILD_NUMBER}"
        BACKEND_REPOSITORY = "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/sentinelops-backend"
        FRONTEND_REPOSITORY = "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/sentinelops-frontend"
        BACKEND_IMAGE = "${BACKEND_REPOSITORY}:${IMAGE_TAG}"
        FRONTEND_IMAGE = "${FRONTEND_REPOSITORY}:${IMAGE_TAG}"

        // Cloud Database & Security Framework Controls
        DB_TYPE = "mysql"
        DB_HOST = "sentinelops-dev-mysql.ccxs8u0gof49.us-east-1.rds.amazonaws.com"
        DB_PORT = "3306"
        DB_NAME = "sentinelops"
        DB_USER = "admin"
    }

    stages {

        /********************************************************************
         * STAGE 1 : PREPARE WORKSPACE
         ********************************************************************/
        stage('Stage 1 : Prepare Workspace') {
            steps {
                echo '========== STAGE 1 : PREPARE WORKSPACE =========='
                sh '''
                echo "[INFO] Cleaning old workspace artifacts..."
                rm -rf compliance/reports/executive_reports/* || true
                rm -rf compliance/reports/gitleaks/* || true
                rm -rf compliance/reports/hadolint/* || true
                rm -rf compliance/reports/trivy/* || true
                rm -rf compliance/reports/zap/* || true
                docker compose down --remove-orphans || true
                docker image prune -f || true
                '''
                checkout scm
            }
        }

        /********************************************************************
         * STAGE 2 : VALIDATE REPOSITORY STRUCTURE
         ********************************************************************/
        stage('Stage 2 : Validate Repository') {
            steps {
                echo '========== STAGE 2 : VALIDATING REPOSITORY STRUCTURE =========='
                sh '''
                test -d security || (echo "[ERROR] Missing security/ directory!" && exit 1)
                test -d monitoring || (echo "[ERROR] Missing monitoring/ directory!" && exit 1)
                test -d deployment || (echo "[ERROR] Missing deployment/ directory!" && exit 1)
                test -d app || (echo "[ERROR] Missing app/ directory!" && exit 1)
                test -f Jenkinsfile || (echo "[ERROR] Missing Jenkinsfile!" && exit 1)
                test -f requirements.txt || (echo "[ERROR] Missing requirements.txt!" && exit 1)
                echo "[SUCCESS] Repository structure validated."
                '''
            }
        }

        /********************************************************************
         * STAGE 3 : CREATE VIRTUAL ENVIRONMENT
         ********************************************************************/
        stage('Stage 3 : Create Python Environment') {
            steps {
                echo '========== STAGE 3 : CREATING PYTHON VENV =========='
                sh '''
                python3 -m venv .venv || true
                . .venv/bin/activate || true
                python3 -m pip install --upgrade pip setuptools wheel || true
                '''
            }
        }

        /********************************************************************
         * STAGE 4 : INSTALL DEPENDENCIES
         ********************************************************************/
        stage('Stage 4 : Install Dependencies') {
            steps {
                echo '========== STAGE 4 : INSTALLING REQUIREMENTS =========='
                sh '''
                pip3 install -r requirements.txt || pip install -r requirements.txt || true
                '''
            }
        }

        /********************************************************************
         * STAGE 5 : GENERATE .ENV FILE
         ********************************************************************/
        stage('Stage 5 : Generate .env File') {
            steps {
                echo '========== STAGE 5 : GENERATING APPLICATION & PIPELINE ENVIRONMENT =========='
                withCredentials([
                    string(credentialsId: 'MONGO_URL', variable: 'MONGO_URL'),
                    string(credentialsId: 'JWT_SECRET', variable: 'JWT_SECRET'),
                    string(credentialsId: 'EMAIL_USER', variable: 'EMAIL_USER'),
                    string(credentialsId: 'EMAIL_PASS', variable: 'EMAIL_PASS'),
                    string(credentialsId: 'DB_PASSWORD', variable: 'DB_PASSWORD'),
                    string(credentialsId: 'NVD_API_KEY', variable: 'NVD_API_KEY'),
                    string(credentialsId: 'COSIGN_PASSWORD', variable: 'COSIGN_PASSWORD')
                ]) {
                    sh '''
                    # Application server .env
                    cat > app/server/.env <<EOF
PORT=5000
MONGO_URL=${MONGO_URL}
JWT_SECRET=${JWT_SECRET}
EMAIL_USER=${EMAIL_USER}
EMAIL_PASS=${EMAIL_PASS}
EOF

                    # Root DevSecOps Framework .env
                    cat > .env <<EOF
DB_TYPE=${DB_TYPE}
DB_HOST=${DB_HOST}
DB_PORT=${DB_PORT}
DB_NAME=${DB_NAME}
DB_USER=${DB_USER}
DB_PASSWORD=${DB_PASSWORD}
NVD_API_KEY=${NVD_API_KEY}
COSIGN_PASSWORD=${COSIGN_PASSWORD}
PROJECT_NAME=${PROJECT_NAME}
REPOSITORY_URL=${GIT_URL:-https://github.com/9MayanK2/DevSecOps}
BRANCH_NAME=${GIT_BRANCH:-main}
SOFT_FAIL=false
EOF
                    '''
                }
            }
        }

        /********************************************************************
         * STAGE 6 : VALIDATE TOOLS & ENVIRONMENT
         ********************************************************************/
        stage('Stage 6 : Validate Environment & Tools') {
            steps {
                echo '========== STAGE 6 : VALIDATING CLI TOOLS =========='
                sh '''
                python3 --version
                docker --version
                aws --version || true
                kubectl version --client || true
                helm version || true
                echo "[SUCCESS] Environment tools validated."
                '''
            }
        }

        /********************************************************************
         * STAGE 7 : CLEAN DOCKER ENVIRONMENT
         ********************************************************************/
        stage('Stage 7 : Clean Docker Environment') {
            steps {
                echo '========== STAGE 7 : CLEAN DOCKER ENVIRONMENT =========='
                sh '''
                docker compose down --remove-orphans || true
                docker network prune -f || true
                '''
            }
        }

        /********************************************************************
         * PARALLEL PRE-BUILD SCANS : STAGE 8 (GITLEAKS) & STAGE 9 (HADOLINT)
         ********************************************************************/
        stage('Pre-Build Parallel Security Scans') {
            parallel {
                stage('Stage 8 : Gitleaks Secrets Scan') {
                    steps {
                        echo '========== STAGE 8 : GITLEAKS SECRETS SCAN =========='
                        sh './security/run_pipeline.sh pre-build gitleaks'
                    }
                }

                stage('Stage 9 : Hadolint Dockerfile Scan') {
                    steps {
                        echo '========== STAGE 9 : HADOLINT DOCKERFILE SCAN =========='
                        sh './security/run_pipeline.sh pre-build hadolint'
                    }
                }
            }
        }

        /********************************************************************
         * PARALLEL DOCKER BUILDS : STAGE 10 (BACKEND) & STAGE 11 (FRONTEND)
         ********************************************************************/
        stage('Parallel Docker Image Builds') {
            parallel {
                stage('Stage 10 : Build Backend Image') {
                    steps {
                        echo '========== STAGE 10 : BUILDING BACKEND IMAGE =========='
                        sh 'docker build -t sentinelops-backend:latest -t sentinelops-backend:${IMAGE_TAG} ./app/server'
                    }
                }

                stage('Stage 11 : Build Frontend Image') {
                    steps {
                        echo '========== STAGE 11 : BUILDING FRONTEND IMAGE =========='
                        sh 'docker build -t sentinelops-frontend:latest -t sentinelops-frontend:${IMAGE_TAG} ./app/client'
                    }
                }
            }
        }

        /********************************************************************
         * PARALLEL TRIVY VULNERABILITY SCANS : STAGE 12
         ********************************************************************/
        stage('Parallel Trivy Container Scans') {
            parallel {
                stage('Stage 12a : Trivy Backend Image Scan') {
                    steps {
                        echo '========== STAGE 12a : TRIVY BACKEND CONTAINER SCAN =========='
                        sh 'bash security/container/trivy.sh backend'
                    }
                }

                stage('Stage 12b : Trivy Frontend Image Scan') {
                    steps {
                        echo '========== STAGE 12b : TRIVY FRONTEND CONTAINER SCAN =========='
                        sh 'bash security/container/trivy.sh frontend'
                    }
                }
            }
        }

        /********************************************************************
         * STAGE 13 : START APPLICATION CONTAINERS
         ********************************************************************/
        stage('Stage 13 : Start Application Containers') {
            steps {
                echo '========== STAGE 13 : STARTING APPLICATION VIA DOCKER COMPOSE =========='
                sh 'docker compose up -d --force-recreate'
            }
        }

        /********************************************************************
         * STAGE 14 : APPLICATION HEALTH CHECK
         ********************************************************************/
        stage('Stage 14 : Application Health Check') {
            steps {
                echo '========== STAGE 14 : HEALTH CHECK VERIFICATION =========='
                sh '''
                for i in {1..30}
                do
                    if curl -fs http://localhost:5000/health > /dev/null
                    then
                        echo "[SUCCESS] Backend is healthy."
                        exit 0
                    fi
                    echo "Waiting for backend health check..."
                    sleep 5
                done
                echo "[ERROR] Backend health check failed!"
                exit 1
                '''
            }
        }

        /********************************************************************
         * STAGE 15 : OWASP ZAP DAST DYNAMIC SCAN
         ********************************************************************/
        stage('Stage 15 : OWASP ZAP DAST Scan') {
            steps {
                echo '========== STAGE 15 : OWASP ZAP DAST DYNAMIC SCAN =========='
                sh './security/run_pipeline.sh dast zap'
            }
        }

        /********************************************************************
         * STAGE 16 : SECURITY ORCHESTRATOR & NORMALIZATION
         ********************************************************************/
        stage('Stage 16 : Security Orchestrator & Risk Engine') {
            steps {
                echo '========== STAGE 16 : PARSING, NORMALIZATION, AGGREGATION, RISK & COMPLIANCE ENGINE =========='
                sh './security/run_pipeline.sh report'
            }
        }

        /********************************************************************
         * STAGE 17 & 18 : VERIFY AMAZON RDS CONNECTIVITY & INGESTION
         ********************************************************************/
        stage('Stage 17 & 18 : Verify RDS Database Persistence') {
            steps {
                echo '========== STAGE 17 & 18 : VERIFYING RDS MYSQL CONNECTION & INGESTED SCAN RECORDS =========='
                sh 'PYTHONPATH=. python3 security/scripts/verify_db.py'
            }
        }

        /********************************************************************
         * STAGE 19 : REPORT GENERATION
         ********************************************************************/
        stage('Stage 19 : Generate Executive Security Reports') {
            steps {
                echo '========== STAGE 19 : GENERATING HTML & PDF REPORTS =========='
                sh './security/run_pipeline.sh report'
            }
        }

        /********************************************************************
         * STAGE 20 : ARCHIVE SECURITY REPORT ARTIFACTS
         ********************************************************************/
        stage('Stage 20 : Archive Reports & Artifacts') {
            steps {
                echo '========== STAGE 20 : ARCHIVING REPORT ARTIFACTS =========='
                archiveArtifacts artifacts: 'compliance/reports/**/*', allowEmptyArchive: true
                archiveArtifacts artifacts: 'compliance/master_reports/**/*', allowEmptyArchive: true
                archiveArtifacts artifacts: 'compliance/logs/**/*', allowEmptyArchive: true
            }
        }

        /********************************************************************
         * STAGE 21 : EXECUTIVE SECURITY SUMMARY
         ********************************************************************/
        stage('Stage 21 : Executive Security Summary') {
            steps {
                echo '========== STAGE 21 : PRINTING EXECUTIVE SECURITY SUMMARY =========='
                sh 'cat compliance/master_reports/master_report.json | grep -A 20 "summary" || true'
            }
        }

        /********************************************************************
         * STAGE 22 : SECURITY GATE EVALUATION
         ********************************************************************/
        stage('Stage 22 : Security Gate Evaluation') {
            steps {
                echo '========== STAGE 22 : SECURITY GATE POLICY EVALUATION =========='
                sh './security/run_pipeline.sh gate'
            }
        }

        /********************************************************************
         * STAGE 23 : COSIGN DIGITAL SIGNING
         ********************************************************************/
        stage('Stage 23 : Cosign PKI Image Signing') {
            steps {
                echo '========== STAGE 23 : COSIGN PKI DIGITAL IMAGE SIGNING =========='
                sh './security/run_pipeline.sh sign'
            }
        }

        /********************************************************************
         * STAGE 24 : VERIFY SIGNATURES
         ********************************************************************/
        stage('Stage 24 : Verify Digital Signatures') {
            steps {
                echo '========== STAGE 24 : VERIFYING COSIGN SIGNATURES =========='
                sh './security/run_pipeline.sh verify'
            }
        }

        /********************************************************************
         * STAGE 25 : LOGIN AMAZON ECR
         ********************************************************************/
        stage('Stage 25 : Login to Amazon ECR') {
            steps {
                echo '========== STAGE 25 : AUTHENTICATING WITH AMAZON ECR =========='
                sh '''
                aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com
                '''
            }
        }

        /********************************************************************
         * STAGE 26 : PUSH IMAGES TO ECR
         ********************************************************************/
        stage('Stage 26 : Push Images to Amazon ECR') {
            steps {
                echo '========== STAGE 26 : PUSHING CONTAINER IMAGES TO ECR =========='
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

        /********************************************************************
         * STAGE 27 : DEPLOY TO AMAZON EKS
         ********************************************************************/
        stage('Stage 27 : Deploy to Amazon EKS') {
            steps {
                echo '========== STAGE 27 : DEPLOYING TO AMAZON EKS KUBERNETES CLUSTER =========='
                sh '''
                aws eks update-kubeconfig --region ${AWS_REGION} --name ${EKS_CLUSTER}
                bash deployment/deploy.sh ${IMAGE_TAG}
                '''
            }
        }

        /********************************************************************
         * STAGE 28 : VERIFY KUBERNETES ROLLOUT
         ********************************************************************/
        stage('Stage 28 : Verify Kubernetes Deployment') {
            steps {
                echo '========== STAGE 28 : VERIFYING EKS POD ROLLOUT STATUS =========='
                sh '''
                kubectl rollout status deployment/backend -n sentinelops --timeout=5m
                kubectl rollout status deployment/frontend -n sentinelops --timeout=5m
                '''
            }
        }

        /********************************************************************
         * STAGE 29 : PIPELINE CLEANUP & COMPLETION
         ********************************************************************/
        stage('Stage 29 : Final Pipeline Cleanup') {
            steps {
                echo '========== STAGE 29 : WORKSPACE & TEMPORARY CLEANUP =========='
                sh '''
                docker compose down --remove-orphans || true
                docker image prune -f || true
                '''
            }
        }

    }

    /********************************************************************
     * POST ACTIONS (NOTIFICATIONS, ARCHIVING & ROLLBACK)
     ********************************************************************/
    post {
        always {
            echo '========== ARCHIVING ALL LOGS AND REPORTS =========='
            archiveArtifacts artifacts: 'compliance/reports/**/*', allowEmptyArchive: true
            archiveArtifacts artifacts: 'compliance/master_reports/**/*', allowEmptyArchive: true
            archiveArtifacts artifacts: 'compliance/logs/**/*', allowEmptyArchive: true
            archiveArtifacts artifacts: 'compliance/reports/signing/**/*', allowEmptyArchive: true
        }

        success {
            echo '''
======================================================================
      🚀 SENTINELOPS ENTERPRISE DEVSECOPS PIPELINE SUCCESS 🚀
   Historical scan analytics persisted to AWS RDS MySQL.
   Real-time Grafana security dashboards updated.
======================================================================
            '''
        }

        failure {
            echo '========== DEPLOYMENT FAILED — EXECUTING ROLLBACK =========='
            sh '''
            echo "[WARNING] Security Gate or Deployment failed. Rolling back Kubernetes release..."
            bash deployment/rollback.sh || true
            kubectl get pods -n sentinelops || true
            '''
        }
    }
}
