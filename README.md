# 🚀 SentinelAI-Ops — Enterprise DevSecOps Security Orchestrator Framework with AI remediation Pipeline

> **Project Codename:** SentinelAI-Ops  
> **Application Name:** HopeGivers — A Real-Time Blood Donation & Recipient Matching Platform  
> **Status:** Production-Grade | 29-Stage CI/CD | Multi-Cloud Ready | AI-Powered Security Remediation

---

## 📋 Table of Contents

1. [Project Overview](#-project-overview)
2. [Architecture at a Glance](#-architecture-at-a-glance)
3. [Application Deep Dive](#-application-deep-dive)
4. [Repository Structure](#-repository-structure)
5. [DevSecOps Pipeline (29 Stages)](#-devsecops-pipeline-29-stages)
6. [Security Framework](#-security-framework)
7. [AI-Powered Remediation Engine](#-ai-powered-remediation-engine)
8. [Infrastructure as Code (Terraform)](#-infrastructure-as-code-terraform)
9. [Kubernetes & Helm Deployment](#-kubernetes--helm-deployment)
10. [Monitoring & Observability](#-monitoring--observability)
11. [Compliance & Reporting](#-compliance--reporting)
12. [Environment Configuration](#-environment-configuration)
13. [Pre-Commit Hooks](#-pre-commit-hooks)
14. [Quick Start Guide](#-quick-start-guide)
15. [Team & Credits](#-team--credits)

---

## 🎯 Project Overview

**SentinelOps** is a production-grade, end-to-end **DevSecOps Automated Security Pipeline** built around a real-world full-stack application — **HopeGivers**, a blood donation and recipient matching platform. This project demonstrates how to integrate security at every stage of the software delivery lifecycle using industry-standard tools, custom Python security frameworks, and cloud-native infrastructure.

### Why This Project Matters

Instead of treating security as a final checkpoint, this pipeline **shifts security left** — catching vulnerabilities at:
- **Source code stage** (pre-commit hooks, SAST)
- **Container build stage** (Dockerfile linting, image CVE scanning)
- **Runtime stage** (DAST, compliance mapping, risk scoring)
- **Deployment stage** (signed images, Kubernetes security contexts)
- **Post-deployment** (monitoring, AI-driven remediation)

### Business Problems Solved

| Problem | Solution |
|---------|----------|
| Insecure code reaching production | Pre-commit hooks (Gitleaks, Semgrep, ESLint) + SAST |
| Vulnerable container images deployed | Trivy image scanning in CI gate |
| No visibility into runtime threats | OWASP ZAP DAST + Wazuh HIDS + Grafana dashboards |
| Manual compliance reporting | Python compliance engine auto-generating NIST/CIS/OWASP reports |
| Hardcoded secrets in code/K8s manifests | AWS Secrets Manager + K8s RBAC + Gitleaks scanning |
| No automated remediation guidance | AI RAG engine with ChromaDB + LLM for contextual fixes |

---

## 🏗️ Architecture at a Glance

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              LAYER 1: DEV                                   │
│  GitHub → Pre-commit (Gitleaks, Semgrep, ESLint) → Branch Protection      │
└─────────────────────────────────────────────────────────────────────────────┘
                                      ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│                           LAYER 2: CI/CD (Jenkins)                          │
│  Checkout → Build → SAST → Secret Scan → Container Scan → DAST → Sign     │
└─────────────────────────────────────────────────────────────────────────────┘
                                      ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│                        LAYER 3: SECURITY ORCHESTRATOR                       │
│  Parser Registry → Risk Engine → Compliance Mapper (4-Layer) → Gate       │
└─────────────────────────────────────────────────────────────────────────────┘
                                      ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│                      LAYER 4: CLOUD DEPLOY (AWS EKS)                        │
│  Terraform (VPC, EKS, RDS, ECR) → Helm Charts → K8s Manifests             │
└─────────────────────────────────────────────────────────────────────────────┘
                                      ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│                     LAYER 5: MONITORING & OBSERVABILITY                     │
│  Prometheus → Grafana (MySQL-backed Security Dashboards) → ELK Stack      │
└─────────────────────────────────────────────────────────────────────────────┘
                                      ↓
┌─────────────────────────────────────────────────────────────────────────────┐
│                    LAYER 6: AI REMEDIATION & COMPLIANCE                     │
│  RAG Engine (ChromaDB + LLM) → Executive Reports → Compliance Matrix      │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 💉 Application Deep Dive

### HopeGivers — Blood Donation Platform

The core application is a **MERN stack** (MongoDB, Express, React, Node.js) web platform that connects blood donors with recipients in real-time.

#### Key Features

| Feature | Description |
|---------|-------------|
| **Donor-Recipient Matching** | Intelligent real-time algorithm matching blood type, location, and urgency |
| **OTP-Based Authentication** | Secure login with email OTP verification and JWT token management |
| **Password Recovery** | Full forgot-password flow with OTP verification and secure token-based reset |
| **Urgent Notifications** | Instant alerts to verified donors when critical blood needs arise |
| **Track Records** | Complete donation history logging for medical accountability |
| **AI ChatBot** | Integrated chat assistant for user queries and guidance |
| **Feedback System** | User feedback collection for continuous improvement |
| **Contact & About Pages** | Public informational pages about the mission and team |

#### Tech Stack

**Frontend (`app/client/`)**
- React 18 with JSX
- React Router DOM (v6) for SPA navigation
- Custom CSS modules per component
- Responsive design with mobile support
- Nginx reverse proxy (Alpine-based, non-root user)

**Backend (`app/server/`)**
- Node.js 20 + Express.js
- MongoDB (Mongoose ODM)
- JWT authentication with `verifyToken` middleware
- Nodemailer for OTP email delivery
- bcrypt for password hashing
- RESTful API architecture

**Database Models**
- `User` — Authentication, OTP, password reset tokens
- `Donor` — Donor profiles with blood group, location, availability status
- `Contact` — Contact form submissions
- `Feedback` — User feedback entries

#### API Endpoints

| Route | Method | Description | Auth |
|-------|--------|-------------|------|
| `/` | GET | Home page data | Public |
| `/health` | GET | Health check endpoint | Public |
| `/user/auth/register` | POST | User registration | Public |
| `/user/auth/login` | POST | User login | Public |
| `/user/auth/forget-password` | POST | Initiate password reset | Public |
| `/user/auth/verify-otp` | POST | Verify OTP | Public |
| `/user/auth/update-password` | POST | Reset password | Token |
| `/user/auth/get-access` | GET | Validate token | Token |

---

## 📁 Repository Structure

```
DevSecOps/
│
├── 📄 .env.example                  # Environment variable template
├── 📄 .gitignore                    # Git ignore rules
├── 📄 .pre-commit-config.yaml       # Pre-commit hooks (Gitleaks, ESLint, Semgrep)
├── 📄 Jenkinsfile                   # 29-stage declarative CI/CD pipeline
├── 📄 docker-compose.yml            # Local development orchestration
├── 📄 requirements.txt              # Python dependencies for security framework
│
├── 📁 app/                          # 🩸 HopeGivers Application
│   ├── client/                      # React frontend
│   │   ├── Dockerfile               # Multi-stage build (Node → Nginx Alpine)
│   │   ├── nginx/nginx.conf         # Custom Nginx config (non-root, port 8080)
│   │   ├── package.json             # React dependencies
│   │   └── src/
│   │       ├── App.jsx              # Main router component
│   │       ├── Home.jsx             # Landing page with blood data
│   │       ├── components/
│   │       │   ├── auth/            # Login, Register, OTP, Password Reset
│   │       │   ├── bot/             # AI ChatBot component
│   │       │   ├── navbar/          # Navbar & Footer
│   │       │   └── ui/              # Reusable UI components
│   │       ├── pages/               # Donor, Receiver, About, Contact, Feedback
│   │       ├── style/               # Component-specific CSS
│   │       └── utils/apis.js        # API endpoint constants
│   └── server/                      # Express backend
│       ├── Dockerfile               # Hardened Node.js Alpine image
│       ├── index.js                 # Express server entrypoint
│       ├── package.json             # Node dependencies
│       ├── controllers/             # Route handlers (auth, home, pages)
│       ├── middleware/              # verifyToken.js (JWT validation)
│       ├── models/                  # Mongoose schemas (User, Donor, Contact, Feedback)
│       ├── routes/                  # Express route definitions
│       └── utils/                   # DB connection & email sender
│
├── 📁 ai/                           # 🤖 AI-Powered Security Remediation
│   ├── core/
│   │   ├── chroma_client.py         # Vector DB client (ChromaDB)
│   │   ├── context_builder.py       # LLM prompt engineering
│   │   ├── llm_client.py            # Free-tier LLM integration
│   │   ├── mysql_client.py          # RDS MySQL query client
│   │   └── rag_engine.py            # RAG orchestrator (Vector + Relational + LLM)
│   ├── data/
│   │   └── remediation_kb.json      # Security remediation knowledge base
│   ├── scripts/
│   │   ├── diagnose.py              # CLI diagnosis tool
│   │   └── embed_remediation.py     # KB indexing script
│   └── requirements.txt             # AI module dependencies
│
├── 📁 compliance/                   # 📊 Security Reports & Compliance Data
│   ├── db/
│   │   ├── nvd_cache.json           # NVD API cache
│   │   └── security_framework.db    # Local SQLite fallback
│   ├── logs/
│   │   └── parser.log               # Security parser logs
│   ├── master_reports/
│   │   └── master_report.json       # Aggregated security report
│   ├── normalized/                  # Normalized scanner outputs
│   │   ├── gitleaks/                # Secret scan normalized reports
│   │   ├── hadolint/                # Dockerfile lint normalized reports
│   │   ├── trivy/                   # Container scan normalized reports
│   │   └── zap/                     # DAST scan normalized reports
│   └── reports/
│       ├── compliance/
│       │   └── compliance_matrix.json
│       ├── executive_reports/       # Generated HTML & PDF reports
│       ├── gitleaks/                # Raw Gitleaks JSON outputs
│       ├── hadolint/                # Raw Hadolint JSON outputs
│       ├── trivy/                   # Raw Trivy JSON outputs
│       └── zap/                     # Raw ZAP JSON outputs
│
├── 📁 deployment/                   # 🚀 K8s Deployment Scripts
│   ├── deploy.sh                    # Main deployment script
│   ├── rollback.sh                  # Rollback script
│   ├── update-image.sh              # Image tag updater
│   └── verify-rollout.sh            # Rollout verification
│
├── 📁 docs/                         # 📚 Project Documentation
│   ├── DevSecOps_Project_Guide.md   # Full 12-week project guide
│   ├── 03-solution-architecture.md
│   ├── 04-AWS-Infrastructure.md
│   ├── 05-Terraform-IaC.md
│   ├── 06-Docker-Containerization.md
│   ├── 07-Jenkins-CI-CD.md
│   ├── 08-DevSecOps-Pipeline.md
│   ├── 09-Security-Orchestrator.md
│   ├── 10-Compliance-Engine.md
│   ├── 11-Kubernetes-Architecture.md
│   ├── 12-Monitoring-Observability.md
│   └── 13-GitOps-ArgoCD.md
│
├── 📁 helm/                         # ⎈ Helm Charts
│   └── sentinelops/
│       ├── Chart.yaml               # Helm chart metadata
│       ├── values.yaml              # Configurable values
│       └── templates/               # K8s manifest templates
│           ├── backend-deployment.yaml
│           ├── backend-service.yaml
│           ├── frontend-deployment.yaml
│           ├── frontend-service.yaml
│           ├── ingress.yaml
│           ├── configmap.yaml
│           └── secret.yaml
│
├── 📁 K8s/                          # ☸️ Raw Kubernetes Manifests
│   ├── backend/
│   │   ├── deployment.yaml          # Backend deployment (2 replicas, probes)
│   │   └── service.yaml             # Backend ClusterIP service
│   ├── frontend/
│   │   ├── deployment.yaml          # Frontend deployment
│   │   └── service.yaml             # Frontend ClusterIP service
│   ├── ingress/
│   │   └── ingress.yaml             # AWS ALB Ingress (path-based routing)
│   ├── configmap.yaml               # Non-sensitive config
│   ├── namespace.yaml               # sentinelops namespace
│   └── secret-template.yaml         # Secret template (base64 encoded)
│
├── 📁 monitoring/                   # 📈 Observability Stack
│   ├── grafana/
│   │   ├── dashboards/
│   │   │   ├── dashboards.yaml      # Dashboard provisioning
│   │   │   └── security_overview_dashboard.json
│   │   ├── datasources/
│   │   │   └── mysql.yaml           # MySQL data source config
│   │   └── ingress.yaml             # Grafana ingress
│   ├── kube-prometheus/
│   │   └── values.yaml              # Prometheus Helm values
│   └── storageclass/
│       └── gp3.yaml                 # AWS gp3 storage class
│
├── 📁 scripts/                      # 🛠️ Infrastructure Setup Scripts
│   ├── install_aws_cli.sh
│   ├── install_docker.sh
│   ├── install_jenkins.sh
│   ├── install_kubectl.sh
│   └── install_terraform.sh
│
├── 📁 security/                     # 🔒 Enterprise Security Framework
│   ├── common/                      # Shared utilities
│   │   ├── categories.py            # Finding category definitions
│   │   ├── logger.py                # Centralized logging
│   │   ├── metadata.py              # Report metadata builder
│   │   ├── notifier.py              # Webhook/email alerts
│   │   ├── recommendation.py        # Auto-recommendation engine
│   │   ├── scanner_type.py          # Scanner enum definitions
│   │   ├── severity.py              # Severity level definitions
│   │   ├── status.py                # Finding status enum
│   │   └── validator.py             # Input validation utilities
│   ├── config/
│   │   ├── config_loader.py         # Configuration loader
│   │   ├── keys/
│   │   │   ├── cosign.key           # Cosign private key
│   │   │   └── cosign.pub           # Cosign public key
│   │   ├── parser.conf              # Parser configuration
│   │   ├── policy.yaml              # Security gate policy rules
│   │   └── tools.conf               # Scanner tool configurations
│   ├── container/
│   │   ├── hadolint.sh              # Dockerfile linting script
│   │   └── trivy.sh                 # Container CVE scanning script
│   ├── core/                        # 🧠 Core Security Engine
│   │   ├── aggregator.py            # Multi-scanner result aggregator
│   │   ├── base_parser.py           # Abstract base parser class
│   │   ├── compliance_mapper.py     # 4-Layer compliance mapping engine
│   │   ├── exceptions.py            # Custom exceptions
│   │   ├── nvd_enrichment.py        # NVD API 2.0 threat intel
│   │   ├── orchestrator.py          # 5-Stage security orchestrator
│   │   ├── parser_registry.py       # Auto-registering parser registry
│   │   ├── report_generator.py      # HTML/PDF report generator
│   │   ├── report_reader.py         # Report file reader
│   │   ├── report_writer.py         # Report file writer
│   │   ├── risk_engine.py           # Weighted risk scoring engine
│   │   ├── security_gate.py         # Policy-based gate evaluator
│   │   └── statistics.py            # Scan statistics calculator
│   ├── dast/
│   │   └── zap.sh                   # OWASP ZAP DAST automation
│   ├── db/
│   │   ├── database.py              # Multi-DB persistence (SQLite/MySQL/PostgreSQL)
│   │   └── query_db.py              # DB query utilities
│   ├── knowledge/                   # 📖 Security Knowledge Base
│   │   ├── build_compliance_db.py   # CWE compliance DB builder
│   │   ├── cwe_compliance_db.json   # CWE → OWASP/CIS/NIST mappings
│   │   ├── framework_config.json    # Framework configuration
│   │   ├── gitleaks_rules.json      # Gitleaks rule definitions
│   │   ├── hadolint_rules.json      # Hadolint rule definitions
│   │   └── trivy_rules.json         # Trivy rule definitions
│   ├── parsers/                     # 📥 Scanner Output Parsers
│   │   ├── gitleaks_parser.py       # Gitleaks JSON → normalized
│   │   ├── hadolint_parser.py       # Hadolint JSON → normalized
│   │   ├── parser_utils.py          # Shared parser utilities
│   │   ├── trivy_parser.py          # Trivy JSON → normalized
│   │   └── zap_parser.py            # ZAP JSON → normalized
│   ├── policies/
│   │   └── security-policy.conf     # Security policy configuration
│   ├── schemas/                     # 📐 Data Models
│   │   ├── finding.py               # Finding dataclass
│   │   ├── report.py                # Report dataclass
│   │   └── summary.py               # Summary dataclass
│   ├── scripts/                     # 🔧 Helper Scripts
│   │   ├── config.sh                # Environment setup
│   │   ├── docker.sh                # Docker utilities
│   │   ├── logger.sh                # Logging utilities
│   │   ├── report.sh                # Report generation wrapper
│   │   ├── utils.sh                 # Common shell utilities
│   │   └── verify_db.py             # DB connectivity verifier
│   ├── secrets/
│   │   └── gitleaks.sh              # Secret detection automation
│   └── signing/                     # 🔏 Image Signing
│       ├── generate_keys.sh         # Cosign key generation
│       ├── sign_images.sh           # Image signing script
│       └── verify_images.sh         # Signature verification
│
├── 📁 terraform/                    # 🌍 Infrastructure as Code
│   ├── main.tf                      # Root module composition
│   ├── provider.tf                  # AWS provider config
│   ├── variables.tf                 # Input variables
│   ├── outputs.tf                   # Output values
│   ├── versions.tf                  # Terraform version constraints
│   ├── data.tf                      # Data sources (AMI lookup)
│   └── modules/
│       ├── ec2/                     # Jenkins server + Elastic IP
│       ├── ecr/                     # Container registries (backend + frontend)
│       ├── eks/                     # Managed Kubernetes cluster
│       ├── network/                 # VPC, subnets, NAT, security groups
│       └── rds/                     # Managed MySQL database
│
└── 📁 Detail/                       # 📎 Architecture Diagrams
    ├── DevSecOps Automated Security Pipeline — Architecture.pdf
    └── DevSecOps_Project_Guide.pdf
```

---

## 🔧 DevSecOps Pipeline (29 Stages)

The `Jenkinsfile` defines a comprehensive 29-stage declarative pipeline that automates the entire software delivery lifecycle with security embedded at every step.

### Stage Breakdown

| Stage # | Name | Purpose | Tools |
|---------|------|---------|-------|
| 1 | **Prepare Workspace** | Clean old artifacts, prune Docker | Shell |
| 2 | **Validate Repository** | Verify required directories exist | Shell |
| 3 | **Create Python Environment** | Set up virtual environment | Python venv |
| 4 | **Install Dependencies** | Install Python requirements | pip |
| 5 | **Generate .env File** | Create app & pipeline env from Jenkins credentials | Credentials Plugin |
| 6 | **Pre-commit Hooks** | Run Gitleaks, ESLint, Semgrep | pre-commit |
| 7 | **SAST — Semgrep** | Static application security testing | Semgrep |
| 8 | **Secret Scan — Gitleaks** | Detect committed secrets | Gitleaks |
| 9 | **Dockerfile Lint — Hadolint** | Lint backend & frontend Dockerfiles | Hadolint |
| 10 | **Build Backend Image** | Build hardened Node.js image | Docker |
| 11 | **Build Frontend Image** | Build multi-stage React → Nginx image | Docker |
| 12 | **Container Scan — Trivy (Backend)** | CVE scan backend image | Trivy |
| 13 | **Container Scan — Trivy (Frontend)** | CVE scan frontend image | Trivy |
| 14 | **Start Application Stack** | Launch services via Docker Compose | docker-compose |
| 15 | **OWASP ZAP DAST Scan** | Dynamic application security testing | OWASP ZAP |
| 16 | **Security Orchestrator** | Parse, normalize, aggregate, risk & compliance | Python Framework |
| 17-18 | **Verify RDS Database** | Confirm MySQL connectivity & ingested records | Python |
| 19 | **Generate Executive Reports** | HTML & PDF security reports | Python |
| 20 | **Archive Reports** | Store artifacts in Jenkins | archiveArtifacts |
| 21 | **Executive Security Summary** | Print summary to console | Shell |
| 22 | **Security Gate Evaluation** | Policy-based pass/fail decision | Python |
| 23 | **Cosign PKI Image Signing** | Digitally sign container images | Cosign |
| 24 | **Verify Digital Signatures** | Verify image signatures | Cosign |
| 25 | **Login to Amazon ECR** | Authenticate with AWS ECR | AWS CLI |
| 26 | **Push Images to ECR** | Push signed images with tags | Docker |
| 27 | **Deploy to Amazon EKS** | Update K8s deployments | kubectl |
| 28 | **Verify Kubernetes Rollout** | Confirm pod health | kubectl |
| 29 | **Final Pipeline Cleanup** | Remove temporary resources | Shell |

### Pipeline Features

- **Credential Injection**: All sensitive values (DB passwords, JWT secrets, email credentials, NVD API key, Cosign password) are injected via Jenkins Credentials Plugin — never hardcoded
- **Parallel Security Scanning**: Multiple scanners run in sequence with independent failure handling
- **Automatic Rollback**: On pipeline failure, Kubernetes rollout is automatically rolled back
- **Artifact Archival**: All reports, logs, and scan results are archived for audit trails
- **Multi-DB Support**: Security data persists to AWS RDS MySQL with automatic SQLite fallback

---

## 🛡️ Security Framework

The `security/` directory contains a **custom-built enterprise security orchestration framework** written in Python. It is the heart of the DevSecOps pipeline, providing automated vulnerability detection, risk scoring, compliance mapping, and reporting.

### 5-Stage Execution Flow

```
Stage 1: Pre-flight Checks      → Validate Docker, directories, policy
Stage 2: Run Active Scanners    → Gitleaks, Hadolint, Trivy, ZAP
Stage 3: Run Parsers            → Normalize raw output to unified schema
Stage 4: Aggregate Results      → Combine into master_report.json
Stage 5: Security Gate          → Policy evaluation → PASS / FAIL
```

### Core Components

#### 1. Security Orchestrator (`security/core/orchestrator.py`)
Master controller that coordinates all 5 stages. Supports selective execution via CLI arguments:
```bash
./security/run_pipeline.sh full          # Run all stages
./security/run_pipeline.sh pre-build     # Run pre-build scanners
./security/run_pipeline.sh post-build    # Run post-build scanners
./security/run_pipeline.sh dast zap      # Run DAST only
./security/run_pipeline.sh report        # Generate reports
./security/run_pipeline.sh gate          # Evaluate security gate
./security/run_pipeline.sh sign          # Sign images with Cosign
./security/run_pipeline.sh verify        # Verify image signatures
```

#### 2. Risk Engine (`security/core/risk_engine.py`)
Calculates weighted risk scores using configurable severity weights:
- **CRITICAL**: 10 points
- **HIGH**: 5 points
- **MEDIUM**: 2 points
- **LOW**: 1 point
- **INFO**: 0 points

Risk levels: `NONE` → `LOW` → `MEDIUM` → `HIGH` → `CRITICAL`

#### 3. 4-Layer Compliance Mapper (`security/core/compliance_mapper.py`)
Universal compliance engine mapping every finding to **OWASP Top 10 2021**, **CIS Benchmarks**, and **NIST SP 800-53**:

| Layer | Method | Example |
|-------|--------|---------|
| **Layer 1** | Exact Rule ID Override | `DL3002` → CIS Docker Benchmark 4.1 |
| **Layer 2** | CWE Database Lookup | `CWE-89` → OWASP A03:2021-Injection |
| **Layer 3** | CWE Taxonomy Family Inference | `CWE-74–117` → Injection Family |
| **Layer 4** | Smart Category Fallback + CVSS | CVSS ≥ 9.0 → adds NIST IR-4 |

#### 4. Security Gate (`security/core/security_gate.py`)
Policy-driven evaluator that reads `security/config/policy.yaml`:
```yaml
policy:
  fail_on_critical: true      # Block if any CRITICAL findings
  fail_on_high: false         # Allow HIGH findings
  minimum_score: 70.0         # Minimum compliance score %
  max_allowed_risk_score: 50  # Maximum risk score threshold
```

#### 5. Database Persistence (`security/db/database.py`)
Cloud-ready database layer supporting:
- **SQLite** (local development)
- **MySQL/MariaDB** (AWS RDS production)
- **PostgreSQL** (alternative cloud)

Tables: `projects`, `scans`, `risk_summary`, `findings`, `compliance_results`, `reports`

#### 6. Report Generator (`security/core/report_generator.py`)
Generates executive-ready reports:
- **HTML Report**: Rich dashboard with severity charts, compliance bars, finding tables
- **PDF Report**: Print-ready executive summary
- **JSON Report**: Machine-readable master report for downstream systems

#### 7. NVD Enrichment (`security/core/nvd_enrichment.py`)
Integrates with **NVD API 2.0** to fetch real-time CVE metadata, CWE mappings, and CVSS scores for enriched threat intelligence.

### Scanner Integrations

| Scanner | Type | Coverage | Script |
|---------|------|----------|--------|
| **Gitleaks** | Secret Detection | API keys, tokens, passwords | `security/secrets/gitleaks.sh` |
| **Hadolint** | Dockerfile Lint | Best practices, security rules | `security/container/hadolint.sh` |
| **Trivy** | Container CVE Scan | OS packages, libraries, misconfigs | `security/container/trivy.sh` |
| **OWASP ZAP** | DAST | Runtime web vulnerabilities | `security/dast/zap.sh` |
| **Semgrep** | SAST | Code patterns, injection flaws | Pre-commit hook |

---

## 🤖 AI-Powered Remediation Engine

The `ai/` module implements a **Retrieval-Augmented Generation (RAG)** system that provides intelligent security remediation advice by combining:

1. **Relational Data**: Real-time vulnerability findings from MySQL RDS
2. **Vector Search**: ChromaDB embeddings of security remediation knowledge
3. **LLM Generation**: Context-aware remediation steps via free-tier LLM APIs

### Architecture

```
User Question / Finding
        ↓
┌─────────────────┐    ┌─────────────────┐
│  MySQL Client   │    │  ChromaDB       │
│  (findings DB)  │    │  (vector KB)    │
└────────┬────────┘    └────────┬────────┘
         ↓                      ↓
    ┌─────────────────────────────────┐
    │      Context Builder            │
    │  (combines findings + KB docs)  │
    └─────────────────────────────────┘
                      ↓
              ┌───────────────┐
              │   LLM Client  │
              │  (generate)   │
              └───────────────┘
                      ↓
            Remediation Advisory
```

### Key Capabilities

- **Diagnose Finding**: Query a specific finding ID → get AI-generated remediation steps
- **Diagnose Scan**: Full scan analysis → executive summary + per-finding advisories
- **Interactive Q&A**: Ask natural language questions about security posture
- **Auto-Update DB**: Write AI recommendations back to MySQL for tracking

### Knowledge Base (`ai/data/remediation_kb.json`)
Structured security knowledge covering:
- CVE-specific remediation steps
- Dockerfile hardening guides
- Secret rotation procedures
- OWASP mitigation strategies

---

## 🌍 Infrastructure as Code (Terraform)

The `terraform/` directory provisions the entire AWS infrastructure using modular Terraform code.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         AWS CLOUD                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   VPC       │  │    EKS      │  │       RDS           │ │
│  │  ┌───────┐  │  │  ┌───────┐  │  │  ┌───────────────┐  │ │
│  │  │Public │  │  │  │Nodes  │  │  │  │ MySQL 8.0     │  │ │
│  │  │Subnet │  │  │  │(t3.med)│  │  │  │ (db.t3.micro) │  │ │
│  │  │- ALB  │  │  │  └───────┘  │  │  └───────────────┘  │ │
│  │  │- NAT  │  │  └─────────────┘  │                     │ │
│  │  └───────┘  │                     │                     │ │
│  │  ┌───────┐  │  ┌─────────────┐  │  ┌───────────────┐  │ │
│  │  │Private│  │  │    ECR      │  │  │    EC2        │  │ │
│  │  │Subnet │  │  │  ┌───────┐  │  │  │  (Jenkins)    │  │ │
│  │  │- Pods │  │  │  │Backend│  │  │  │  + Elastic IP │  │ │
│  │  │- RDS  │  │  │  │Frontend│  │  │  └───────────────┘  │ │
│  │  └───────┘  │  │  └───────┘  │  │                     │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Modules

| Module | Resources | Purpose |
|--------|-----------|---------|
| **network** | VPC, IGW, NAT, 2×Public Subnets, 2×Private Subnets, Route Tables, Security Groups | Network isolation with Kubernetes tagging |
| **ec2** | Ubuntu instance, Elastic IP, IAM policy | Jenkins CI/CD server |
| **ecr** | 2×Repositories (backend + frontend), lifecycle policies | Container image registry |
| **eks** | EKS Cluster (v1.33), Managed Node Group, IAM roles | Kubernetes orchestration |
| **rds** | MySQL 8.0 instance, subnet group, security group | Security scan persistence |

### Security Features
- Private subnets for EKS nodes and RDS (no direct internet exposure)
- NAT Gateway for outbound-only traffic from private subnets
- Security groups with least-privilege rules
- IAM roles with minimal required policies (EKS, ECR, Worker Node)

---

## ☸️ Kubernetes & Helm Deployment

### Raw Manifests (`K8s/`)

Production-ready Kubernetes manifests with security hardening:

| Manifest | Security Features |
|----------|-------------------|
| `namespace.yaml` | Dedicated `sentinelops` namespace |
| `backend/deployment.yaml` | Non-root user, resource limits, readiness/liveness probes, rolling update strategy |
| `frontend/deployment.yaml` | Same hardening as backend |
| `ingress/ingress.yaml` | AWS ALB with path-based routing (`/api` → backend, `/` → frontend) |
| `configmap.yaml` | Non-sensitive configuration externalized |
| `secret-template.yaml` | Base64-encoded secrets (replaced by AWS Secrets Manager in prod) |

### Helm Chart (`helm/sentinelops/`)

Templated deployment for environment-specific configurations:
- `values.yaml` — Configurable image tags, replica counts, resource limits
- Templates for all K8s resources with Helm conditionals
- Chart version: `0.1.0`

---

## 📈 Monitoring & Observability

### Grafana Dashboard (`monitoring/grafana/`)

**DevSecOps Executive Security & Compliance Dashboard** connected to MySQL RDS:

| Panel | Metric | Visualization |
|-------|--------|---------------|
| Security Gate Verdict | Latest scan PASS/FAIL | Stat (color-coded) |
| Overall Compliance Score | Compliance percentage | Gauge (0-100%) |
| Threat Density Risk Score | Total risk points | Stat with thresholds |
| Overall Risk Level | CRITICAL/HIGH/MEDIUM/LOW | Stat (color-coded) |
| Finding Severity Distribution | Count by severity | Pie chart |
| Framework Pass Percentages | OWASP/CIS/NIST scores | Bar gauge |
| Recent Critical & High Findings | Top 50 findings | Table with details |

**Auto-refresh**: Every 1 minute

### Prometheus (`monitoring/kube-prometheus/`)
- Configured via Helm values for EKS cluster metrics
- Scrapes node-exporter, kube-state-metrics, and custom application metrics

---

## 📊 Compliance & Reporting

### Supported Frameworks

| Framework | Baseline Controls | Mapping Method |
|-----------|-------------------|----------------|
| **OWASP Top 10 2021** | 10 controls | Rule ID + CWE + Category |
| **CIS Benchmarks** | 15 controls | Docker Benchmark + Controls v8 |
| **NIST SP 800-53** | 20 controls | Control families + CVSS enhancement |

### Generated Artifacts

1. **`compliance/master_reports/master_report.json`** — Unified findings with compliance layers
2. **`compliance/reports/compliance/compliance_matrix.json`** — Framework-level scoring
3. **`compliance/reports/executive_reports/security_report.html`** — Visual HTML dashboard
4. **`compliance/reports/executive_reports/security_report.pdf`** — Print-ready PDF

### Compliance Score Calculation
```
Compliance % = (Controls Passed / Total Baseline Controls) × 100
Overall Score = Average of all framework percentages
```

---

## ⚙️ Environment Configuration

Copy `.env.example` to `.env` and configure:

```bash
# Database (AWS RDS MySQL recommended for production)
DB_TYPE=mysql
DB_HOST=sentinelops-dev-mysql.ccxs8u0gof49.us-east-1.rds.amazonaws.com
DB_PORT=3306
DB_NAME=sentinelops
DB_USER=admin
DB_PASSWORD=your_secure_password

# Local SQLite fallback
DB_PATH=compliance/db/security_framework.db

# Threat Intelligence
NVD_API_KEY=your_nvd_api_key

# Image Signing
COSIGN_PASSWORD=your_cosign_password

# DAST Target
ZAP_TARGET_URL=http://sentinelops-frontend:8080

# Gate Policy
SOFT_FAIL=false
ENFORCE_GATE=true
```

### Application Environment (`app/server/.env`)
```bash
PORT=5000
MONGO_URL=mongodb+srv://your-mongo-url
JWT_SECRET=your_jwt_secret
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_app_password
```

---

## 🪝 Pre-Commit Hooks

The `.pre-commit-config.yaml` enforces security before code ever reaches CI:

| Hook | Purpose |
|------|---------|
| **Gitleaks** | Block commits containing secrets |
| **Trailing Whitespace** | Code hygiene |
| **Check YAML/JSON** | Syntax validation |
| **Check Merge Conflicts** | Prevent conflict markers |
| **Check Large Files** | Block files > 2MB |
| **Frontend ESLint** | React code quality |
| **Backend ESLint** | Node.js code quality |
| **Semgrep SAST** | Static security analysis |

**Install hooks:**
```bash
pip install pre-commit
pre-commit install
```

---

## 🚀 Quick Start Guide

### Prerequisites
- Docker & Docker Compose
- Python 3.10+
- Node.js 20+
- AWS CLI (configured)
- kubectl
- Terraform 1.5+

### Local Development

```bash
# 1. Clone repository
git clone https://github.com/9MayanK2/DevSecOps.git
cd DevSecOps

# 2. Install pre-commit hooks
pip install pre-commit
pre-commit install

# 3. Configure environment
cp .env.example .env
# Edit .env with your credentials

# 4. Start application locally
docker-compose up --build

# 5. Access application
# Frontend: http://localhost:3000
# Backend:  http://localhost:5000
```

### Run Security Pipeline Locally

```bash
# Install Python dependencies
pip install -r requirements.txt

# Run full security pipeline
./security/run_pipeline.sh full

# Run specific stages
./security/run_pipeline.sh pre-build    # Gitleaks + Hadolint
./security/run_pipeline.sh post-build   # Trivy
./security/run_pipeline.sh dast zap     # OWASP ZAP
./security/run_pipeline.sh report       # Generate reports
./security/run_pipeline.sh gate         # Evaluate gate
```

### Deploy Infrastructure

```bash
cd terraform
terraform init
terraform plan
terraform apply
```

### Deploy to EKS

```bash
# Update kubeconfig
aws eks update-kubeconfig --region us-east-1 --name sentinelops-dev-eks

# Deploy via Helm
helm upgrade --install sentinelops ./helm/sentinelops   --namespace sentinelops   --create-namespace

# Or via raw manifests
kubectl apply -f K8s/namespace.yaml
kubectl apply -f K8s/configmap.yaml
kubectl apply -f K8s/secret-template.yaml
kubectl apply -f K8s/backend/
kubectl apply -f K8s/frontend/
kubectl apply -f K8s/ingress/
```

---

## 🔄 End-to-End DevSecOps Flow

This section walks you through the **complete lifecycle** of a code change — from the moment a developer pushes code, through every security gate, AI analysis, and compliance check, all the way to production deployment and continuous monitoring.

---

### Phase 0: Developer Workspace (Before Push)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DEVELOPER LOCAL MACHINE                             │
│                                                                             │
│  Developer writes code → git add → git commit                             │
│                              ↓                                              │
│                    ┌─────────────────┐                                      │
│                    │  PRE-COMMIT     │  ← Automatically triggered by git    │
│                    │    HOOKS        │                                     │
│                    └────────┬────────┘                                      │
│                             ↓                                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐   │
│  │  Gitleaks   │  │   ESLint    │  │  Semgrep    │  │  File Hygiene   │   │
│  │  (Secrets)  │  │ (Code Qual) │  │   (SAST)    │  │ (YAML/JSON/Large│   │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  │   File Checks)  │   │
│         └─────────────────┴─────────────────┘        └─────────────────┘   │
│                              ↓                                              │
│                    ┌─────────────────┐                                      │
│                    │   ANY FAIL?     │                                      │
│                    └────────┬────────┘                                      │
│                             ↓                                               │
│              ┌──────────────┴──────────────┐                                │
│              ↓                              ↓                               │
│        ┌─────────┐                   ┌─────────┐                           │
│        │   ❌    │                   │   ✅    │                           │
│        │  FAIL   │                   │  PASS   │                           │
│        └────┬────┘                   └────┬────┘                           │
│             ↓                             ↓                                 │
│   Commit BLOCKED                  Commit ALLOWED                            │
│   Fix issues locally              git push origin feature/xxx               │
│                                   → Triggers Jenkins Webhook                │
└─────────────────────────────────────────────────────────────────────────────┘
```

**What happens here:**
- When the developer runs `git commit`, the `.pre-commit-config.yaml` automatically executes
- **Gitleaks** scans for hardcoded secrets (API keys, passwords, tokens) — if found, commit is **BLOCKED**
- **ESLint** (frontend + backend) checks code quality and security anti-patterns
- **Semgrep** performs lightweight SAST — catches SQL injection, XSS, insecure crypto patterns
- **File hygiene checks** ensure no merge conflicts, invalid YAML/JSON, or files >2MB
- **If ANY hook fails**, the commit is rejected with a clear error message. The developer must fix issues locally before retrying.
- **Only if ALL hooks pass** does the commit proceed, and `git push` triggers the Jenkins webhook.

---

### Phase 1: Jenkins CI/CD Pipeline Trigger

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         JENKINS CI/CD SERVER                                │
│                                                                             │
│  GitHub Webhook → Jenkins Job Triggered                                    │
│         ↓                                                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  STAGE 1-6: PREPARATION & VALIDATION                               │   │
│  │  • Clean workspace + prune Docker                                   │   │
│  │  • Validate repo structure (app/, security/, terraform/ exist)     │   │
│  │  • Create Python venv + install requirements.txt                    │   │
│  │  • Generate .env from Jenkins Credentials (secrets NEVER in repo)  │   │
│  │  • Run pre-commit hooks AGAIN in CI (belt + suspenders)            │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│         ↓                                                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  STAGE 7-9: STATIC SECURITY TESTING (SAST + Secret Scan + Lint)    │   │
│  │  • Semgrep SAST (full codebase deep scan)                           │   │
│  │  • Gitleaks secret scan (entire git history)                        │   │
│  │  • Hadolint Dockerfile lint (backend + frontend)                    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│         ↓                                                                   │
│         ┌─────────────────────────────────────────┐                         │
│         │   ANY CRITICAL FINDING IN SAST/SECRET?  │                         │
│         └─────────────────────┬───────────────────┘                         │
│                               ↓                                             │
│              ┌────────────────┴────────────────┐                            │
│              ↓                                  ↓                           │
│        ┌─────────┐                       ┌─────────┐                       │
│        │   ❌    │                       │   ✅    │                       │
│        │  FAIL   │                       │  PASS   │                       │
│        └────┬────┘                       └────┬────┘                       │
│             ↓                                 ↓                             │
│   Pipeline ABORTED                    Continue to Build                     │
│   Alerts sent (Slack/Email)           Stage 10-11                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key Insight:** The pipeline runs pre-commit hooks **again** in CI because:
- A developer might bypass local hooks with `--no-verify`
- CI provides a clean, controlled environment
- Full git history is scanned (Gitleaks checks all commits, not just the latest)

---

### Phase 2: Build & Container Security

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    CONTAINER BUILD & VULNERABILITY SCAN                     │
│                                                                             │
│  STAGE 10-11: BUILD                                                         │
│  ┌─────────────────┐    ┌─────────────────┐                                │
│  │  Backend Image  │    │  Frontend Image │                                │
│  │  (Node Alpine)  │    │ (React→Nginx)   │                                │
│  │  • Non-root user│    │  • Non-root user│                                │
│  │  • Minimal layers│   │  • Port 8080    │                                │
│  └────────┬────────┘    └────────┬────────┘                                │
│           ↓                      ↓                                          │
│  STAGE 12-13: TRIVY CONTAINER SCAN                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Trivy scans BOTH images for:                                       │   │
│  │  • OS-level CVEs (Alpine packages)                                  │   │
│  │  • Application-level CVEs (npm packages)                            │   │
│  │  • Misconfigurations (Dockerfile best practices)                    │   │
│  │  • Secrets embedded in image layers                                 │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│           ↓                                                                 │
│  ┌─────────────────────────────────────────┐                                │
│  │   ANY CRITICAL/HIGH CVE IN IMAGES?      │                                │
│  └─────────────────────┬───────────────────┘                                │
│                        ↓                                                    │
│         ┌──────────────┴──────────────┐                                     │
│         ↓                              ↓                                    │
│   ┌─────────┐                   ┌─────────┐                                │
│   │   ❌    │                   │   ✅    │                                │
│   │  FAIL   │                   │  PASS   │                                │
│   └────┬────┘                   └────┬────┘                                │
│        ↓                              ↓                                     │
│  Images NOT pushed              Continue to DAST                            │
│  Pipeline ABORTED               Stage 14-15                                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### Phase 3: Dynamic Application Security Testing (DAST)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DAST & RUNTIME TESTING                              │
│                                                                             │
│  STAGE 14: START APPLICATION STACK                                          │
│  docker-compose up → Backend (port 5000) + Frontend (port 3000)            │
│         ↓                                                                   │
│  STAGE 15: OWASP ZAP DAST SCAN                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  ZAP Spider crawls the app → Active Scan attacks endpoints          │   │
│  │  Detects:                                                           │   │
│  │  • SQL Injection, XSS, CSRF                                         │   │
│  │  • Insecure headers, missing CSP                                    │   │
│  │  • Exposed sensitive endpoints                                      │   │
│  │  • Broken authentication                                            │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│         ↓                                                                   │
│  Raw scan outputs saved to:                                                 │
│  • compliance/reports/gitleaks/                                             │
│  • compliance/reports/hadolint/                                             │
│  • compliance/reports/trivy/                                                │
│  • compliance/reports/zap/                                                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### Phase 4: 🧠 THE SECURITY ORCHESTRATOR (Where the Magic Happens)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    STAGE 16: SECURITY ORCHESTRATOR                          │
│                                                                             │
│  This is the BRAIN of the pipeline — a custom Python framework that:       │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  STEP 1: PARSER REGISTRY                                            │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────┐ │   │
│  │  │Gitleaks JSON│  │Hadolint JSON│  │ Trivy JSON  │  │  ZAP JSON │ │   │
│  │  │   (raw)     │  │   (raw)     │  │   (raw)     │  │   (raw)   │ │   │
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────┬─────┘ │   │
│  │         └─────────────────┴─────────────────┘               │       │   │
│  │                              ↓                              ↓       │   │
│  │              ┌───────────────────────────────────────────────┐      │   │
│  │              │        UNIFIED FINDING SCHEMA                  │      │   │
│  │              │  { tool, severity, file, line, message,       │      │   │
│  │              │    cve, cwe, cvss, recommendation, ... }      │      │   │
│  │              └───────────────────────┬───────────────────────┘      │   │
│  └──────────────────────────────────────┼──────────────────────────────┘   │
│                                         ↓                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  STEP 2: NVD ENRICHMENT (Threat Intelligence)                       │   │
│  │  • Queries NVD API 2.0 for each CVE found                           │   │
│  │  • Fetches: CVSS scores, CWE mappings, descriptions, references     │   │
│  │  • Caches results to compliance/db/nvd_cache.json                   │   │
│  │  • Rate-limited with API key for 50 req/30s                         │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                         ↓                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  STEP 3: RISK ENGINE                                                │   │
│  │  • Assigns weighted scores: CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1   │   │
│  │  • Calculates: Total Risk Score, Risk Level (NONE→CRITICAL)        │   │
│  │  • Counts: fixable, exploitable, scanned targets/packages/files    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                         ↓                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  STEP 4: COMPLIANCE MAPPER (4-Layer Universal Engine)              │   │
│  │                                                                     │   │
│  │  Every finding is mapped to 3 frameworks simultaneously:           │   │
│  │                                                                     │   │
│  │  LAYER 1 ─ Rule ID Override                                       │   │
│  │    "DL3002" → CIS Docker Benchmark 4.1 (Last USER instruction)   │   │
│  │                                                                     │   │
│  │  LAYER 2 ─ CWE Database Lookup                                    │   │
│  │    "CWE-89" → OWASP A03:2021 - Injection                         │   │
│  │                                                                     │   │
│  │  LAYER 3 ─ CWE Taxonomy Family Inference                          │   │
│  │    CWE-74~117 → Injection Family → OWASP A03 + CIS 16.10         │   │
│  │                                                                     │   │
│  │  LAYER 4 ─ Smart Category Fallback + CVSS                         │   │
│  │    High CVSS (≥9.0) → Auto-adds NIST IR-4 (Incident Handling)    │   │
│  │                                                                     │   │
│  │  Output: compliance_json per finding + compliance_matrix.json      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                         ↓                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  STEP 5: AGGREGATOR → MASTER REPORT                                 │   │
│  │  • Combines ALL findings into master_report.json                    │   │
│  │  • Includes: summary, risk_summary, compliance_summary, findings   │   │
│  │  • Saved to: compliance/master_reports/                             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### Phase 5: 🤖 AI-POWERED REMEDIATION (Where AI Comes In)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│              STAGE 16 (CONTINUED): AI RAG REMEDIATION ENGINE                │
│                                                                             │
│  After the orchestrator creates the master report, the AI module activates:│
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    RAG ENGINE PIPELINE                              │   │
│  │                                                                     │   │
│  │   ┌─────────────────┐                                             │   │
│  │   │  MySQL Client   │  ← Reads real findings from RDS            │   │
│  │   │  (findings DB)  │     SELECT * FROM findings WHERE severity  │   │
│  │   └────────┬────────┘     IN ('CRITICAL','HIGH');                │   │
│  │            ↓                                                        │   │
│  │   ┌─────────────────┐                                             │   │
│  │   │  Context Builder│  ← Builds LLM prompt with:                 │   │
│  │   │                 │     • Finding details (file, line, CVE)    │   │
│  │   │                 │     • Surrounding code context             │   │
│  │   │                 │     • Compliance framework mappings        │   │
│  │   └────────┬────────┘                                             │   │
│  │            ↓                                                        │   │
│  │   ┌─────────────────┐                                             │   │
│  │   │  ChromaDB       │  ← Vector search over remediation KB       │   │
│  │   │  (Vector DB)    │     "Find similar CVE-2021-44228 fixes"    │   │
│  │   └────────┬────────┘                                             │   │
│  │            ↓                                                        │   │
│  │   ┌─────────────────────────────────────────────────────────────┐ │   │
│  │   │  LLM CLIENT (Free-tier API)                                  │ │   │
│  │   │  Prompt: "Given this finding [context + KB docs], generate:  │ │   │
│  │   │  1. Root cause analysis                                      │ │   │
│  │   │  2. Step-by-step remediation                                 │ │   │
│  │   │  3. Code fix example                                         │ │   │
│  │   │  4. Compliance control to implement"                         │ │   │
│  │   └─────────────────────────────────────────────────────────────┘ │   │
│  │            ↓                                                        │   │
│  │   ┌─────────────────┐                                             │   │
│  │   │  MySQL Write-Back│  ← Saves AI advice to findings table      │   │
│  │   │                 │     recommendation column                  │   │
│  │   └─────────────────┘                                             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  📌 WHEN AI IS TRIGGERED:                                                  │
│  • Automatically for ALL CRITICAL and HIGH findings                        │
│  • On-demand via CLI: python ai/scripts/diagnose.py --finding-id <id>     │
│  • For full scan analysis: python ai/scripts/diagnose.py --scan-id <id>   │
│                                                                             │
│  📌 AI KNOWLEDGE BASE (ai/data/remediation_kb.json):                       │
│  • CVE-specific fix procedures                                             │
│  • Dockerfile hardening patterns                                           │
│  • Secret rotation playbooks                                               │
│  • OWASP mitigation cheat-sheets                                           │
│  • Framework-specific control implementations                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**AI Integration Points in the Pipeline:**

| Point | Trigger | Action |
|-------|---------|--------|
| **Post-Orchestrator** | Auto | AI generates remediation for CRITICAL/HIGH findings |
| **Report Generation** | Auto | AI summaries included in HTML/PDF reports |
| **Manual CLI** | On-demand | Developers query AI for specific findings |
| **Grafana Dashboard** | On-click | Future: "Get AI Fix" button per finding |

---

### Phase 6: 📊 COMPLIANCE & REPORTING (Where Compliance Comes In)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│           STAGE 17-20: COMPLIANCE VALIDATION & REPORTING                    │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  STEP 1: DATABASE PERSISTENCE                                       │   │
│  │                                                                     │   │
│  │  master_report.json → DatabaseManager.save_master_report()         │   │
│  │                                                                     │   │
│  │  Tables populated:                                                  │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────┐ │   │
│  │  │  projects   │  │   scans     │  │  findings   │  │compliance_│ │   │
│  │  │             │  │             │  │             │  │  results  │ │   │
│  │  │ project_id  │  │ scan_id     │  │ id          │  │ id        │ │   │
│  │  │ name        │  │ scan_time   │  │ scan_id     │  │ scan_id   │ │   │
│  │  │ repo_url    │  │ total_find  │  │ tool        │  │ framework │ │   │
│  │  │ branch      │  │ risk_level  │  │ severity    │  │ control_id│ │   │
│  │  └─────────────┘  │ compliance  │  │ cve/cwe     │  │ status    │ │   │
│  │                   │  _score     │  │ message     │  └───────────┘ │   │
│  │                   └─────────────┘  │ ai_recommend│                │   │
│  │                                    └─────────────┘                │   │
│  │                                                                     │   │
│  │  Supports: SQLite (local) | MySQL (AWS RDS) | PostgreSQL          │   │
│  │  Auto-fallback: If RDS fails → automatically saves to SQLite       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    ↓                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  STEP 2: VERIFY DATABASE INTEGRITY                                  │   │
│  │  • Connect to RDS MySQL                                             │   │
│  │  • Verify tables: projects, scans, findings, compliance_results    │   │
│  │  • Confirm record counts match master report                        │   │
│  │  • If verification fails → pipeline warns but continues             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    ↓                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  STEP 3: GENERATE EXECUTIVE REPORTS                                 │   │
│  │                                                                     │   │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐    │   │
│  │  │   HTML Report   │  │   PDF Report    │  │   JSON Report   │    │   │
│  │  │                 │  │                 │  │                 │    │   │
│  │  │ • Severity      │  │ • Executive     │  │ • Machine-      │    │   │
│  │  │   distribution  │  │   summary       │  │   readable      │    │   │
│  │  │ • Compliance    │  │ • Risk score    │  │ • CI/CD         │    │   │
│  │  │   bars (OWASP/  │  │ • Top findings  │  │   integration   │    │   │
│  │  │   CIS/NIST)     │  │ • AI fixes      │  │   ready         │    │   │
│  │  │ • Finding table │  │ • Compliance    │  │                 │    │   │
│  │  │ • AI advice     │  │   posture       │  │                 │    │   │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘    │   │
│  │                                                                     │   │
│  │  Saved to: compliance/reports/executive_reports/                    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    ↓                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  STEP 4: ARCHIVE ARTIFACTS                                          │   │
│  │  • All reports archived in Jenkins for audit trail                  │   │
│  │  • Raw scan outputs preserved                                       │   │
│  │  • Report metadata saved to `reports` table                         │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Compliance Framework Coverage:**

| Framework | Baseline Controls | How Mapped |
|-----------|-------------------|------------|
| **OWASP Top 10 2021** | 10 controls | Rule ID → CWE → OWASP category |
| **CIS Benchmarks** | 15 controls | Dockerfile rules + Docker Benchmark |
| **NIST SP 800-53** | 20 controls | CVSS severity + CWE family → NIST control |

**Compliance Score Formula:**
```
Framework Score = (Controls Passed / Total Baseline Controls) × 100
Overall Compliance = Average(OWASP Score, CIS Score, NIST Score)
```

---

### Phase 7: 🔒 SECURITY GATE (The Final Checkpoint)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    STAGE 22: SECURITY GATE EVALUATION                       │
│                                                                             │
│  The gate reads security/config/policy.yaml and evaluates:                 │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  POLICY RULES:                                                      │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │  fail_on_critical: true    ← ANY critical finding = FAIL   │   │   │
│  │  │  fail_on_high: false       ← HIGH findings allowed         │   │   │
│  │  │  minimum_score: 70.0       ← Compliance must be ≥ 70%      │   │   │
│  │  │  max_allowed_risk_score: 50← Risk score must be ≤ 50       │   │   │
│  │  └─────────────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    ↓                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  GATE DECISION:                                                     │   │
│  │                                                                     │   │
│  │  ┌─────────────┐              ┌─────────────┐                      │   │
│  │  │   PASS ✅   │              │   FAIL ❌   │                      │   │
│  │  │             │              │             │                      │   │
│  │  │ • No CRIT   │              │ • CRITICAL  │                      │   │
│  │  │ • Score≥70  │              │   findings  │                      │   │
│  │  │ • Risk≤50   │              │ • OR Score  │                      │   │
│  │  │             │              │   < 70      │                      │   │
│  │  │ Continue to │              │ • OR Risk   │                      │   │
│  │  │   Sign &    │              │   > 50      │                      │   │
│  │  │   Deploy    │              │             │                      │   │
│  │  └─────────────┘              │ Pipeline    │                      │   │
│  │                               │ ABORTED     │                      │   │
│  │                               │ (unless     │                      │   │
│  │                               │ SOFT_FAIL)  │                      │   │
│  │                               └─────────────┘                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  📌 SOFT_FAIL mode (for dev/testing):                                       │
│  • Set SOFT_FAIL=true in .env                                               │
│  • Gate still evaluates and reports                                         │
│  • Pipeline continues with exit code 0 (doesn't block deployment)          │
│  • Use ONLY in non-production environments                                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### Phase 8: 🔏 Image Signing & Deployment

```
┌─────────────────────────────────────────────────────────────────────────────┐
│              STAGE 23-29: SIGN, PUSH, DEPLOY, VERIFY                        │
│                                                                             │
│  STAGE 23-24: COSIGN IMAGE SIGNING                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  • Generate Cosign keypair (or use existing in security/config/keys)│   │
│  │  • Sign backend image: cosign sign --key cosign.key <image>        │   │
│  │  • Sign frontend image: cosign sign --key cosign.key <image>       │   │
│  │  • Verify signatures: cosign verify --key cosign.pub <image>       │   │
│  │  • Ensures image integrity & provenance (who built it, when)       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    ↓                                        │
│  STAGE 25-26: PUSH TO ECR                                                   │
│  • Authenticate with AWS ECR via IAM role                                   │
│  • Tag images with build number + latest                                    │
│  • Push signed images to:                                                   │
│    - 284064534086.dkr.ecr.us-east-1.amazonaws.com/sentinelops-backend      │
│    - 284064534086.dkr.ecr.us-east-1.amazonaws.com/sentinelops-frontend     │
│                                    ↓                                        │
│  STAGE 27-28: DEPLOY TO EKS                                                 │
│  • Update kubeconfig for EKS cluster                                        │
│  • kubectl set image deployment/backend backend=<new-image>                 │
│  • kubectl set image deployment/frontend frontend=<new-image>               │
│  • Rolling update with zero-downtime                                        │
│  • Verify rollout: kubectl rollout status deployment/backend                │
│  • Readiness/liveness probes confirm pods are healthy                       │
│                                    ↓                                        │
│  STAGE 29: CLEANUP                                                          │
│  • Remove temporary containers                                              │
│  • Prune unused Docker images                                               │
│  • Archive build logs                                                       │
│  • Send success notification (Slack/Email)                                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### Phase 9: 📈 Continuous Monitoring (Post-Deployment)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    POST-DEPLOYMENT: ALWAYS-ON MONITORING                    │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  GRAFANA DASHBOARD (Real-time, MySQL-backed)                        │   │
│  │                                                                     │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────┐ │   │
│  │  │ Gate Verdict│  │ Compliance  │  │ Risk Score  │  │ Risk Level│ │   │
│  │  │   PASS ✅   │  │    85% 🟢   │  │    12 🟢    │  │   LOW 🟢  │ │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └───────────┘ │   │
│  │                                                                     │   │
│  │  ┌─────────────────────────┐  ┌─────────────────────────────────┐ │   │
│  │  │  Severity Distribution  │  │  Framework Pass Percentages     │ │   │
│  │  │  [Pie Chart]            │  │  [Bar Gauge: OWASP/CIS/NIST]    │ │   │
│  │  └─────────────────────────┘  └─────────────────────────────────┘ │   │
│  │                                                                     │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │  Recent Critical & High Findings Table (Top 50)             │   │   │
│  │  │  Tool | Severity | Rule ID | CVE | File | Line | Summary    │   │   │
│  │  └─────────────────────────────────────────────────────────────┘   │   │
│  │                                                                     │   │
│  │  Auto-refresh: Every 1 minute                                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  PROMETHEUS + ALERTMANAGER                                          │   │
│  │  • Cluster resource metrics (CPU, memory, disk)                     │   │
│  │  • Application metrics (request rate, error rate, latency)          │   │
│  │  • Security alerts (high finding count spike, gate failure)         │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  FUTURE: AI CONTINUOUS REMEDIATION                                  │   │
│  │  • Scheduled job runs AI diagnosis on latest scan                   │   │
│  │  • Auto-creates GitHub issues for CRITICAL findings                 │   │
│  │  • Suggests PRs with automated code fixes                           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### 🎯 Complete Flow Summary

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   DEVELOPER │     │   PRE-COMMIT│     │   JENKINS   │     │   BUILD &   │
│   PUSHES    │────▶│   HOOKS     │────▶│   CI/CD     │────▶│   CONTAINER │
│   CODE      │     │   (Pass?)   │     │   PIPELINE  │     │   SCAN      │
└─────────────┘     └──────┬──────┘     └─────────────┘     └──────┬──────┘
                           │                                         │
                      ┌────┴────┐                               ┌───┴────┐
                      │  FAIL   │                               │  FAIL  │
                      │ BLOCKED │                               │ ABORT  │
                      └─────────┘                               └────────┘
                           │                                         │
                           └─────────────────────────────────────────┘
                                           │
                                           ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   DAST      │     │  SECURITY   │     │     AI      │     │  COMPLIANCE │
│   (ZAP)     │────▶│ ORCHESTRATOR│────▶│   RAG       │────▶│  & REPORTS  │
│             │     │ (Parse/Risk/│     │  REMEDIATION│     │  (DB/HTML/  │
│             │     │  Compliance)│     │             │     │   PDF/JSON) │
└─────────────┘     └──────┬──────┘     └─────────────┘     └──────┬──────┘
                           │                                         │
                           ▼                                         ▼
                    ┌─────────────┐                           ┌─────────────┐
                    │  SECURITY   │                           │   VERIFY    │
                    │    GATE     │                           │   REPORTS   │
                    │  (Pass?)    │                           │   IN RDS    │
                    └──────┬──────┘                           └─────────────┘
                           │
                    ┌──────┴──────┐
                    │    FAIL     │
                    │   ABORT     │
                    └─────────────┘
                           │
                           ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   COSIGN    │     │    PUSH     │     │   DEPLOY    │     │  MONITOR    │
│   SIGN      │────▶│    TO ECR   │────▶│   TO EKS    │────▶│  & ALERT    │
│  (PKI)      │     │             │     │  (K8s/Helm) │     │ (Grafana)   │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
```

---

### 📋 Decision Matrix: Pass vs Fail at Each Gate

| Gate | Condition | Pass Action | Fail Action |
|------|-----------|-------------|-------------|
| **Pre-commit** | Gitleaks + ESLint + Semgrep all pass | Commit proceeds | Commit blocked, fix locally |
| **SAST/Secret Scan** | No CRITICAL findings | Continue build | Pipeline abort |
| **Container Scan** | No CRITICAL/HIGH CVEs | Continue to DAST | Pipeline abort |
| **DAST** | No CRITICAL vulnerabilities | Continue to orchestrator | Pipeline abort |
| **Security Gate** | Score ≥ 70%, Risk ≤ 50, No CRITICAL | Sign & deploy | Abort (unless SOFT_FAIL) |
| **DB Verification** | Records ingested successfully | Continue | Warn, use SQLite fallback |
| **K8s Rollout** | All pods healthy | Pipeline success | Auto-rollback |

---

### 🔗 How AI and Compliance Work Together

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    AI ↔ COMPLIANCE INTEGRATION FLOW                         │
│                                                                             │
│  1. Orchestrator creates master_report.json                                │
│         ↓                                                                   │
│  2. Compliance Mapper adds framework mappings to each finding              │
│     (OWASP A03, CIS 16.10, NIST IR-4)                                      │
│         ↓                                                                   │
│  3. AI RAG Engine reads the finding + its compliance mappings              │
│         ↓                                                                   │
│  4. AI generates remediation that is COMPLIANCE-AWARE:                     │
│     "To fix this SQL Injection (OWASP A03), implement parameterized        │
│      queries AND add input validation per NIST SI-10."                     │
│         ↓                                                                   │
│  5. Remediation advice saved to DB alongside compliance controls           │
│         ↓                                                                   │
│  6. Reports show BOTH the compliance posture AND AI-recommended fixes      │
│         ↓                                                                   │
│  7. Grafana dashboard displays compliance scores + drill-down to AI advice │
│                                                                             │
│  RESULT: Security fixes are not just "patch the bug" — they are            │
│          "patch the bug AND satisfy these 3 compliance controls."          │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### Module Mapping (PGCP-ITISS)

| Module | Coverage |
|--------|----------|
| ITISS01 — Computer Networks | VPC, subnets, ACLs, routing |
| ITISS02 — OS & Administration | Linux hardening, Bash scripts |
| ITISS03 — Programming | Python automation, MySQL, Node.js |
| ITISS04 — IT Infra & DevOps | Docker, K8s, Jenkins, AWS |
| ITISS05 — Network Defense | SIEM |
| ITISS06 — Security Concepts | OWASP ZAP, SAST, DAST |
| ITISS07 — Cyber Forensics + PKI | TLS certs, digital signatures |
| ITISS08 — Compliance Audit | NIST, ISO 27001 reporting |

---

## 📄 License

This project is built for educational purposes as part of the PGCP-ITISS program.

---

> **"Security is not a product, but a process."** — This pipeline embodies that philosophy by embedding security into every commit, every build, and every deployment.

**🔗 Repository:** [github.com/9MayanK2/DevSecOps](https://github.com/9MayanK2/DevSecOps)
