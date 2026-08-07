<div align="center">

# 🔐 SentinelOps

### **An Enterprise Security Orchestrator framework with Automated CI/CD**

*Security by Design. Automation by Default.*

[![Jenkins](https://img.shields.io/badge/Jenkins-CI%2FCD-D24939?logo=jenkins&logoColor=white)](https://www.jenkins.io/)
[![AWS](https://img.shields.io/badge/AWS-EKS-FF9900?logo=amazon-aws&logoColor=white)](https://aws.amazon.com/eks/)
[![Docker](https://img.shields.io/badge/Docker-Containers-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-Orchestration-326CE5?logo=kubernetes&logoColor=white)](https://kubernetes.io/)
[![Terraform](https://img.shields.io/badge/Terraform-IaC-623CE4?logo=terraform&logoColor=white)](https://www.terraform.io/)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Node.js](https://img.shields.io/badge/Node.js-20-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

</div>

---

## 📖 Table of Contents

- [🎯 The Problem](#-the-problem)
- [✨ The Solution — SentinelOps](#-the-solution--sentinelops)
- [🏗️ Six-Layer Security Architecture](#%EF%B8%8F-six-layer-security-architecture)
- [📊 Complete Pipeline Flow](#-complete-pipeline-flow)
- [☁️ AWS Cloud Architecture](#%EF%B8%8F-aws-cloud-architecture)
- [🛡️ Security Controls Mapping](#%EF%B8%8F-security-controls-mapping)
- [💻 Application Stack](#-application-stack)
- [📁 Repository Structure](#-repository-structure)
- [🚀 Quick Start](#-quick-start)
- [🔧 Configuration](#-configuration)
- [👥 Team & Credits](#-team--credits)
- [📚 Acknowledgments](#-acknowledgments)

---

## 🎯 The Problem

Every day, thousands of lines of code are pushed to production. But here is the terrifying truth:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐         │
│   │  HARDCODED       │  │  CRITICAL CVEs   │  │  RUNTIME ATTACKS │         │
│   │  SECRETS IN      │  │  IN CONTAINER    │  │  UNDETECTED      │         │
│   │  GITHUB REPOS    │  │  IMAGES          │  │  FOR WEEKS       │         │
│   └──────────────────┘  └──────────────────┘  └──────────────────┘         │
│                                                                             │
│   📊 74% of organizations have experienced a security incident in CI/CD    │
│   📊 85% of vulnerabilities are discovered AFTER deployment                │
│   📊 Hardcoded secrets are found in 1 out of every 5 code reviews          │
│                                                                             │
│   SECURITY IS STILL TREATED AS A FINAL CHECKPOINT...                        │
│   INSTEAD OF BEING BAKED INTO EVERY STAGE OF THE PIPELINE.                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**What if security wasn't a final checkpoint... but was automated at every single stage?**

---

## ✨ The Solution — SentinelOps

**SentinelOps** is a production-grade, end-to-end DevSecOps pipeline that integrates security at every stage of the software delivery lifecycle — from the developer\'s laptop to production runtime.

Built for the **PGCP-ITISS program** at CDAC ACTS, Pune, this project demonstrates enterprise-level competence across:

| Domain | Tools & Technologies |
|--------|---------------------|
| 🖥️ **Development** | React 19, Node.js 20, MongoDB, VS Code |
| 🔒 **Shift-Left Security** | Gitleaks, Semgrep, ESLint, Pre-commit Hooks |
| 🔄 **CI/CD** | Jenkins (17-stage pipeline), GitHub Webhooks |
| 🐳 **Containerization** | Docker, Multi-stage builds, Hadolint |
| 🔍 **Vulnerability Scanning** | Trivy (CVE), OWASP ZAP (DAST) |
| 🔏 **Supply Chain Security** | Cosign (PKI Digital Signing) |
| ☁️ **Cloud Infrastructure** | AWS EKS, ECR, VPC, ALB, IAM, Terraform |
| ☸️ **Orchestration** | Kubernetes, Helm, ArgoCD (GitOps) |
| 📊 **Monitoring & SIEM** | Prometheus, Grafana, ELK Stack, Wazuh, Snort |
| 📋 **Compliance** | NIST CSF, ISO 27001, OWASP Top 10, CIS Benchmarks |

---

## 🏗️ Six-Layer Security Architecture

SentinelOps implements a **Defense-in-Depth** strategy across six distinct layers:

```
╔═════════════════════════════════════════════════════════════════════════════╗
║                    SENTINELOPS — SIX-LAYER SECURITY ARCHITECTURE            ║
╠═════════════════════════════════════════════════════════════════════════════╣
║                                                                             ║
║  ┌─────────────────────────────────────────────────────────────────────┐   ║
║  │  LAYER 1: SECURE DEVELOPMENT (Shift-Left)                          │   ║
║  │  • Pre-commit hooks: Gitleaks + Semgrep + ESLint                   │   ║
║  │  • Block secrets & insecure code BEFORE commit                     │   ║
║  └─────────────────────────────────────────────────────────────────────┘   ║
║                                    ↓                                        ║
║  ┌─────────────────────────────────────────────────────────────────────┐   ║
║  │  LAYER 2: JENKINS CI/CD — 17-Stage Pipeline                        │   ║
║  │  • Build → Scan → Sign → Push → Deploy (Fully Automated)           │   ║
║  │  • Trivy CVE scan + OWASP ZAP DAST + Security Gate                 │   ║
║  └─────────────────────────────────────────────────────────────────────┘   ║
║                                    ↓                                        ║
║  ┌─────────────────────────────────────────────────────────────────────┐   ║
║  │  LAYER 3: SECURITY FRAMEWORK (Python Orchestrator)                 │   ║
║  │  • 5-Stage Execution: Pre-flight → Scanners → Parsers → Aggregate → Gate │ ║
║  │  • Risk Engine: CVSS-weighted scoring + Compliance Mapping         │   ║
║  └─────────────────────────────────────────────────────────────────────┘   ║
║                                    ↓                                        ║
║  ┌─────────────────────────────────────────────────────────────────────┐   ║
║  │  LAYER 4: AWS CLOUD DEPLOYMENT (EKS + Terraform)                   │   ║
║  │  • VPC with Public/Private subnets, NAT Gateway, ALB               │   ║
║  │  • EKS v1.33 with Managed Node Groups, IAM roles, RBAC             │   ║
║  │  • ECR for signed image storage, Helm for K8s deployments          │   ║
║  └─────────────────────────────────────────────────────────────────────┘   ║
║                                    ↓                                        ║
║  ┌─────────────────────────────────────────────────────────────────────┐   ║
║  │  LAYER 5: MONITORING & OBSERVABILITY                               │   ║
║  │  • Prometheus + Grafana: Metrics, dashboards, alerting             │   ║
║  │  • ELK Stack: Centralized log aggregation & correlation            │   ║
║  │  • Wazuh (HIDS): File integrity, rootkit detection                 │   ║
║  │  • Snort (NIDS): Network intrusion detection                       │   ║
║  └─────────────────────────────────────────────────────────────────────┘   ║
║                                    ↓                                        ║
║  ┌─────────────────────────────────────────────────────────────────────┐   ║
║  │  LAYER 6: COMPLIANCE & REPORTING                                   │   ║
║  │  • NIST CSF + ISO 27001 + OWASP Top 10 + CIS Benchmarks            │   ║
║  │  • Auto-generated HTML/PDF executive reports                       │   ║
║  │  • Remediation tracker with risk scoring history                   │   ║
║  └─────────────────────────────────────────────────────────────────────┘   ║
║                                                                             ║
╚═════════════════════════════════════════════════════════════════════════════╝
```

---

## 📊 Complete Pipeline Flow

This is the **single view** of how code travels from a developer\'s machine to a secured, monitored production environment:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  DEVELOPER\'S LAPTOP                                                        │
│  ┌─────────────────────┐                                                    │
│  │  git commit -m ...  │                                                    │
│  └──────────┬──────────┘                                                    │
│             │                                                               │
│             ▼                                                               │
│  ┌─────────────────────┐     BLOCKED IF SECRETS/ISSUES FOUND               │
│  │  PRE-COMMIT HOOKS   │───────────────────────────────────────────────▶    │
│  │  • Gitleaks         │                                                    │
│  │  • Semgrep (SAST)   │                                                    │
│  │  • ESLint           │                                                    │
│  │  • File Hygiene     │                                                    │
│  └──────────┬──────────┘                                                    │
│             │                                                               │
│             ▼  (Code passes hooks)                                          │
│  ┌─────────────────────┐                                                    │
│  │  git push origin    │                                                    │
│  └──────────┬──────────┘                                                    │
│             │                                                               │
└─────────────┼───────────────────────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  GITHUB REPOSITORY                                                          │
│  ┌─────────────────────┐                                                    │
│  │  Webhook Trigger    │───────────────────────────────────────────────▶    │
│  └──────────┬──────────┘                                                    │
│             │                                                               │
└─────────────┼───────────────────────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  JENKINS CI/CD — 17 STAGES                                                  │
│                                                                             │
│  [1] Checkout  →  [2] Install Deps  →  [3] Generate .env                   │
│       │                  │                      │                           │
│       ▼                  ▼                      ▼                           │
│  [4] Pre-Commit Validation                                                  │
│       │                                                                     │
│       ▼                                                                     │
│  [5] Hadolint  →  [6] Build Backend  →  [7] Build Frontend                 │
│       │                  │                      │                           │
│       ▼                  ▼                      ▼                           │
│  [8] Trivy CVE Scan  →  [9] OWASP ZAP DAST                                 │
│       │                      │                                              │
│       ▼                      ▼                                              │
│  [10] Generate Reports  →  [11] Security Gate (Pass/Fail)                  │
│       │                      │                                              │
│       ▼                      ▼                                              │
│  [12] Cosign Sign  →  [13] Verify Signatures                               │
│       │                                                                     │
│       ▼                                                                     │
│  [14] Login ECR  →  [15] Push Signed Images                                │
│       │                                                                     │
│       ▼                                                                     │
│  [16] Deploy to EKS  →  [17] Verify Rollout                                │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─────────────────────┐     ┌─────────────────────┐                        │
│  │   ✅ SUCCESS        │     │   ❌ FAILURE        │                        │
│  │   Archive Reports   │     │   Auto Rollback     │                        │
│  │   Clean Resources   │     │   Alert Team        │                        │
│  └─────────────────────┘     └─────────────────────┘                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  AMAZON ECR (Container Registry)                                            │
│  ┌─────────────────────┐  ┌─────────────────────┐                          │
│  │  sentinelops-backend  │  │  sentinelops-frontend │                          │
│  │  build-42 (signed)    │  │  build-42 (signed)    │                          │
│  │  latest (signed)      │  │  latest (signed)      │                          │
│  └──────────┬──────────┘  └──────────┬──────────┘                          │
│             │                        │                                      │
└─────────────┼──────────┬─────────────┼──────────────────────────────────────┘
              │          │             │
              ▼          ▼             ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  ARGOCD GITOPS (Future State)                                               │
│  ┌─────────────────────┐                                                    │
│  │  Watches ECR for    │                                                    │
│  │  new image tags     │                                                    │
│  └──────────┬──────────┘                                                    │
│             │                                                               │
│             ▼                                                               │
│  ┌─────────────────────┐                                                    │
│  │  Updates Helm       │                                                    │
│  │  values in Git      │                                                    │
│  └──────────┬──────────┘                                                    │
│             │                                                               │
│             ▼  (Auto-sync every 3 min)                                      │
│  ┌─────────────────────┐                                                    │
│  │  Deploys to EKS     │                                                    │
│  │  (Desired = Actual) │                                                    │
│  └──────────┬──────────┘                                                    │
│             │                                                               │
└─────────────┼───────────────────────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  AMAZON EKS — PRODUCTION CLUSTER                                            │
│  ┌─────────────────────┐  ┌─────────────────────┐                          │
│  │  Backend Pods       │  │  Frontend Pods      │                          │
│  │  (Replica: 2)       │  │  (Replica: 2)       │                          │
│  └──────────┬──────────┘  └──────────┬──────────┘                          │
│             │                        │                                      │
│             └──────────┬─────────────┘                                      │
│                        │                                                    │
│                        ▼                                                    │
│  ┌─────────────────────┐  ┌─────────────────────┐                          │
│  │  ALB (Ingress)      │  │  AWS Secrets Mgr    │                          │
│  │  + WAF Protection   │  │  (via CSI Driver)   │                          │
│  └──────────┬──────────┘  └─────────────────────┘                          │
│             │                                                               │
└─────────────┼───────────────────────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  MONITORING & SIEM STACK                                                    │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐               │
│  │  PROMETHEUS    │  │  GRAFANA       │  │  ELK STACK     │               │
│  │  (Metrics)     │  │  (Dashboards)  │  │  (Logs)        │               │
│  └────────────────┘  └────────────────┘  └────────────────┘               │
│  ┌────────────────┐  ┌────────────────┐                                   │
│  │  WAZUH (HIDS)  │  │  SNORT (NIDS)  │                                   │
│  │  File Integrity│  │  Port Scans    │                                   │
│  │  Rootkit Detect│  │  C2 Traffic    │                                   │
│  └────────────────┘  └────────────────┘                                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  COMPLIANCE DASHBOARD                                                       │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐               │
│  │  NIST CSF      │  │  ISO 27001     │  │  PDF REPORTS   │               │
│  │  Mapping       │  │  Annex A       │  │  (Auto-gen)    │               │
│  └────────────────┘  └────────────────┘  └────────────────┘               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## ☁️ AWS Cloud Architecture

```
                              🌐 INTERNET
                                   │
┌──────────────────────────────────┼─────────────────────────────────────────┐
│                                  ▼                                         │
│                    📍 ROUTE 53 + ACM (SSL/TLS)                             │
│                    sentinelops.example.com                                 │
│                    HTTPS Certificate (Auto-renew)                          │
│                                  │                                         │
│                                  ▼                                         │
│                    ⚖️ APPLICATION LOAD BALANCER (ALB)                      │
│                    • SSL Termination (443 → 80)                            │
│                    • Path Routing: /api → Backend, / → Frontend            │
│                    • Health Checks (30s interval)                          │
│                    • Cross-AZ Load Balancing                               │
│                                  │                                         │
│         ┌────────────────────────┼────────────────────────┐                │
│         │                        │                        │                │
│         ▼                        ▼                        ▼                │
│ ┌────────────────┐  ┌────────────────┐  ┌────────────────┐               │
│ │ 🛡️ AWS WAF v2  │  │ 📡 PUBLIC      │  │ 📡 PUBLIC      │               │
│ │ SQLi/XSS Rules │  │ SUBNET 1       │  │ SUBNET 2       │               │
│ │ Rate Limiting  │  │ (us-east-1a)   │  │ (us-east-1b)   │               │
│ │ Bot Control    │  │                │  │                │               │
│ │                │  │ ┌────────────┐ │  │ ┌────────────┐ │               │
│ │                │  │ │ 🖥️ Jenkins │ │  │ │ 🌐 NAT GW  │ │               │
│ │                │  │ │ EC2 t3.lg  │ │  │ │ (HA Pair)  │ │               │
│ │                │  │ │ Port 8080  │ │  │ └────────────┘ │               │
│ │                │  │ └────────────┘ │  │ ┌────────────┐ │               │
│ │                │  │ ┌────────────┐ │  │ │ 🛡️ Bastion │ │               │
│ │                │  │ │ 🌐 NAT GW  │ │  │ │ (Jump Box) │ │               │
│ │                │  │ │ (Outbound) │ │  │ │ Port 22    │ │               │
│ │                │  │ └────────────┘ │  │ └────────────┘ │               │
│ └────────────────┘  └────────────────┘  └────────────────┘               │
│         │                        │                        │                │
│         └────────────────────────┼────────────────────────┘                │
│                                  │                                         │
│                                  ▼                                         │
│ ┌───────────────────────────────────────────────────────────────────────┐ │
│ │                         🏠 AWS VPC (10.0.0.0/16)                      │ │
│ │                                                                       │ │
│ │  ┌─────────────────────────────────────────────────────────────────┐ │ │
│ │  │  🔒 PRIVATE SUBNET 1 (us-east-1a)                                │ │ │
│ │  │                                                                  │ │ │
│ │  │  ┌────────────┐  ┌────────────┐  ┌────────────────────────┐   │ │ │
│ │  │  │ ☸️ EKS     │  │ ☸️ EKS     │  │ 📦 App Pods            │   │ │ │
│ │  │  │ Worker 1   │  │ Worker 2   │  │   Backend (x2)         │   │ │ │
│ │  │  │ t3.medium  │  │ t3.medium  │  │   Frontend (x2)        │   │ │ │
│ │  │  └────────────┘  └────────────┘  └────────────────────────┘   │ │ │
│ │  │                                                                  │ │ │
│ │  │  ┌────────────┐  ┌────────────┐  ┌────────────────────────┐   │ │ │
│ │  │  │ 🔐 Secrets │  │ 📊 CW      │  │ 📦 ECR Pull            │   │ │ │
│ │  │  │ Mgr (CSI)  │  │ Agent      │  │   (Signed Images)      │   │ │ │
│ │  │  └────────────┘  └────────────┘  └────────────────────────┘   │ │ │
│ │  └─────────────────────────────────────────────────────────────────┘ │ │
│ │                                                                       │ │
│ │  ┌─────────────────────────────────────────────────────────────────┐ │ │
│ │  │  🔒 PRIVATE SUBNET 2 (us-east-1b)                                │ │ │
│ │  │                                                                  │ │ │
│ │  │  ┌────────────┐  ┌────────────┐  ┌────────────────────────┐   │ │ │
│ │  │  │ ☸️ EKS     │  │ ☸️ EKS     │  │ 🚀 ArgoCD Server       │   │ │ │
│ │  │  │ Worker 3   │  │ Worker 4   │  │   GitOps Controller    │   │ │ │
│ │  │  │ t3.medium  │  │ t3.medium  │  │   Port: 8080           │   │ │ │
│ │  │  └────────────┘  └────────────┘  └────────────────────────┘   │ │ │
│ │  │                                                                  │ │ │
│ │  │  ┌────────────┐  ┌────────────┐  ┌────────────────────────┐   │ │ │
│ │  │  │ 📊 Prom.   │  │ 📊 Grafana │  │ 📝 ELK Stack           │   │ │ │
│ │  │  │ (Metrics)  │  │ (Dash)     │  │   (Logs/Search)        │   │ │ │
│ │  │  └────────────┘  └────────────┘  └────────────────────────┘   │ │ │
│ │  └─────────────────────────────────────────────────────────────────┘ │ │
│ │                                                                       │ │
│ │  ┌─────────────────────────────────────────────────────────────────┐ │ │
│ │  │  🔐 AWS MANAGED SERVICES                                         │ │ │
│ │  │                                                                  │ │ │
│ │  │  ┌────────────┐  ┌────────────┐  ┌────────────────────────┐   │ │ │
│ │  │  │ 📦 ECR     │  │ 🔐 Secrets │  │ 📊 CloudWatch          │   │ │ │
│ │  │  │ Registry   │  │ Mgr        │  │   Logs & Metrics       │   │ │ │
│ │  │  │ • backend  │  │ • MongoDB  │  │                        │   │ │ │
│ │  │  │ • frontend │  │ • JWT      │  │                        │   │ │ │
│ │  │  └────────────┘  └────────────┘  └────────────────────────┘   │ │ │
│ │  └─────────────────────────────────────────────────────────────────┘ │ │
│ │                                                                       │ │
│ └───────────────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## 🛡️ Security Controls Mapping

| Framework | SentinelOps Implementation | Coverage |
|-----------|---------------------------|----------|
| **OWASP Top 10 (2021)** | ZAP DAST + Semgrep SAST + Secure Coding | A01-A10 |
| **CIS Docker Benchmark** | Hadolint + Hardened Multi-stage Dockerfiles | 4.1-4.9 |
| **CIS Kubernetes Benchmark** | RBAC + NetworkPolicy + PodSecurityContext | 5.1-5.7 |
| **NIST CSF** | Identify → Protect → Detect → Respond → Recover | All 5 Functions |
| **ISO 27001 Annex A** | A.12.6 (Vuln Mgmt) + A.13.1 (Network Sec) + A.16.1 (Incident Mgmt) | A.12-A.16 |
| **PCI-DSS** | Req 6 (Secure Dev) + Req 11 (Vuln Scanning) | Req 6, 11 |

---

## 💻 Application Stack

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         FULL-STACK APPLICATION                              │
│                                                                             │
│  ┌───────────────────────────┐  ┌───────────────────────────┐              │
│  │      FRONTEND             │  │      BACKEND              │              │
│  │      (React 19)           │  │      (Node.js 20)         │              │
│  │                           │  │                           │              │
│  │  React Router DOM 7.6     │  │  Express 5.1              │              │
│  │  Axios (HTTP Client)      │  │  JWT + bcrypt (Auth)      │              │
│  │  React Hot Toast          │  │  Joi (Validation)         │              │
│  │  React Icons              │  │  Mongoose 8.15 (MongoDB)  │              │
│  │  React Countdown          │  │  Nodemailer (Email)       │              │
│  │                           │  │  OpenAI API               │              │
│  │  Multi-stage Docker:      │  │  CSRF Protection          │              │
│  │  Node Build → Nginx       │  │  CORS                     │              │
│  │  Non-root user            │  │  Cookie Parser            │              │
│  │  Health Check /health     │  │  Health Check /health     │              │
│  └────────────┬──────────────┘  └────────────┬──────────────┘              │
│               │                              │                              │
│               └──────────────┬───────────────┘                              │
│                              │                                              │
│                              ▼                                              │
│  ┌───────────────────────────┐                                              │
│  │      DATABASE             │                                              │
│  │      (MongoDB)            │                                              │
│  │                           │                                              │
│  │  User Data                │                                              │
│  │  Application State        │                                              │
│  │  Session Management       │                                              │
│  └───────────────────────────┘                                              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 📁 Repository Structure

```
DevSecOps/
│
├── app/
│   ├── client/                    # React Frontend
│   │   ├── Dockerfile             # Multi-stage: Node → Nginx
│   │   ├── nginx/nginx.conf
│   │   ├── package.json           # React 19, Router, Axios
│   │   └── src/                   # Components, Pages, Hooks
│   │
│   └── server/                    # Node.js/Express Backend
│       ├── Dockerfile             # Node 20 Alpine, non-root
│       ├── package.json           # Express, JWT, Mongoose
│       ├── index.js               # Main entry
│       └── .env                   # Generated at runtime
│
├── security/                      # Enterprise Security Framework
│   ├── core/
│   │   ├── orchestrator.py        # 5-Stage Security Controller
│   │   ├── parser_registry.py     # Scanner output normalizers
│   │   ├── aggregator.py          # Multi-scanner aggregation
│   │   ├── security_gate.py       # Policy pass/fail evaluator
│   │   ├── compliance_mapper.py   # NIST/CIS/OWASP mapping
│   │   ├── risk_engine.py         # CVSS-weighted risk scoring
│   │   └── report_generator.py    # HTML/PDF report generator
│   │
│   ├── container/
│   │   ├── trivy.sh               # CVE scanner wrapper
│   │   └── hadolint.sh            # Dockerfile linter wrapper
│   │
│   ├── dast/
│   │   └── zap.sh                 # OWASP ZAP DAST wrapper
│   │
│   ├── secrets/
│   │   └── gitleaks.sh            # Secret scanning wrapper
│   │
│   ├── signing/
│   │   ├── sign_images.sh         # Cosign PKI signing
│   │   ├── verify_images.sh       # Signature verification
│   │   └── generate_keys.sh       # One-time key generation
│   │
│   ├── parsers/                   # Scanner output normalizers
│   ├── db/                        # Database manager (SQLite/PostgreSQL)
│   ├── config/                    # Tool configs & PKI keys
│   └── scripts/                   # Shared bash utilities
│
├── terraform/                     # Infrastructure as Code
│   ├── main.tf                    # Root module composition
│   ├── variables.tf               # Input variables
│   ├── outputs.tf                 # Output values
│   └── modules/
│       ├── network/               # VPC, subnets, SGs
│       ├── ec2/                   # Jenkins server
│       ├── ecr/                   # Container registries
│       └── eks/                   # Kubernetes cluster
│
├── k8s/                           # Raw Kubernetes Manifests
│   ├── namespace.yaml
│   ├── backend-deployment.yaml
│   ├── frontend-deployment.yaml
│   ├── service.yaml
│   ├── network-policy.yaml
│   └── rbac.yaml
│
├── helm/sentinelops/              # Helm Chart
│   ├── Chart.yaml
│   ├── values.yaml                # Configurable parameters
│   └── templates/
│       ├── deployment.yaml
│       ├── service.yaml
│       ├── ingress.yaml
│       └── secrets.yaml
│
├── argocd/                        # ArgoCD GitOps Configuration
│   ├── applications/
│   │   ├── sentinelops-dev.yaml
│   │   ├── sentinelops-staging.yaml
│   │   └── sentinelops-prod.yaml
│   ├── app-of-apps/
│   │   └── root-application.yaml
│   ├── projects/
│   │   └── sentinelops-project.yaml
│   └── image-updater/
│       └── configmap.yaml
│
├── deployment/
│   ├── deploy.sh                  # EKS deployment script
│   └── rollback.sh                # Automated rollback
│
├── monitoring/
│   ├── prometheus/
│   │   └── prometheus.yml         # Scraping config
│   ├── grafana/
│   │   └── dashboards/
│   └── elk/
│       └── logstash.conf
│
├── compliance/                    # Generated Artifacts
│   ├── reports/                   # Raw scanner outputs
│   ├── normalized/                # Normalized findings
│   ├── master_reports/            # Aggregated reports
│   └── logs/                      # Execution logs
│
├── docs/
│   ├── architecture.md
│   └── DevSecOps_Project_Guide.md
│
├── scripts/                       # Utility scripts
│
├── Jenkinsfile                    # 17-Stage Declarative Pipeline
├── docker-compose.yml             # Local dev environment
├── requirements.txt               # Python dependencies
├── .pre-commit-config.yaml        # Pre-commit hooks
└── .gitignore
```

---

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- Python 3.11+
- Node.js 20+
- AWS CLI (configured)
- kubectl + Helm
- Jenkins (for CI/CD)

### Local Development

```bash
# 1. Clone the repository
git clone https://github.com/9MayanK2/SentinelOps.git
cd DevSecOps

# 2. Install pre-commit hooks
pip install pre-commit && pre-commit install

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Start local development environment
docker-compose up --build
```

**Access:**
- Frontend: http://localhost:3000
- Backend: http://localhost:5000
- Backend Health: http://localhost:5000/health

### Run Security Scans

```bash
# Full security pipeline
./security/run_pipeline.sh full

# Pre-build scans only (SAST + Secrets)
./security/run_pipeline.sh pre-build

# Post-build scans (Container CVE scan)
./security/run_pipeline.sh post-build

# DAST scan only
./security/run_pipeline.sh dast zap

# Security gate evaluation (soft-fail mode)
./security/run_pipeline.sh gate --soft-fail

# Generate compliance reports
./security/run_pipeline.sh report

# Sign container images
./security/run_pipeline.sh sign

# Verify signatures
./security/run_pipeline.sh verify
```

### Deploy to AWS EKS

```bash
# 1. Provision infrastructure
cd terraform
terraform init
terraform apply

# 2. Configure kubectl
aws eks update-kubeconfig --region us-east-1 --name sentinelops-dev-eks

# 3. Option A: ArgoCD (GitOps)
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
kubectl apply -f argocd/applications/sentinelops-dev.yaml

# 4. Option B: Helm (Traditional)
helm upgrade --install sentinelops ./helm/sentinelops \
  --namespace sentinelops --create-namespace \
  --set backend.image.tag=build-42 \
  --set frontend.image.tag=build-42
```

---

## 🔧 Configuration

### Security Policy

Edit `security/config/policy.yaml` to configure gate thresholds:

```yaml
policy:
  fail_on_critical: true        # Fail pipeline on CRITICAL CVEs
  fail_on_high: false           # Allow HIGH severity (warn only)
  minimum_score: 70.0           # Minimum compliance score %
  max_allowed_risk_score: 50    # Maximum risk score threshold
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DB_TYPE` | Database type (`sqlite` / `postgres`) | `sqlite` |
| `DB_PATH` | SQLite database path | `compliance/db/security_framework.db` |
| `SOFT_FAIL` | Enable soft-fail mode for gate | `false` |
| `ENFORCE_GATE` | Enforce security gate | `true` |
| `AWS_REGION` | AWS region | `us-xxxxx` |
| `AWS_ACCOUNT_ID` | AWS account ID | `2xxxxxxxx` |
| `EKS_CLUSTER` | EKS cluster name | `sentinelops-dev-eks` |

---

## 📊 Layer-by-Layer Deep Dive

### Layer 1: Secure Development (Shift-Left)

Every commit is automatically screened before it enters the repository:

| Hook | Purpose | Blocks Commit? |
|------|---------|---------------|
| **Gitleaks** | Detect hardcoded secrets, API keys, tokens | ✅ Yes |
| **Semgrep** | Static Application Security Testing (SAST) | ✅ Yes |
| **ESLint (Frontend)** | Code quality & security linting | ✅ Yes |
| **ESLint (Backend)** | Code quality & security linting | ✅ Yes |
| **File Hygiene** | YAML/JSON validation, large file checks | ✅ Yes |

### Layer 2: Jenkins CI/CD — 17 Stages

| Stage | Action | Security Value |
|-------|--------|---------------|
| 1 | Checkout Source | Pull latest code from GitHub |
| 2 | Install Python Deps | Install framework dependencies |
| 3 | Generate .env | Inject secrets from Jenkins Credentials — **never hardcoded** |
| 4 | Pre-Commit Validation | Re-run Gitleaks + ESLint + Semgrep in CI |
| 5 | Hadolint | Lint Dockerfiles for security best practices |
| 6 | Build Backend | Multi-stage Docker build (Node → Alpine) |
| 7 | Build Frontend | Multi-stage build (Node → Nginx) |
| 8 | Trivy CVE Scan | Scan both images for CRITICAL/HIGH CVEs |
| 9 | OWASP ZAP DAST | Dynamic scan of running application |
| 10 | Generate Reports | Aggregate all scan results |
| 11 | Security Gate | Python risk scorer — **pass/fail decision** |
| 12 | Cosign Signing | PKI digital signature on both images |
| 13 | Verify Signatures | Confirm signatures before push |
| 14 | Login ECR | Authenticate with Amazon ECR |
| 15 | Push Images | Push signed images with build tag + latest |
| 16 | Deploy to EKS | Helm upgrade — rolling deployment |
| 17 | Verify Rollout | `kubectl rollout status` with 5m timeout |

### Layer 3: Security Framework (Python Orchestrator)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     PYTHON SECURITY ORCHESTRATOR                            │
│                     security/core/orchestrator.py                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────┐                                                    │
│  │  STAGE 1            │  Pre-flight Checks (Docker, dirs, policy)         │
│  └──────────┬──────────┘                                                    │
│             ▼                                                               │
│  ┌─────────────────────┐                                                    │
│  │  STAGE 2            │  Run Scanners (Gitleaks, Hadolint, Trivy, ZAP)    │
│  └──────────┬──────────┘                                                    │
│             ▼                                                               │
│  ┌─────────────────────┐                                                    │
│  │  STAGE 3            │  Run Parsers (Normalize to common schema)         │
│  └──────────┬──────────┘                                                    │
│             ▼                                                               │
│  ┌─────────────────────┐                                                    │
│  │  STAGE 4            │  Aggregate Results + Compliance Mapping           │
│  │                     │  (OWASP + CIS + NIST) + Generate HTML/PDF         │
│  └──────────┬──────────┘                                                    │
│             ▼                                                               │
│  ┌─────────────────────┐                                                    │
│  │  STAGE 5            │  Security Gate Evaluation                         │
│  │                     │  Risk Score vs Threshold → PASS (0) / FAIL (1)    │
│  └──────────┬──────────┘                                                    │
│    ┌────────┴────────┐                                                      │
│    ▼                 ▼                                                      │
│ ┌──────┐       ┌────────┐                                                   │
│ │ PASS │       │  FAIL  │                                                   │
│ │Exit 0│       │ Exit 1 │                                                   │
│ └──────┘       └────────┘                                                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Risk Engine Scoring:**

| Severity | Weight | Description |
|----------|--------|-------------|
| CRITICAL | 10 pts | RCE, SQLi, hardcoded secrets |
| HIGH | 5 pts | Privilege escalation, XSS |
| MEDIUM | 2 pts | Information disclosure |
| LOW | 1 pt | Minor misconfigurations |
| INFO | 0 pts | Informational only |

**Risk Levels:**
- **NONE**: 0 points
- **LOW**: 1–10 points
- **MEDIUM**: 11–30 points
- **HIGH**: 31–60 points
- **CRITICAL**: 61+ points

### Layer 4: AWS Deployment

| Component | Technology | Security Feature |
|-----------|-----------|-----------------|
| VPC | Custom (10.0.0.0/16) | Network isolation |
| Public Subnets | 2x (us-east-1a, 1b) | ALB, NAT Gateway, Bastion |
| Private Subnets | 2x (us-east-1a, 1b) | EKS nodes, monitoring stack |
| EKS | v1.33 | Managed node groups, IAM roles |
| ECR | 2 repositories | Signed image storage |
| ALB | Application Load Balancer | SSL termination, path routing |
| WAF | AWS WAF v2 | SQLi/XSS rules, rate limiting |
| Secrets | AWS Secrets Manager | Runtime injection via CSI |

### Layer 5: Monitoring & SIEM

| Tool | Type | Function |
|------|------|----------|
| **Prometheus** | Metrics | Scrape node-exporter, kube-state-metrics, app endpoints |
| **Grafana** | Visualization | Cluster health, pod restarts, network traffic, security events |
| **ELK Stack** | Log Aggregation | Logstash → Elasticsearch → Kibana with correlation rules |
| **Wazuh** | HIDS | File integrity monitoring, rootkit detection, compliance |
| **Snort** | NIDS | Port scan detection, exploit attempts, C2 traffic |

**Alert Channels:** PagerDuty | Email | Slack

### Layer 6: Compliance & Reporting

| Framework | Controls Mapped | Auto-Report |
|-----------|----------------|-------------|
| **NIST CSF** | Identify, Protect, Detect, Respond, Recover | ✅ |
| **ISO 27001** | A.12.6, A.13.1, A.16.1 | ✅ |
| **OWASP Top 10** | A01–A10 | ✅ |
| **CIS Benchmarks** | Docker + Kubernetes | ✅ |
| **PCI-DSS** | Req 6, Req 11 | ✅ |

**Generated Artifacts:**
- `compliance/master_reports/master_report.json` — Aggregated findings
- `compliance/reports/compliance/compliance_matrix.json` — Framework scores
- `compliance/reports/signing/signature_*.json` — PKI audit trail
- HTML Executive Report — Visual dashboard
- PDF Report — Management-ready export

---

## 👥 Team & Credits

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  BUILT BY A 4-PERSON TEAM FOR PGCP-ITISS PROGRAM                           │
│  Sunbeam CDAC ACTS, Pune | February 2026                                   │
│                                                                             │
│  ┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐ │
│  │  DevSecOps Lead     │  │  Security Engineer  │  │  Cloud & Monitoring │ │
│  │                     │  │                     │  │                     │ │
│  │  • Jenkins CI/CD    │  │  • Gitleaks/Semgrep │  │  • AWS EKS/IaC      │ │
│  │  • Docker Hardening │  │  • Hadolint         │  │  • Prometheus/Grafana│ │
│  │  • Trivy/Hadolint   │  │  • OWASP ZAP        │  │  • ELK Stack        │ │
│  │  • K8s/Helm/ArgoCD  │  │  • Python Scoring   |  │  • Grafana Dashboard  │ │
│  │  • Cosign Signing   │  │  • PKI/TLS Certs    │  │  • MySQL/Reports    │ │
│  └─────────────────────┘  └─────────────────────┘  └─────────────────────┘ │
│                                                                             │
│                                                                             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 📚 Acknowledgments

- **Sunbeam, Pune** — Comprehensive DevSecOps curriculum and guidance
- **Trivy** by Aqua Security — Container vulnerability scanner
- **OWASP ZAP** by OWASP — Dynamic application security testing
- **Cosign** by Sigstore — Container image signing and verification
- **Wazuh** by Wazuh Team — Host-based intrusion detection
- **Gitleaks** by Zachary Rice — Secret detection in code
- **Semgrep** by Semgrep, Inc. — Lightweight static analysis
- **ArgoCD** by Argo Proj — Declarative GitOps for Kubernetes

---

<div align="center">

**Built with ❤️ for the future of secure software delivery.**

[⭐ Star this repo](https://github.com/9MayanK2/SentinelOps) • [🐛 Report Issues](https://github.com/9MayanK2/SentinelOps/issues) • [📝 Read Docs](./docs)

</div>
