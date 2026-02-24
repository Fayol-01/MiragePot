# MiragePot Use Cases & Target Users

This document outlines the intended users of MiragePot and their specific use cases.

---

## Target Users

### 1. Students & Academics 🎓

| Role | Use Case |
|------|----------|
| **CS/Cybersecurity Students** | Mini-projects, thesis research, learning honeypot concepts |
| **University Labs** | Practical demonstrations of deception technology |
| **Professors/Instructors** | Teaching network security, AI applications in cybersecurity |

**Example Scenario:**  
A B.Tech student demonstrates MiragePot for a final year project on "AI-based Intrusion Detection Systems"

---

### 2. Security Researchers 🔬

| Role | Use Case |
|------|----------|
| **Threat Intelligence Analysts** | Collecting attacker TTPs, studying new attack vectors |
| **Malware Researchers** | Capturing malware droppers, C2 communication patterns |
| **Academic Researchers** | Publishing papers on attacker behavior, honeypot effectiveness |

**Example Scenario:**  
A researcher deploys MiragePot on a cloud VPS to study SSH brute-force patterns across different regions

---

### 3. Security Operations Teams (SOC) 🛡️

| Role | Use Case |
|------|----------|
| **SOC Analysts** | Training on attack recognition, incident response practice |
| **Red Team/Blue Team** | Purple team exercises, testing detection capabilities |
| **Security Engineers** | Evaluating honeypot integration into existing infrastructure |

**Example Scenario:**  
A SOC team uses MiragePot in a training lab to help junior analysts recognize common attacker commands

---

### 4. DevSecOps / Infrastructure Teams ⚙️

| Role | Use Case |
|------|----------|
| **DevOps Engineers** | Deploying decoy servers in production environments |
| **Cloud Architects** | Adding deception layers to cloud infrastructure |
| **Penetration Testers** | Understanding defender capabilities |

**Example Scenario:**  
A DevOps team deploys MiragePot alongside production servers to detect lateral movement attempts

---

### 5. Conference Presenters & Educators 📊

| Role | Use Case |
|------|----------|
| **Security Conference Speakers** | Live demos of AI-powered honeypots |
| **Workshop Instructors** | Hands-on cybersecurity training sessions |
| **Content Creators** | Educational content on honeypot technology |

**Example Scenario:**  
A speaker at a security conference demonstrates real-time attacker engagement using MiragePot

---

### 6. Small Businesses / Startups 🏢

| Role | Use Case |
|------|----------|
| **IT Administrators** | Early warning system for network intrusions |
| **Startup CTOs** | Low-cost threat detection without expensive solutions |

**Example Scenario:**  
A startup deploys MiragePot on an unused IP to detect if their network is being scanned

---

## Primary Use Cases

### 1. Cybersecurity Research & Threat Intelligence

- **Capture attacker behavior** - Log all commands, credentials, and techniques used by attackers
- **MITRE ATT&CK mapping** - Automatically detect and classify attack techniques (TTPs)
- **Honeytoken tracking** - Plant fake credentials/API keys to detect data exfiltration attempts
- **Geographic analysis** - Track attacker locations via IP geolocation

### 2. Academic/Educational Demonstrations

- **Student projects** - Demonstrates practical concepts in cybersecurity, network protocols, and applied AI
- **Demo-ready** - Includes complete walkthrough for technical presentations
- **Offline deployment** - Can be deployed without internet for conference/classroom demos

### 3. Security Operations Training

- Train SOC analysts on recognizing attack patterns
- Practice incident response workflows
- Study attacker TTPs in a safe, sandboxed environment

### 4. Network Deception & Early Warning

- Deploy as decoy servers to detect unauthorized access attempts
- Generate alerts when attackers interact with honeypot
- Slow down attackers with tarpit mechanisms

---

## User Distribution (Estimated)

```
┌─────────────────────────────────────────────────────┐
│  Students/Academics         ████████████████  45%   │
│  Security Researchers       ██████████        25%   │
│  SOC/Security Teams         ██████            15%   │
│  DevSecOps                  ████              10%   │
│  Others                     ██                 5%   │
└─────────────────────────────────────────────────────┘
```

---

## Who Should NOT Use This

| User | Reason |
|------|--------|
| **Production-critical environments** | Honeypots should be isolated, not protecting real assets |
| **Non-technical users** | Requires understanding of SSH, Docker, and security concepts |
| **Malicious actors** | This is a defensive tool, not for attacking systems |

---

## Deployment Scenarios

### Scenario 1: University Lab Setup

```
┌──────────────────────────────────────────────────────────┐
│  University Network                                       │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │  Student    │    │  MiragePot  │    │  Dashboard  │  │
│  │  Workstations│───▶│  Honeypot   │◀───│  (Streamlit)│  │
│  └─────────────┘    └─────────────┘    └─────────────┘  │
│                            │                              │
│                     ┌──────▼──────┐                      │
│                     │  Session    │                      │
│                     │  Logs/JSON  │                      │
│                     └─────────────┘                      │
└──────────────────────────────────────────────────────────┘
```

### Scenario 2: Cloud Research Deployment

```
┌──────────────────────────────────────────────────────────┐
│  Cloud VPS (AWS/GCP/Azure)                               │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │  Internet   │    │  MiragePot  │    │  Prometheus │  │
│  │  Attackers  │───▶│  Port 2222  │───▶│  + Grafana  │  │
│  └─────────────┘    └─────────────┘    └─────────────┘  │
│                            │                              │
│                     ┌──────▼──────┐                      │
│                     │  TTP/ATT&CK │                      │
│                     │  Analysis   │                      │
│                     └─────────────┘                      │
└──────────────────────────────────────────────────────────┘
```

### Scenario 3: Enterprise Deception Layer

```
┌──────────────────────────────────────────────────────────┐
│  Enterprise Network                                       │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │  Production │    │  MiragePot  │    │  SIEM       │  │
│  │  Servers    │    │  (Decoy)    │───▶│  Integration│  │
│  └─────────────┘    └─────────────┘    └─────────────┘  │
│         │                  │                              │
│         └──────────────────┘                              │
│              Same subnet (detection)                      │
└──────────────────────────────────────────────────────────┘
```

---

## Getting Started by User Type

| User Type | Recommended Setup | Documentation |
|-----------|-------------------|---------------|
| **Students** | Docker Simple Stack | [DEMO_WALKTHROUGH.md](DEMO_WALKTHROUGH.md) |
| **Researchers** | Full Docker Stack | [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md) |
| **SOC Teams** | Full Stack + Grafana | [MONITORING.md](MONITORING.md) |
| **Presenters** | Offline Deployment | [OFFLINE_DEPLOYMENT.md](OFFLINE_DEPLOYMENT.md) |
| **Developers** | Local Python Setup | [INSTALL.md](INSTALL.md) |

---

## Summary

MiragePot is designed primarily for **students, researchers, and security professionals** who want to:

1. Study attacker behavior in a safe environment
2. Learn about honeypot technology and AI applications in security
3. Train on incident response and threat detection
4. Demonstrate modern deception technology

The project prioritizes **ease of deployment**, **educational value**, and **privacy** (all AI processing is local).
