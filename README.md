# Security Assessor

AI-powered security assessment tool that transforms product names, URLs, or SHA1 hashes into CISO-ready trust briefs in 30–60 seconds.

---

## Key Features

- **Multi-Agent Verification**  
  3-agent pipeline (Research → Verification → Synthesis) prevents AI hallucinations

- **Tool-Based Fact-Checking**  
  Every CVE claim validated against the NVD database

- **MITRE ATT&CK Mapping**  
  Visualize attack techniques enabled by CVEs (Initial Access → Impact)

- **Trust Score (0–100)**  
  Transparent calculation:
  - 50% CVSS
  - 40% EPSS
  - 10% CISA KEV

- **30-Day Cache**  
  Instant results for repeat assessments

- **Multiple Inputs**
  - Product names
  - URLs
  - SHA1 file hashes (VirusTotal)

- **Data Sources**
  - NVD (CVE)
  - CISA KEV
  - EPSS
  - ProductHunt
  - VirusTotal
  - MITRE ATT&CK

- **Modern Stack**
  - React frontend
  - Flask backend
  - Real-time progress tracking

---

## How It Works

### 3-Agent Verification Pipeline

1. **Research Agent**
   - Analyzes CVE, KEV, and EPSS data
   - Generates findings with citations

2. **Verification Agent**
   - Validates every CVE against NVD using tools (`verify_cve()`)
   - Cross-checks CVSS scores

3. **Synthesis Agent**
   - Compiles verified data
   - Assigns confidence levels (High / Medium / Low)

Result: Tool-verified security reports, not AI hallucinations.

---

## Setup

### Prerequisites

- Python 3.8+ (3.11+ recommended)
- Node.js 20+ (for React frontend)
- Google Gemini API Key (required)  
  https://makersuite.google.com/app/apikey

---

### Quick Setup

```bash
# 1. Clone and navigate
git clone https://github.com/mohiuddinislam/professional_skills_project.git
cd app-rehension

# 2. Run automated setup
chmod +x setup.sh
./setup.sh
