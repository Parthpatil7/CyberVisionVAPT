🛡️ CyberVision VAPT Framework

An AI-powered automated Vulnerability Assessment and Penetration Testing (VAPT) tool for CCTV cameras and DVRs.
Developed by Team PatchScout for Smart India Hackathon 2025 (Problem ID: SIH25233) under the Smart Automation theme.

🚀 Overview

CyberVision is a smart and scalable VAPT framework designed specifically for CCTV and DVR ecosystems.
It performs automated global discovery, machine learning-based vulnerability detection, safe penetration testing, and provides a real-time dashboard for threat monitoring and remediation.

🧠 Key Features

Automated Discovery Engine:
Uses Shodan API and Nmap to identify exposed CCTV/DVR devices worldwide.

AI-Powered Vulnerability Detection:
Employs ML models (XGBoost, IsolationForest) trained on CCTV datasets to detect, classify, and score vulnerabilities in real time.

Smart Exploitation Module:
Conducts safe and controlled penetration tests targeting CCTV-specific flaws like weak passwords and outdated firmware.

Real-Time Intelligence Dashboard:
Built with React and Chart.js, featuring global maps, device insights, CVE links, and remediation guidance.

Scalable & Modular Architecture:
Supports multiple camera/DVR models with plugin-based detection and validation modules.

⚙️ Tech Stack

Backend: Python, FastAPI, Redis, MongoDB/PostgreSQL, Docker
Frontend: React.js, Chart.js, Leaflet (for maps)
Scanning Tools: Nmap, Shodan API, ONVIF/RTSP probes
Machine Learning: Scikit-learn (XGBoost, IsolationForest), Pandas, NumPy

🔄 Workflow

Find CCTV/DVRs → Global device discovery

Collect Information → Metadata and network scan

Check Weak Points → Default creds, open RTSP, weak auth

Simulate Safe Tests → AI-driven vulnerability validation

Show Results & Fixes → Dashboard and downloadable reports

📊 Impact & Benefits

Enhances security visibility and reduces breach risk.

Saves time with automated scanning and reporting.

Provides compliance-ready audit logs.

Promotes proactive risk management and public safety.

🧩 Feasibility

Technically Viable: Built on proven, scalable open-source tools.

Market Ready: Growing CCTV market with demand for VAPT automation.

Legally Compliant: Safe scanning and complete audit trails.

Operationally Efficient: Minimal training with an intuitive web interface.

⚠️ Risk Mitigation
Risk	Mitigation
Privacy or Legal Violation	Authorized scope, safe-mode scanning, audit logs
False Positives/Negatives	Multi-source validation and ML model retraining
Scalability Issues	Distributed task queues and auto-scaling
Model Drift	Scheduled retraining and expert feedback integration
🔗 Resources

GitHub Repository: CyberVisionVAPT

Prototype Video: Watch on YouTube

Research References:

The Security of IP-based Video Surveillance Systems

Physical Integrity Attack Detection via Deep Learning

Shodan API Docs

Nmap Docs

NVD/CVE Database

👥 Team PatchScout

Mentors:

Prof. A. P. Bangar – Assistant Professor, Computer Networks

Mr. Dharmesh Vala – Software Engineer, Industry Mentor
