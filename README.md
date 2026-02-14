# Cloud-Based Honeypot & Threat Intelligence System

![Project Status](https://img.shields.io/badge/Status-Completed-success)
![Platform](https://img.shields.io/badge/Platform-DigitalOcean-blue)
![Stack](https://img.shields.io/badge/Tech-T--Pot%20%7C%20MISP%20%7C%20ELK-orange)

## 📖 Project Overview
This project involves the deployment of a cloud-based honeypot architecture using **T-Pot 24.04** on a **DigitalOcean** droplet. The system was designed to simulate a vulnerable enterprise network, capture live attack data, and automate the ingestion of Indicators of Compromise (IoCs) into **MISP** (Malware Information Sharing Platform).

The goal was to analyze attacker behavior, map techniques to the **MITRE ATT&CK** framework, and generate actionable threat intelligence.

---

## 🏗️ Architecture
The system consists of three core components:
1.  **The Trap:** A **DigitalOcean Droplet (Ubuntu 22.04 LTS)** running T-Pot, exposing multiple honeypot services (Cowrie, Dionaea, Honeytrap) to the internet.
2.  **The Collection:** Logs are aggregated locally using the **ELK Stack** (Elasticsearch, Logstash, Kibana) for real-time visualization.
3.  **The Intel:** A separate instance running **MISP** is used to store and correlate the collected IoCs (IPs, Hashes, Payloads) for threat sharing.

*[Insert a screenshot of your Architecture Diagram from Page 26 here]*

---

## 🚀 Key Features
* **Multi-Vector Data Collection:** Captures attacks across SSH, HTTP, SMB, and ADB using specialized honeypot drivers.
* **Automated Deployment:** Utilizes cloud-init scripts for rapid provisioning of sensor nodes.
* **Threat Visualization:** Custom Kibana dashboards to track:
    * Top Attacker Source IPs & Geo-location.
    * Most Targeted Ports & Services.
    * Malware Payload Analysis.
* **MISP Integration:** Automated feeding of captured threat data into a Threat Intelligence Platform.

---

## 📊 Results & Analysis
During the operational period, the honeypot successfully captured significant attack traffic. Key findings included:
* **High Volume of SSH Bruteforce:** The Cowrie honeypot recorded the highest number of interactions, primarily targeting port 22.
* **Common Attack Vectors:** Exploitation attempts were frequently observed on SMB (WannaCry style) and ADB (Android Debug Bridge) ports.

*[Insert Screenshot of your T-Pot Attack Map or Kibana Dashboard here]*

---

## 🛠️ Installation & Setup
To replicate this setup:

1.  **Provision Cloud Server:**
    * Provider: DigitalOcean
    * OS: Ubuntu 22.04 LTS (Minimum 8GB RAM).
2.  **Install T-Pot:**
    ```bash
    git clone [https://github.com/telekom-security/tpotce](https://github.com/telekom-security/tpotce)
    cd tpotce/iso/installer/
    ./install.sh --type=user
    ```
3.  **Configure Firewall:** Ensure only administrative ports (64294, 64295, 64297) are accessible to your management IP.

---

## 📄 Documentation
For a deep dive into the implementation details, configuration, and full analysis, please refer to the comprehensive project report:
* [**Download Full Project Report (PDF)**](./HenryDavidKee_FYP2.pdf)

---

### ⚠️ Disclaimer
*This project involves handling live malware and attack traffic. It was conducted in a strictly isolated cloud environment. Do not deploy this on a production network.*
