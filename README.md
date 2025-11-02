# Autonomous AI Security Agent
This project is a 24/7 autonomous security agent that uses Google's Gemini AI to detect, analyze, and respond to cybersecurity threats on a Linux server in real-time.
It integrates with a Wazuh SIEM to monitor for malicious activity (like SSH brute-force attacks) and automatically blocks attackers by adding rules to the `iptables` firewall.
___
### Working

The agent runs as a persistent `systemd` service, following a continuous "Detect, Analyze, Respond" loop.

1.  **Detect:** The agent polls the Wazuh Indexer (OpenSearch) on `localhost:9200` every 10 seconds, querying for new alerts.
2.  **Analyze:** When a potential threat is found (e.g., an alert containing "sshd: authentication failed" or "non-existent user"), the full JSON alert is sent to the **Google Gemini API**. A "smart prompt" (see `main.py`) instructs the AI to act as a senior security analyst and return a simple "YES" or "NO" decision.
3.  **Respond:**
    * If **Gemini Decision: YES**, the agent extracts the attacker's `srcip` from the alert.
    * It then instantly executes an `iptables` command to insert a firewall rule, dropping all packets from that IP.
4.  **Remember:** The agent maintains a "memory" (`seen_alerts.txt`) to ensure it never processes the same alert twice, even after a system reboot.

---

### Core Technologies

* **Python 3:** The core agent logic (`requests`, `subprocess`, `json`).
* **Agentic AI:** Google Gemini Pro (via API) for autonomous decision-making.
* **SIEM:** Wazuh (for log analysis and alert generation).
* **Database:** OpenSearch (Wazuh's indexer, queried on port 9200).
* **Firewall:** `iptables` (for real-time, persistent IP blocking).
* **Linux/DevOps:** Amazon Linux, `systemd` (to run as a 24/7 service), `yum`.
