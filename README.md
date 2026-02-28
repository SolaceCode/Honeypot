# 🍯 SSH Honeypot - Cowrie Deployment

![Image Banner](Images/banner.png)

A low-interaction SSH honeypot built with Cowrie to capture and analyze attacker behavior in real-time. This project demonstrates practical threat intelligence gathering, log analysis, and automated alerting.

![Project Status](https://img.shields.io/badge/status-complete-brightgreen)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-orange)

---

## Overview

This project deploys a secure SSH honeypot that mimics a real Linux server. When attackers attempt to break in, they are trapped in a safe, isolated environment where every action they take is logged and analyzed.

**Purpose:** Understand attacker behavior, gather threat intelligence, and strengthen defensive security strategies.

---

## Features

- ✅ **Cowrie Honeypot** – Industry-standard SSH honeypot
- ✅ **Port Redirection** – All port 22 traffic forwarded to honeypot
- ✅ **Real-Time Alerts** – Telegram notifications for every attacker connection
- ✅ **Log Analysis** – Custom Python script generates threat intelligence reports
- ✅ **Systemd Service** – Runs persistently in the background
- ✅ **JSON Logging** – Structured logs for easy parsing

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Honeypot | Cowrie |
| Language | Python 3 |
| OS | Ubuntu Linux |
| Alerting | Telegram Bot API |
| Log Parsing | Python (json, collections) |
| Persistence | systemd |
| Networking | iptables |

---

"""
Project: SSH Honeypot
Author: Solace Ngugi
Date: 21-02-2026
Notion: https://www.notion.so/SSH-Honeypot-3115a65918868041aa7ff74b91a7e7a7
"""


