#!/usr/bin/env python3
"""
SSH Honeypot Log Analyzer
Parses Cowrie JSON logs to extract threat intelligence
Author: Solace Ngugi
Date: 24-02-2026
"""

import json
import os
from collections import Counter
from datetime import datetime

# ── CONFIGURATION ──────────────────────────────────────────────────
# Path to Cowrie's JSON log — adjust this to your actual path
LOG_PATH = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"

# ── DATA COLLECTORS ────────────────────────────────────────────────
attempted_passwords = []   # Every password tried
attempted_usernames = []   # Every username tried
attacker_ips = []          # Source IP addresses
commands_run = []          # Commands typed in fake shell
login_successes = []       # Successful logins (used our allowed passwords)
session_timestamps = []    # When attacks happened

# ── PARSE THE LOG FILE ─────────────────────────────────────────────
print(f"[*] Reading log file: {LOG_PATH}")
print(f"[*] Analysis started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("-" * 60)

if not os.path.exists(LOG_PATH):
    print("[!] Log file not found. Make sure Cowrie is running and has received connections.")
    exit(1)

with open(LOG_PATH, 'r') as f:
    for line_number, line in enumerate(f, 1):
        line = line.strip()
        if not line:      # Skip empty lines 
            continue
        
        try:
            # Parse each line as JSON 
            event = json.loads(line)
            
            # Each event has an 'eventid' field telling us what happened
            event_type = event.get('eventid', '')
            
            # ── CAPTURE LOGIN ATTEMPTS ──
            if event_type == 'cowrie.login.failed':
                attempted_usernames.append(event.get('username', 'unknown'))
                attempted_passwords.append(event.get('password', 'unknown'))
                attacker_ips.append(event.get('src_ip', 'unknown'))
                session_timestamps.append(event.get('timestamp', ''))
            
            # ── CAPTURE SUCCESSFUL LOGINS ──
            elif event_type == 'cowrie.login.success':
                login_successes.append({
                    'ip': event.get('src_ip'),
                    'username': event.get('username'),
                    'password': event.get('password'),
                    'time': event.get('timestamp')
                })
                attacker_ips.append(event.get('src_ip', 'unknown'))
            
            # ── CAPTURE COMMANDS RUN IN FAKE SHELL ──
            elif event_type == 'cowrie.command.input':
                commands_run.append(event.get('input', ''))
            
        except json.JSONDecodeError:
            # Some log lines might not be valid JSON — skip them
            pass

# ── GENERATE THREAT INTELLIGENCE REPORT ───────────────────────────
print("\n" + "=" * 60)
print("        SSH HONEYPOT THREAT INTELLIGENCE REPORT")
print("=" * 60)

total_attempts = len(attempted_passwords)
unique_ips = len(set(attacker_ips))

print(f"\n📊 OVERVIEW")
print(f"   Total login attempts recorded : {total_attempts}")
print(f"   Unique attacker IPs           : {unique_ips}")
print(f"   Successful logins (into trap) : {len(login_successes)}")
print(f"   Commands executed by attackers: {len(commands_run)}")

# Top passwords and usernames give us insight into what attackers are trying most often, which can inform our defenses.
print(f"\n🔑 TOP 10 PASSWORDS ATTEMPTED")
password_counts = Counter(attempted_passwords)
for rank, (password, count) in enumerate(password_counts.most_common(10), 1):
    bar = "█" * min(count, 30)   # Visual bar, capped at 30 chars
    print(f"   {rank:2}. {password:<20} {count:>4} attempts  {bar}")

print(f"\n👤 TOP 10 USERNAMES ATTEMPTED")
username_counts = Counter(attempted_usernames)
for rank, (username, count) in enumerate(username_counts.most_common(10), 1):
    print(f"   {rank:2}. {username:<20} {count:>4} attempts")

print(f"\n🌍 TOP 10 ATTACKER IP ADDRESSES")
ip_counts = Counter(attacker_ips)
for rank, (ip, count) in enumerate(ip_counts.most_common(10), 1):
    print(f"   {rank:2}. {ip:<20} {count:>4} attempts")

if login_successes:
    print(f"\n⚠️  ATTACKERS WHO MADE IT INTO THE FAKE SHELL")
    for session in login_successes:
        print(f"   IP: {session['ip']} | User: {session['username']} | Pass: {session['password']}")

if commands_run:
    print(f"\n💻 TOP COMMANDS RUN BY ATTACKERS IN FAKE SHELL")
    command_counts = Counter(commands_run)
    for rank, (cmd, count) in enumerate(command_counts.most_common(15), 1):
        print(f"   {rank:2}. {cmd:<40} ({count}x)")

print(f"\n📋 SECURITY RECOMMENDATIONS BASED ON FINDINGS")
if password_counts:
    most_common_pass = password_counts.most_common(1)[0][0]
    print(f"   • Block accounts using password: '{most_common_pass}' — most targeted")
print(f"   • Implement fail2ban to block IPs after repeated failures")
print(f"   • Enforce SSH key-based authentication, disable password auth")
print(f"   • Consider geoblocking top attacker IP ranges")

print(f"\n{'=' * 60}")
print(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"{'=' * 60}\n")