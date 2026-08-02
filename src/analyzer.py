import pandas as pd
import json
import os
from datetime import datetime


class PolicyAnalyzer:
    def __init__(self, policy_file=None):
        if policy_file is None:
            BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            policy_file = os.path.join(BASE_DIR, "configs", "security_policies.json")
        self.policies = self.load_policies(policy_file)
        self.violations = []

    def load_policies(self, policy_file):
        try:
            with open(policy_file, 'r') as f:
                data = json.load(f)
            print(f"✅ Loaded security policies")
            return data
        except Exception as e:
            print(f"❌ Could not load policies: {e}")
            return {}

    def analyze_firewall_logs(self, df):
        print("\n🔍 Analyzing firewall logs...")
        all_violations = []

        checks = [
            ("Blocked Ports",       self.check_blocked_ports),
            ("Blacklisted IPs",     self.check_blacklisted_ips),
            ("After Hours Access",  self.check_after_hours),
            ("Large Data Transfer", self.check_large_transfer),
            ("Brute Force",         self.check_brute_force),
            ("Suspicious Ports",    self.check_suspicious_ports),
            ("Protocol Violations", self.check_protocol_violations),
            ("Excessive Denials",   self.check_excessive_denials),
        ]

        for name, func in checks:
            results = func(df)
            all_violations.extend(results)
            icon = "🔴" if results else "✅"
            print(f"  {icon} {name}: {len(results)} violations")

        self.violations = all_violations
        print(f"\n📊 Total Firewall Violations: {len(all_violations)}")
        return all_violations

    def analyze_router_logs(self, df):
        print("\n🔍 Analyzing router logs...")
        violations = []

        failed  = df[df['event'] == 'LOGIN_FAILED']
        counts  = failed.groupby('ip').size().reset_index(name='count')
        limit   = self.policies.get("max_failed_logins", 5)
        flagged = counts[counts['count'] >= limit]

        for _, row in flagged.iterrows():
            violations.append({
                "violation_type": "ROUTER_BRUTE_FORCE",
                "severity":       "CRITICAL",
                "timestamp":      str(datetime.now()),
                "src_ip":         row['ip'],
                "dst_ip":         "Router",
                "dst_port":       22,
                "protocol":       "SSH",
                "action":         "DENY",
                "description":    f"Router brute force from {row['ip']}: {row['count']} attempts",
                "recommendation": "Block IP immediately and enable MFA"
            })

        config = df[df['event'] == 'CONFIG_CHANGE']
        for _, row in config.iterrows():
            violations.append({
                "violation_type": "UNAUTHORIZED_CONFIG_CHANGE",
                "severity":       "HIGH",
                "timestamp":      str(row['timestamp']),
                "src_ip":         row['ip'],
                "dst_ip":         "Router",
                "dst_port":       22,
                "protocol":       "SSH",
                "action":         "ALLOW",
                "description":    f"Router config changed: {row['message']}",
                "recommendation": "Verify if this change was authorized"
            })

        print(f"  🔴 Router Violations: {len(violations)}")
        return violations

    def check_blocked_ports(self, df):
        violations = []
        blocked = self.policies.get("blocked_ports", [])
        flagged = df[df['dst_port'].isin(blocked)]
        for _, row in flagged.iterrows():
            violations.append({
                "violation_type": "BLOCKED_PORT",
                "severity":       "HIGH",
                "timestamp":      str(row['timestamp']),
                "src_ip":         row['src_ip'],
                "dst_ip":         row['dst_ip'],
                "dst_port":       int(row['dst_port']),
                "protocol":       row['protocol'],
                "action":         row['action'],
                "description":    f"Connection on blocked port {int(row['dst_port'])}",
                "recommendation": f"Ensure port {int(row['dst_port'])} is blocked at perimeter"
            })
        return violations

    def check_blacklisted_ips(self, df):
        violations = []
        blacklisted = self.policies.get("blocked_ips", [])
        for direction, col in [("FROM", "src_ip"), ("TO", "dst_ip")]:
            flagged = df[df[col].isin(blacklisted)]
            for _, row in flagged.iterrows():
                violations.append({
                    "violation_type": "BLACKLISTED_IP",
                    "severity":       "CRITICAL",
                    "timestamp":      str(row['timestamp']),
                    "src_ip":         row['src_ip'],
                    "dst_ip":         row['dst_ip'],
                    "dst_port":       int(row['dst_port']),
                    "protocol":       row['protocol'],
                    "action":         row['action'],
                    "description":    f"Traffic {direction} blacklisted IP: {row[col]}",
                    "recommendation": "Block this IP and investigate immediately"
                })
        return violations

    def check_after_hours(self, df):
        violations = []
        start = self.policies.get("allowed_hours", {}).get("start", 8)
        end   = self.policies.get("allowed_hours", {}).get("end", 18)
        df2   = df.copy()
        df2['hour'] = df2['timestamp'].dt.hour
        flagged = df2[
            ((df2['hour'] < start) | (df2['hour'] >= end)) &
            (df2['action'] == 'ALLOW')
        ]
        for _, row in flagged.iterrows():
            violations.append({
                "violation_type": "AFTER_HOURS_ACCESS",
                "severity":       "MEDIUM",
                "timestamp":      str(row['timestamp']),
                "src_ip":         row['src_ip'],
                "dst_ip":         row['dst_ip'],
                "dst_port":       int(row['dst_port']),
                "protocol":       row['protocol'],
                "action":         row['action'],
                "description":    f"Access at {row['hour']}:00 outside hours ({start}:00-{end}:00)",
                "recommendation": "Verify if after-hours access was authorized"
            })
        return violations

    def check_large_transfer(self, df):
        violations = []
        limit = self.policies.get("max_data_transfer_mb", 500) * 1024 * 1024
        flagged = df[df['bytes'] > limit]
        for _, row in flagged.iterrows():
            size_gb = row['bytes'] / (1024 ** 3)
            violations.append({
                "violation_type": "LARGE_DATA_TRANSFER",
                "severity":       "HIGH",
                "timestamp":      str(row['timestamp']),
                "src_ip":         row['src_ip'],
                "dst_ip":         row['dst_ip'],
                "dst_port":       int(row['dst_port']),
                "protocol":       row['protocol'],
                "action":         row['action'],
                "description":    f"Large transfer: {size_gb:.2f} GB detected",
                "recommendation": "Investigate for possible data exfiltration"
            })
        return violations

    def check_brute_force(self, df):
        violations = []
        max_attempts = self.policies.get("max_failed_logins", 5)
        denied  = df[df['action'].isin(['DENY', 'DROP'])]
        counts  = denied.groupby(['src_ip', 'dst_port']).size().reset_index(name='count')
        flagged = counts[counts['count'] >= max_attempts]
        for _, row in flagged.iterrows():
            violations.append({
                "violation_type": "BRUTE_FORCE_ATTEMPT",
                "severity":       "CRITICAL",
                "timestamp":      str(datetime.now()),
                "src_ip":         row['src_ip'],
                "dst_ip":         "Multiple Targets",
                "dst_port":       int(row['dst_port']),
                "protocol":       "TCP",
                "action":         "DENY",
                "description":    f"Brute force: {row['count']} attempts from {row['src_ip']} on port {int(row['dst_port'])}",
                "recommendation": "Block source IP immediately"
            })
        return violations

    def check_suspicious_ports(self, df):
        violations = []
        suspicious = self.policies.get("suspicious_ports", [])
        flagged = df[df['dst_port'].isin(suspicious)]
        for _, row in flagged.iterrows():
            violations.append({
                "violation_type": "SUSPICIOUS_PORT",
                "severity":       "HIGH",
                "timestamp":      str(row['timestamp']),
                "src_ip":         row['src_ip'],
                "dst_ip":         row['dst_ip'],
                "dst_port":       int(row['dst_port']),
                "protocol":       row['protocol'],
                "action":         row['action'],
                "description":    f"Traffic on suspicious port {int(row['dst_port'])} - possible malware",
                "recommendation": "Scan host for malware immediately"
            })
        return violations

    def check_protocol_violations(self, df):
        violations = []
        blocked = [p.upper() for p in self.policies.get("blocked_protocols", [])]
        flagged = df[df['protocol'].str.upper().isin(blocked)]
        for _, row in flagged.iterrows():
            violations.append({
                "violation_type": "PROTOCOL_VIOLATION",
                "severity":       "MEDIUM",
                "timestamp":      str(row['timestamp']),
                "src_ip":         row['src_ip'],
                "dst_ip":         row['dst_ip'],
                "dst_port":       int(row['dst_port']),
                "protocol":       row['protocol'],
                "action":         row['action'],
                "description":    f"Forbidden protocol: {row['protocol']}",
                "recommendation": f"Block {row['protocol']} at firewall level"
            })
        return violations

    def check_excessive_denials(self, df):
        violations = []
        limit   = self.policies.get("max_connections_per_minute", 50)
        denied  = df[df['action'].isin(['DENY', 'DROP'])].copy()
        denied['minute'] = denied['timestamp'].dt.floor('min')
        counts  = denied.groupby(['src_ip', 'minute']).size().reset_index(name='count')
        flagged = counts[counts['count'] > limit]
        for _, row in flagged.iterrows():
            violations.append({
                "violation_type": "EXCESSIVE_DENIALS",
                "severity":       "HIGH",
                "timestamp":      str(row['minute']),
                "src_ip":         row['src_ip'],
                "dst_ip":         "Multiple",
                "dst_port":       "Various",
                "protocol":       "Various",
                "action":         "DENY",
                "description":    f"{row['count']} denied connections in 1 min from {row['src_ip']}",
                "recommendation": "Possible port scan or DDoS - block IP"
            })
        return violations

    def get_summary(self):
        if not self.violations:
            return {"total": 0}
        df = pd.DataFrame(self.violations)
        return {
            "total":         len(self.violations),
            "by_severity":   df['severity'].value_counts().to_dict(),
            "by_type":       df['violation_type'].value_counts().to_dict(),
            "top_offenders": df['src_ip'].value_counts().head(5).to_dict()
        }