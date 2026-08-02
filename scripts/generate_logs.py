import random
import csv
import os
from datetime import datetime, timedelta


def generate_firewall_logs(filename=None, count=1000):
    """Generate realistic sample firewall logs"""

    if filename is None:
        BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        filename = os.path.join(BASE_DIR, "logs", "sample_firewall.log")

    internal_ips = [f"192.168.1.{i}" for i in range(1, 50)]
    external_ips = [
        f"203.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        for _ in range(20)
    ]
    malicious_ips = [
        "185.220.101.45",
        "194.165.16.72",
        "91.108.4.1",
        "45.142.212.100"
    ]
    suspicious_ports = [4444, 1337, 31337, 9090]
    logs = []
    start_time = datetime.now() - timedelta(days=7)

    for i in range(count):
        timestamp = start_time + timedelta(minutes=random.randint(0, 10080))
        traffic_type = random.choice([
            "normal", "normal", "normal", "normal",
            "blocked_port", "malicious_ip", "after_hours",
            "large_transfer", "suspicious_ip", "brute_force"
        ])

        if traffic_type == "blocked_port":
            src_ip = random.choice(internal_ips)
            dst_ip = random.choice(external_ips)
            dst_port = random.choice([23, 3389, 445, 135])
            action = "DENY"
            protocol = "TCP"
            bytes_transferred = random.randint(0, 1000)

        elif traffic_type == "malicious_ip":
            src_ip = random.choice(malicious_ips)
            dst_ip = random.choice(internal_ips)
            dst_port = random.choice([22, 80, 443])
            action = random.choice(["DENY", "DROP"])
            protocol = "TCP"
            bytes_transferred = random.randint(1000, 50000)

        elif traffic_type == "after_hours":
            src_ip = random.choice(internal_ips)
            dst_ip = random.choice(external_ips)
            dst_port = random.choice([80, 443])
            action = "ALLOW"
            protocol = "HTTP"
            timestamp = timestamp.replace(
                hour=random.choice([0, 1, 2, 3, 4, 5, 6, 7, 19, 20, 21, 22, 23])
            )
            bytes_transferred = random.randint(1000, 10000)

        elif traffic_type == "large_transfer":
            src_ip = random.choice(internal_ips)
            dst_ip = random.choice(external_ips)
            dst_port = 443
            action = "ALLOW"
            protocol = "HTTPS"
            bytes_transferred = random.randint(500000000, 2000000000)

        elif traffic_type == "suspicious_ip":
            src_ip = random.choice(internal_ips)
            dst_ip = random.choice(malicious_ips)
            dst_port = random.choice(suspicious_ports)
            action = "DENY"
            protocol = "TCP"
            bytes_transferred = random.randint(0, 5000)

        elif traffic_type == "brute_force":
            src_ip = random.choice(malicious_ips)
            dst_ip = random.choice(internal_ips)
            dst_port = 22
            action = "DENY"
            protocol = "SSH"
            for _ in range(random.randint(5, 20)):
                logs.append({
                    "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": random.randint(1024, 65535),
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "action": "DENY",
                    "bytes": 0,
                    "rule_id": f"RULE_{random.randint(1, 100)}",
                    "interface": random.choice(["eth0", "eth1", "wan0"])
                })
            continue

        else:
            src_ip = random.choice(internal_ips)
            dst_ip = random.choice(external_ips)
            dst_port = random.choice([80, 443, 53])
            action = "ALLOW"
            protocol = random.choice(["HTTP", "HTTPS", "DNS"])
            bytes_transferred = random.randint(1000, 100000)

        logs.append({
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": random.randint(1024, 65535),
            "dst_port": dst_port,
            "protocol": protocol,
            "action": action,
            "bytes": bytes_transferred,
            "rule_id": f"RULE_{random.randint(1, 100)}",
            "interface": random.choice(["eth0", "eth1", "wan0"])
        })

    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=logs[0].keys())
        writer.writeheader()
        writer.writerows(logs)

    print(f"✅ Generated {len(logs)} firewall log entries → {filename}")
    return filename


def generate_router_logs(filename=None, count=500):
    """Generate sample router logs"""

    if filename is None:
        BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        filename = os.path.join(BASE_DIR, "logs", "sample_router.log")

    events = [
        "LOGIN_SUCCESS", "LOGIN_FAILED", "CONFIG_CHANGE",
        "ACL_MATCH", "ROUTE_CHANGE", "INTERFACE_DOWN"
    ]
    users = ["admin", "root", "user1", "netadmin", "unknown"]
    ips = [f"192.168.1.{i}" for i in range(1, 30)]
    malicious_ips = ["185.220.101.45", "194.165.16.72"]
    logs = []
    start_time = datetime.now() - timedelta(days=7)

    for i in range(count):
        timestamp = start_time + timedelta(minutes=random.randint(0, 10080))
        event = random.choice(events)
        user = random.choice(users)

        if event == "LOGIN_FAILED":
            ip = random.choice(malicious_ips + ips)
            message = f"Authentication failed for user {user} from {ip}"
            severity = "WARNING"
        elif event == "LOGIN_SUCCESS":
            ip = random.choice(ips)
            user = random.choice(["admin", "netadmin"])
            message = f"User {user} logged in successfully from {ip}"
            severity = "INFO"
        elif event == "CONFIG_CHANGE":
            ip = random.choice(ips)
            message = f"Configuration changed by {user} from {ip}"
            severity = "CRITICAL"
        elif event == "ACL_MATCH":
            ip = random.choice(ips + malicious_ips)
            message = f"ACL rule matched for traffic from {ip}"
            severity = "WARNING"
        else:
            ip = "127.0.0.1"
            message = f"System event: {event}"
            severity = "INFO"

        logs.append({
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "event": event,
            "ip": ip,
            "user": user,
            "message": message,
            "severity": severity
        })

    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=logs[0].keys())
        writer.writeheader()
        writer.writerows(logs)

    print(f"✅ Generated {len(logs)} router log entries → {filename}")
    return filename


if __name__ == "__main__":
    print("🔄 Generating sample logs...")
    generate_firewall_logs()
    generate_router_logs()
    print("\n✅ All logs generated successfully!")