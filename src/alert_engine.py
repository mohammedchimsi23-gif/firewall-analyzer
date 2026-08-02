from datetime import datetime
from colorama import Fore, init

init(autoreset=True)


class AlertEngine:
    def __init__(self):
        self.alerts = []

    SEVERITY_PRIORITY = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    SEVERITY_COLORS   = {
        "CRITICAL": Fore.RED,
        "HIGH":     Fore.YELLOW,
        "MEDIUM":   Fore.CYAN,
        "LOW":      Fore.GREEN
    }

    def generate_alerts(self, violations):
        self.alerts = []
        for i, v in enumerate(violations):
            self.alerts.append({
                "alert_id":       f"ALERT-{i+1:04d}",
                "timestamp":      v.get("timestamp", str(datetime.now())),
                "violation_type": v.get("violation_type"),
                "severity":       v.get("severity", "LOW"),
                "src_ip":         v.get("src_ip"),
                "dst_ip":         v.get("dst_ip"),
                "dst_port":       v.get("dst_port"),
                "protocol":       v.get("protocol"),
                "description":    v.get("description"),
                "recommendation": v.get("recommendation"),
                "status":         "OPEN"
            })
        self.alerts.sort(
            key=lambda x: self.SEVERITY_PRIORITY.get(x['severity'], 0),
            reverse=True
        )
        return self.alerts

    def print_alerts(self, limit=20):
        print("\n" + "=" * 60)
        print("🚨  SECURITY VIOLATION ALERTS")
        print("=" * 60)
        if not self.alerts:
            print(Fore.GREEN + "✅ No violations detected!")
            return
        for alert in self.alerts[:limit]:
            color = self.SEVERITY_COLORS.get(alert['severity'], Fore.WHITE)
            print(f"\n{color}{'─' * 55}")
            print(f"{color}  [{alert['severity']}]  {alert['alert_id']}")
            print(f"  Type     : {alert['violation_type']}")
            print(f"  Time     : {alert['timestamp']}")
            print(f"  Source   : {alert['src_ip']}")
            print(f"  Dest     : {alert['dst_ip']} : {alert['dst_port']}")
            print(f"  Detail   : {alert['description']}")
            print(f"  Action   : {alert['recommendation']}")
        if len(self.alerts) > limit:
            print(f"\n  ... and {len(self.alerts) - limit} more alerts")
        print(f"\n{Fore.WHITE}  Total: {len(self.alerts)} alerts generated")

    def get_stats(self):
        return {
            "total":    len(self.alerts),
            "critical": sum(1 for a in self.alerts if a['severity'] == 'CRITICAL'),
            "high":     sum(1 for a in self.alerts if a['severity'] == 'HIGH'),
            "medium":   sum(1 for a in self.alerts if a['severity'] == 'MEDIUM'),
            "low":      sum(1 for a in self.alerts if a['severity'] == 'LOW'),
            "open":     sum(1 for a in self.alerts if a['status'] == 'OPEN'),
        }