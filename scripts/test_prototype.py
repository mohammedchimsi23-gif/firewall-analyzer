import sys
import os

# Fix paths so we can import from src/ folder
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, 'src'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from generate_logs import generate_firewall_logs, generate_router_logs
from log_parser import LogParser
from analyzer import PolicyAnalyzer
from alert_engine import AlertEngine

print("=" * 55)
print("🔬  FIREWALL ANALYZER - PROTOTYPE TEST")
print("=" * 55)

print("\n📝 STEP 1: Generating logs...")
fw_log_path = os.path.join(BASE_DIR, "logs", "sample_firewall.log")
rt_log_path = os.path.join(BASE_DIR, "logs", "sample_router.log")
generate_firewall_logs(filename=fw_log_path, count=500)
generate_router_logs(filename=rt_log_path, count=200)

print("\n📂 STEP 2: Parsing log files...")
parser  = LogParser()
fw_df   = parser.parse_firewall_log(fw_log_path)
rt_df   = parser.parse_router_log(rt_log_path)
summary = parser.get_firewall_summary(fw_df)

print(f"\n  📊 Firewall Summary:")
print(f"     Total   : {summary.get('total_entries', 0)}")
print(f"     Allowed : {summary.get('allowed', 0)}")
print(f"     Denied  : {summary.get('denied', 0)}")
print(f"     Dropped : {summary.get('dropped', 0)}")

print("\n🔍 STEP 3: Running policy analysis...")
policy_path = os.path.join(BASE_DIR, "configs", "security_policies.json")
analyzer  = PolicyAnalyzer(policy_file=policy_path)
fw_viols  = analyzer.analyze_firewall_logs(fw_df)
rt_viols  = analyzer.analyze_router_logs(rt_df)
all_viols = fw_viols + rt_viols

print("\n🚨 STEP 4: Generating alerts...")
engine = AlertEngine()
alerts = engine.generate_alerts(all_viols)
engine.print_alerts(limit=10)

stats = engine.get_stats()
print("\n" + "=" * 55)
print("📊  FINAL RESULTS")
print("=" * 55)
print(f"  Total Alerts : {stats['total']}")
print(f"  🔴 Critical  : {stats['critical']}")
print(f"  🟡 High      : {stats['high']}")
print(f"  🔵 Medium    : {stats['medium']}")
print(f"  🟢 Low       : {stats['low']}")
print(f"  📂 Open      : {stats['open']}")
print("\n✅ Test complete! Now run: python src/app.py")