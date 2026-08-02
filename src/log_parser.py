import pandas as pd


class LogParser:
    def __init__(self):
        self.firewall_df = None
        self.router_df = None

    def parse_firewall_log(self, filepath):
        try:
            df = pd.read_csv(filepath)
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df['bytes'] = pd.to_numeric(df['bytes'], errors='coerce').fillna(0)
            df['dst_port'] = pd.to_numeric(df['dst_port'], errors='coerce').fillna(0)
            self.firewall_df = df
            print(f"✅ Parsed {len(df)} firewall log entries")
            return df
        except FileNotFoundError:
            print(f"❌ File not found: {filepath}")
            print("   Run generate_logs.py first!")
            return None
        except Exception as e:
            print(f"❌ Error parsing firewall log: {e}")
            return None

    def parse_router_log(self, filepath):
        try:
            df = pd.read_csv(filepath)
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            self.router_df = df
            print(f"✅ Parsed {len(df)} router log entries")
            return df
        except FileNotFoundError:
            print(f"❌ File not found: {filepath}")
            print("   Run generate_logs.py first!")
            return None
        except Exception as e:
            print(f"❌ Error parsing router log: {e}")
            return None

    def get_firewall_summary(self, df):
        if df is None or df.empty:
            return {}
        return {
            "total_entries":  len(df),
            "allowed":        len(df[df['action'] == 'ALLOW']),
            "denied":         len(df[df['action'] == 'DENY']),
            "dropped":        len(df[df['action'] == 'DROP']),
            "unique_src_ips": df['src_ip'].nunique(),
            "unique_dst_ips": df['dst_ip'].nunique(),
            "total_bytes":    int(df['bytes'].sum()),
            "date_start":     str(df['timestamp'].min()),
            "date_end":       str(df['timestamp'].max())
        }