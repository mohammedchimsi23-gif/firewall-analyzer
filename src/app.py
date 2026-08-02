import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, jsonify, request
from database import db, Alert, save_violations_to_db
from log_parser import LogParser
from analyzer import PolicyAnalyzer
from alert_engine import AlertEngine
import json

# Get the project root directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__,
            template_folder=os.path.join(BASE_DIR, 'templates'),
            static_folder=os.path.join(BASE_DIR, 'static'))

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///firewall_analyzer.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'firewall-secret-2024'

db.init_app(app)
parser   = LogParser()
analyzer = PolicyAnalyzer(policy_file=os.path.join(BASE_DIR, "configs", "security_policies.json"))
engine   = AlertEngine()


@app.route('/')
def dashboard():
    stats = {
        'total_alerts': Alert.query.count(),
        'critical':     Alert.query.filter_by(severity='CRITICAL').count(),
        'high':         Alert.query.filter_by(severity='HIGH').count(),
        'medium':       Alert.query.filter_by(severity='MEDIUM').count(),
        'low':          Alert.query.filter_by(severity='LOW').count(),
        'open_alerts':  Alert.query.filter_by(status='OPEN').count(),
        'resolved':     Alert.query.filter_by(status='RESOLVED').count(),
    }
    recent_alerts = Alert.query.order_by(Alert.id.desc()).limit(10).all()
    violation_types = db.session.query(
        Alert.violation_type,
        db.func.count(Alert.id).label('count')
    ).group_by(Alert.violation_type).all()
    chart_data = {
        'labels': [vt[0] for vt in violation_types],
        'values': [vt[1] for vt in violation_types]
    }
    return render_template('index.html',
                           stats=stats,
                           recent_alerts=recent_alerts,
                           chart_data=json.dumps(chart_data))


@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        fw_log = request.form.get('firewall_log', os.path.join(BASE_DIR, 'logs', 'sample_firewall.log'))
        rt_log = request.form.get('router_log',   os.path.join(BASE_DIR, 'logs', 'sample_router.log'))
        fw_df  = parser.parse_firewall_log(fw_log)
        rt_df  = parser.parse_router_log(rt_log)
        all_violations = []
        if fw_df is not None:
            all_violations.extend(analyzer.analyze_firewall_logs(fw_df))
        if rt_df is not None:
            all_violations.extend(analyzer.analyze_router_logs(rt_df))
        Alert.query.delete()
        db.session.commit()
        save_violations_to_db(all_violations)
        return jsonify({
            'success': True,
            'total':   len(all_violations),
            'message': f'Analysis complete! Found {len(all_violations)} violations!'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/alerts')
def alerts_page():
    severity = request.args.get('severity', 'ALL')
    status   = request.args.get('status',   'ALL')
    query    = Alert.query
    if severity != 'ALL':
        query = query.filter_by(severity=severity)
    if status != 'ALL':
        query = query.filter_by(status=status)
    all_alerts = query.order_by(Alert.id.desc()).all()
    return render_template('alerts.html',
                           alerts=all_alerts,
                           severity_filter=severity,
                           status_filter=status)


@app.route('/alerts/<int:alert_id>/resolve', methods=['POST'])
def resolve_alert(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    alert.status = 'RESOLVED'
    db.session.commit()
    return jsonify({'success': True})


@app.route('/reports')
def reports():
    by_type = db.session.query(
        Alert.violation_type,
        db.func.count(Alert.id).label('count')
    ).group_by(Alert.violation_type).all()
    by_severity = db.session.query(
        Alert.severity,
        db.func.count(Alert.id).label('count')
    ).group_by(Alert.severity).all()
    top_ips = db.session.query(
        Alert.src_ip,
        db.func.count(Alert.id).label('count')
    ).group_by(Alert.src_ip).order_by(
        db.func.count(Alert.id).desc()
    ).limit(10).all()
    return render_template('reports.html',
                           by_type=by_type,
                           by_severity=by_severity,
                           top_ips=top_ips)


@app.route('/api/stats')
def api_stats():
    return jsonify({
        'total':    Alert.query.count(),
        'critical': Alert.query.filter_by(severity='CRITICAL').count(),
        'high':     Alert.query.filter_by(severity='HIGH').count(),
        'medium':   Alert.query.filter_by(severity='MEDIUM').count(),
        'low':      Alert.query.filter_by(severity='LOW').count(),
        'open':     Alert.query.filter_by(status='OPEN').count(),
        'resolved': Alert.query.filter_by(status='RESOLVED').count(),
    })


@app.route('/api/alerts')
def api_alerts():
    return jsonify([a.to_dict() for a in Alert.query.all()])


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("✅ Database tables created")
    print("🚀 Starting server → http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)