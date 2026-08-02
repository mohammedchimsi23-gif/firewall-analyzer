from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class Alert(db.Model):
    __tablename__ = 'alerts'

    id             = db.Column(db.Integer, primary_key=True)
    alert_id       = db.Column(db.String(20))
    timestamp      = db.Column(db.DateTime, default=datetime.utcnow)
    violation_type = db.Column(db.String(100))
    severity       = db.Column(db.String(20))
    src_ip         = db.Column(db.String(50))
    dst_ip         = db.Column(db.String(100))
    dst_port       = db.Column(db.String(20))
    protocol       = db.Column(db.String(20))
    description    = db.Column(db.Text)
    recommendation = db.Column(db.Text)
    status         = db.Column(db.String(20), default='OPEN')

    def to_dict(self):
        return {
            "id":             self.id,
            "alert_id":       self.alert_id,
            "timestamp":      str(self.timestamp),
            "violation_type": self.violation_type,
            "severity":       self.severity,
            "src_ip":         self.src_ip,
            "dst_ip":         self.dst_ip,
            "dst_port":       self.dst_port,
            "protocol":       self.protocol,
            "description":    self.description,
            "recommendation": self.recommendation,
            "status":         self.status
        }


def save_violations_to_db(violations):
    for i, v in enumerate(violations):
        alert = Alert(
            alert_id       = f"ALERT-{i+1:04d}",
            violation_type = v.get("violation_type"),
            severity       = v.get("severity"),
            src_ip         = v.get("src_ip"),
            dst_ip         = str(v.get("dst_ip")),
            dst_port       = str(v.get("dst_port")),
            protocol       = v.get("protocol"),
            description    = v.get("description"),
            recommendation = v.get("recommendation"),
            status         = "OPEN"
        )
        db.session.add(alert)
    db.session.commit()
    print(f"✅ Saved {len(violations)} alerts to database")