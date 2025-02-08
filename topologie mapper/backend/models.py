from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Device(db.Model):
    __tablename__ = 'network_devices'
    
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50), unique=True, nullable=False)
    mac = db.Column(db.String(50), index=True)
    hostname = db.Column(db.String(150))
    vendor = db.Column(db.String(150))
    device_type = db.Column(db.String(50))
    os = db.Column(db.String(200))
    ports = db.Column(db.JSON)
    first_seen = db.Column(db.DateTime, server_default=db.func.now())
    last_seen = db.Column(db.DateTime, server_default=db.func.now(), 
                         onupdate=db.func.now())

    __table_args__ = (
        db.Index('ix_ip_mac', 'ip', 'mac'),
        db.Index('ix_device_type', 'device_type'),
        db.Index('ix_last_seen', 'last_seen'),
        db.Index('ix_combined', 'device_type', 'last_seen'),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "device_type": self.device_type,
            "os": self.os,
            "ports": self.ports,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None
        }

    def __repr__(self):
        return f"<Device {self.ip} ({self.device_type})>"