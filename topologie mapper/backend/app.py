from flask import Flask, jsonify, request, Response
from flask_socketio import SocketIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_session import Session
from sqlalchemy.exc import SQLAlchemyError
import nmap
import networkx as nx
import threading
from mac_vendor_lookup import MacLookup, VendorNotFoundError
import re
import os
import logging
from dotenv import load_dotenv
from models import db, Device
import redis
from datetime import datetime
from collections import defaultdict
from typing import List, Dict, Generator
from redis.lock import Lock as RedisLock

# Load environment variables
load_dotenv()

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Initialize Flask application
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv('SECRET_KEY'),
    SQLALCHEMY_DATABASE_URI=os.getenv('DATABASE_URI'),
    SQLALCHEMY_ENGINE_OPTIONS={
        'pool_size': 20,
        'max_overflow': 10,
        'pool_pre_ping': True,
        'pool_recycle': 300
    },
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_TYPE='redis',
    SESSION_REDIS=redis.Redis(
        host='redis',
        port=6379,
        password=os.getenv('REDIS_PASSWORD'),
        db=0
    )
)

# Initialize extensions
db.init_app(app)
Session(app)
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    manage_session=False,
    async_mode='eventlet',
    logger=logger.level == logging.DEBUG,
    engineio_logger=logger.level == logging.DEBUG
)

# Configure rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["500 per day", "100 per hour"],
    storage_uri=f"redis://:{os.getenv('REDIS_PASSWORD')}@redis:6379/1",
    strategy="moving-window"
)

# Redis connections
redis_conn = redis.Redis(
    host='redis',
    port=6379,
    password=os.getenv('REDIS_PASSWORD'),
    db=2,
    decode_responses=True
)

# Lock configuration
REDIS_LOCK_NAME = "scan_lock"
LOCK_TIMEOUT = 3600  # 1 hour

# Global variables
mac_lookup = MacLookup()
CACHE_TTL = 3600  # 1 hour

def validate_ip_range(ip_range: str) -> bool:
    """Validate CIDR notation with enhanced regex"""
    cidr_pattern = re.compile(
        r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(3[0-2]|[12]?[0-9])$'
    )
    return bool(cidr_pattern.match(ip_range))

def get_mac_vendor(mac: str) -> str:
    """Get vendor with Redis caching and error handling"""
    if not mac or mac == 'Unknown':
        return 'Unknown'
    
    cached = redis_conn.get(f"mac_vendor:{mac}")
    if cached:
        return cached
    
    try:
        vendor = mac_lookup.lookup(mac)
        redis_conn.setex(f"mac_vendor:{mac}", CACHE_TTL, vendor)
        return vendor
    except (VendorNotFoundError, ValueError):
        return 'Unknown'
    except Exception as e:
        logger.error(f"MAC lookup failed: {str(e)}", exc_info=True)
        return 'Unknown'

def detect_device_type(ports: List[Dict]) -> str:
    """Enhanced device type detection based on open ports"""
    common_ports = {p['port'] for p in ports}
    
    if 22 in common_ports or 3389 in common_ports:
        return 'server'
    if 80 in common_ports or 443 in common_ports:
        return 'router'
    if 445 in common_ports or 548 in common_ports:
        return 'nas'
    return 'workstation'

def generate_topology(devices: List[Dict]) -> nx.Graph:
    """Generate network topology with intelligent edge detection"""
    G = nx.Graph()
    router_ips = [d['ip'] for d in devices if d['type'] == 'router']
    
    for device in devices:
        G.add_node(device['ip'], **device)
        if device['type'] != 'router' and router_ips:
            G.add_edge(device['ip'], router_ips[0], type='wired')
    
    return G

def background_scan(ip_range: str):
    """Thread-safe network scanning with resource cleanup"""
    lock = RedisLock(redis_conn, REDIS_LOCK_NAME, timeout=LOCK_TIMEOUT)
    try:
        if not lock.acquire(blocking=False):
            logger.warning("Scan already in progress from another worker")
            return

        scanner = nmap.PortScanner()
        scanner.scan(ip_range, arguments='-sn -O -T4 --max-retries 1 --host-timeout 15s')
        
        with app.app_context():
            with db.session.begin():
                existing_devices = {d.ip: d for d in Device.query.all()}
                current_ips = set()
                new_devices = []
                updated_devices = []
                port_stats = defaultdict(int)

                for ip in scanner.all_hosts():
                    host = scanner[ip]
                    if host.state()['state'] != 'up':
                        continue

                    mac = host.get('addresses', {}).get('mac', 'Unknown')
                    ports = [
                        {'port': p, 'state': s['state']}
                        for p, s in host.get('tcp', {}).items()
                    ]
                    
                    for port in ports:
                        port_stats[port['port']] += 1

                    device_data = {
                        'ip': ip,
                        'mac': mac,
                        'hostname': host.hostname() or 'Unknown',
                        'vendor': get_mac_vendor(mac),
                        'device_type': detect_device_type(ports),
                        'os': host.get('osmatch', [{}])[0].get('name', 'Unknown'),
                        'ports': ports,
                        'last_seen': datetime.utcnow()
                    }

                    if ip in existing_devices:
                        device = existing_devices[ip]
                        update_needed = False
                        if device.mac != mac:
                            device.mac = mac
                            update_needed = True
                        if device.ports != ports:
                            device.ports = ports
                            update_needed = True
                        if update_needed:
                            device.last_seen = datetime.utcnow()
                            updated_devices.append(device_data)
                    else:
                        device = Device(**device_data)
                        db.session.add(device)
                        new_devices.append(device_data)
                    
                    current_ips.add(ip)

                # Remove stale devices
                Device.query.filter(Device.ip.notin_(current_ips)).delete()

                # Generate network topology
                devices = [d.to_dict() for d in Device.query.all()]
                G = generate_topology(devices)
                nodes = [{'id': n, **d} for n, d in G.nodes(data=True)]
                edges = [{'from': u, 'to': v, 'type': d.get('type', 'wired')} 
                        for u, v, d in G.edges(data=True)]
                
                # Real-time updates
                socketio.emit('topology_update', {
                    'nodes': nodes,
                    'edges': edges,
                    'stats': {
                        'total': len(devices),
                        'new': len(new_devices),
                        'updated': len(updated_devices),
                        'ports': dict(port_stats),
                        'online': len([d for d in devices if d['status'] == 'up'])
                    }
                }, namespace='/scan')
                
                # New device notifications
                for device in new_devices:
                    socketio.emit('new_device', {
                        'ip': device['ip'],
                        'type': device['device_type'],
                        'timestamp': datetime.utcnow().isoformat()
                    }, namespace='/alerts')
                
                logger.info(f"Scan completed: {len(devices)} devices, "
                           f"{len(new_devices)} new, {len(updated_devices)} updated")

    except nmap.PortScannerError as e:
        logger.error(f"Nmap scan failed: {str(e)}")
    except Exception as e:
        logger.error(f"Scanning error: {str(e)}", exc_info=True)
    finally:
        try:
            lock.release()
        except redis.exceptions.LockNotOwnedError:
            logger.warning("Lock release failed - possible timeout")

@app.route('/health')
def health_check():
    """Enhanced health check endpoint"""
    status = {'status': 'ok', 'services': {}, 'timestamp': datetime.utcnow().isoformat()}
    status_code = 200

    try:
        db.session.execute('SELECT 1')
        status['services']['database'] = 'connected'
    except Exception as e:
        status['services']['database'] = f'error: {str(e)}'
        status['status'] = 'degraded'
        status_code = 500

    try:
        redis_conn.ping()
        status['services']['redis'] = 'connected'
    except Exception as e:
        status['services']['redis'] = f'error: {str(e)}'
        status['status'] = 'degraded'
        status_code = 500

    try:
        nmap.PortScanner()
        status['services']['nmap'] = 'available'
    except Exception as e:
        status['services']['nmap'] = f'error: {str(e)}'
        status['status'] = 'degraded'
        status_code = 500

    return jsonify(status), status_code

@app.route('/scan', methods=['POST'])
@limiter.limit("5 per minute", exempt_when=lambda: app.testing)
def scan():
    """Initiate network scan endpoint"""
    try:
        if RedisLock(redis_conn, REDIS_LOCK_NAME).locked():
            return jsonify(error='Scan in progress'), 429
    except redis.exceptions.RedisError as e:
        logger.error(f"Lock check failed: {str(e)}")
        return jsonify(error='Internal server error'), 500

    ip_range = request.json.get('range', '192.168.1.0/24')
    if not validate_ip_range(ip_range):
        return jsonify(error='Invalid IP range format'), 400

    try:
        scanner_thread = threading.Thread(
            target=background_scan,
            args=(ip_range,),
            daemon=True
        )
        scanner_thread.start()
        return jsonify(
            status='scan_started',
            range=ip_range,
            start_time=datetime.utcnow().isoformat()
        )
    except Exception as e:
        logger.error(f"Scan initiation failed: {str(e)}", exc_info=True)
        return jsonify(error='Internal server error'), 500

@app.route('/export')
@limiter.limit("10 per hour")
def export_data():
    """Streaming device data export endpoint"""
    format = request.args.get('format', 'csv')
    
    if format != 'csv':
        return jsonify(error="Unsupported format"), 400

    def generate() -> Generator:
        yield "IP Address,MAC Address,Hostname,Type,OS,Vendor,First Seen,Last Seen,Ports\n"
        for device in Device.query.order_by(Device.last_seen.desc()).yield_per(100):
            ports = ','.join(str(p['port']) for p in device.ports) if device.ports else ''
            yield (f'"{device.ip}","{device.mac}","{device.hostname}",'
                  f'"{device.device_type}","{device.os}","{device.vendor}",'
                  f'"{device.first_seen.isoformat() if device.first_seen else ""}",'
                  f'"{device.last_seen.isoformat() if device.last_seen else ""}",'
                  f'"{ports}"\n')

    return Response(
        generate(),
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=network_export.csv"}
    )

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(
        app,
        host='0.0.0.0',
        port=5000,
        use_reloader=False,
        log_output=True
    )