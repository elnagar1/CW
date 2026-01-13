"""
Mock Security Sources API Server.
Simulates QRadar, CrowdStrike, Defender, Splunk APIs for testing Pull mode.
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import random
import time
from datetime import datetime, timedelta
import string
import os

app = Flask(__name__)
CORS(app)

# ============================================
# Helper Functions
# ============================================

def random_ip():
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

def random_host():
    return f"HOST-{random_string(6).upper()}"

def random_string(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def random_hash(length=64):
    return ''.join(random.choices('0123456789abcdef', k=length))

def random_user():
    return random.choice(['admin', 'user', 'service', 'root', 'system', 'guest', 'operator'])

THREAT_NAMES = [
    'Ransomware Attack', 'Brute Force', 'SQL Injection', 'XSS Attack',
    'Malware Detected', 'Phishing Attempt', 'DDoS Attack', 'Credential Theft',
    'Lateral Movement', 'Data Exfiltration', 'Privilege Escalation', 'Botnet Activity',
    'Cryptominer', 'Trojan Detected', 'Worm Spreading', 'Zero-Day Exploit',
    'Command and Control', 'Port Scanning', 'DNS Tunneling', 'Memory Injection'
]

TACTICS = [
    'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
    'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
    'Collection', 'Command and Control', 'Exfiltration', 'Impact'
]

# ============================================
# Configuration - Number of alerts to generate
# ============================================
ALERTS_PER_REQUEST = int(os.environ.get('ALERTS_PER_REQUEST', 5))


# ============================================
# IBM QRadar Mock API
# ============================================

@app.route('/api/siem/offenses', methods=['GET'])
def qradar_offenses():
    """Mock QRadar Offenses API."""
    count = min(int(request.args.get('limit', ALERTS_PER_REQUEST)), 50)
    
    offenses = []
    for i in range(count):
        offense = {
            'id': random.randint(10000, 99999),
            'description': random.choice(THREAT_NAMES),
            'severity': random.randint(1, 10),
            'offense_type': random.randint(1, 5),
            'status': random.choice(['OPEN', 'HIDDEN', 'CLOSED']),
            'start_time': int((datetime.now() - timedelta(minutes=random.randint(1, 60))).timestamp() * 1000),
            'last_updated_time': int(datetime.now().timestamp() * 1000),
            'offense_source': random_ip(),
            'source_network': random.choice(['Internal', 'External', 'DMZ']),
            'destination_networks': ['Internal'],
            'categories': [random.choice(['Firewall Deny', 'Suspicious Activity', 'Malware', 'Reconnaissance'])],
            'magnitude': random.randint(1, 10),
            'relevance': random.randint(1, 10),
            'credibility': random.randint(1, 10),
            'event_count': random.randint(10, 1000),
            'flow_count': random.randint(0, 100),
            'assigned_to': random.choice([None, 'analyst1', 'analyst2']),
            'local_destination_count': random.randint(1, 10),
            'remote_destination_count': random.randint(0, 5),
        }
        offenses.append(offense)
    
    return jsonify(offenses)


@app.route('/api/siem/offenses/<int:offense_id>', methods=['GET'])
def qradar_offense_detail(offense_id):
    """Mock QRadar Offense detail."""
    return jsonify({
        'id': offense_id,
        'description': random.choice(THREAT_NAMES),
        'severity': random.randint(1, 10),
        'status': 'OPEN',
        'source_address_ids': [random.randint(1, 1000) for _ in range(3)],
        'local_destination_address_ids': [random.randint(1, 1000) for _ in range(2)],
    })


# ============================================
# CrowdStrike Falcon Mock API
# ============================================

@app.route('/detects/queries/detects/v1', methods=['GET'])
def crowdstrike_detect_ids():
    """Mock CrowdStrike Detection IDs."""
    count = min(int(request.args.get('limit', ALERTS_PER_REQUEST)), 50)
    
    detection_ids = [f"ldt:{random_string(16)}:{random.randint(100000, 999999)}" for _ in range(count)]
    
    return jsonify({
        'resources': detection_ids,
        'meta': {
            'query_time': 0.05,
            'pagination': {'total': len(detection_ids)}
        }
    })


@app.route('/detects/entities/summaries/GET/v2', methods=['POST'])
def crowdstrike_detect_details():
    """Mock CrowdStrike Detection Details."""
    data = request.get_json() or {}
    ids = data.get('ids', [])
    
    detections = []
    for det_id in ids[:50]:
        detection = {
            'detection_id': det_id,
            'created_timestamp': (datetime.now() - timedelta(minutes=random.randint(1, 60))).isoformat() + 'Z',
            'max_severity': random.randint(50, 100),
            'max_severity_displayname': random.choice(['Low', 'Medium', 'High', 'Critical']),
            'status': random.choice(['new', 'in_progress', 'true_positive', 'false_positive']),
            'device': {
                'device_id': random_string(32),
                'hostname': random_host(),
                'external_ip': random_ip(),
                'local_ip': f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
                'os_version': random.choice(['Windows 10', 'Windows 11', 'macOS 14', 'Ubuntu 22.04']),
                'platform_name': random.choice(['Windows', 'Mac', 'Linux']),
                'machine_domain': 'corp.local'
            },
            'behaviors': [{
                'behavior_id': f"ind:{random_string(16)}:{random.randint(1000, 9999)}-{random.randint(1, 5)}",
                'scenario': random.choice(['suspicious_activity', 'malware', 'ransomware', 'credential_access']),
                'severity': random.randint(50, 100),
                'tactic': random.choice(TACTICS),
                'technique': random.choice(THREAT_NAMES),
                'user_name': random_user(),
                'filename': random.choice(['powershell.exe', 'cmd.exe', 'rundll32.exe', 'regsvr32.exe', 'wscript.exe']),
                'cmdline': f"powershell.exe -enc {random_string(32)}",
                'sha256': random_hash(64),
                'ioc_type': 'hash_sha256',
                'ioc_value': random_hash(64)
            }]
        }
        detections.append(detection)
    
    return jsonify({
        'resources': detections,
        'meta': {'query_time': 0.1}
    })


# ============================================
# Microsoft Defender Mock API
# ============================================

@app.route('/api/alerts', methods=['GET'])
def defender_alerts():
    """Mock Microsoft Defender Alerts API."""
    count = min(int(request.args.get('$top', ALERTS_PER_REQUEST)), 50)
    
    alerts = []
    for _ in range(count):
        alert = {
            'id': f"da{random.randint(100000, 999999)}",
            'incidentId': random.randint(10000, 99999),
            'alertCreationTime': (datetime.now() - timedelta(minutes=random.randint(1, 60))).isoformat() + 'Z',
            'severity': random.choice(['Low', 'Medium', 'High', 'Critical']),
            'title': random.choice(THREAT_NAMES),
            'description': f"Detected {random.choice(THREAT_NAMES).lower()} activity on endpoint",
            'category': random.choice(['Malware', 'SuspiciousActivity', 'UnwantedSoftware', 'Ransomware']),
            'status': random.choice(['New', 'InProgress', 'Resolved']),
            'assignedTo': random.choice([None, 'analyst@company.com']),
            'investigationState': random.choice(['Queued', 'Running', 'Successful']),
            'detectionSource': random.choice(['WindowsDefenderAtp', 'WindowsDefenderAv', 'CloudAppSecurity']),
            'threatFamilyName': random.choice(['Emotet', 'TrickBot', 'Cobalt Strike', 'Mimikatz']),
            'machineId': random_string(40),
            'computerDnsName': f"{random_host()}.corp.local",
            'aadTenantId': random_string(36),
            'evidence': [
                {
                    '@odata.type': '#microsoft.graph.security.ipEvidence',
                    'ipAddress': random_ip()
                },
                {
                    '@odata.type': '#microsoft.graph.security.userEvidence',
                    'userAccount': {'accountName': random_user(), 'domainName': 'CORP'}
                },
                {
                    '@odata.type': '#microsoft.graph.security.fileEvidence',
                    'fileName': random.choice(['malware.exe', 'payload.dll', 'dropper.bat']),
                    'sha256': random_hash(64)
                }
            ]
        }
        alerts.append(alert)
    
    return jsonify({'value': alerts})


# ============================================
# Splunk Mock API
# ============================================

@app.route('/services/search/jobs', methods=['POST'])
def splunk_create_search():
    """Mock Splunk Create Search Job."""
    return jsonify({
        'sid': f"splunk_search_{random_string(16)}"
    })


@app.route('/services/search/jobs/<sid>/results', methods=['GET'])
def splunk_search_results(sid):
    """Mock Splunk Search Results."""
    count = min(int(request.args.get('count', ALERTS_PER_REQUEST)), 50)
    
    results = []
    for _ in range(count):
        result = {
            'event_id': f"sp_{random_string(12)}",
            '_time': (datetime.now() - timedelta(minutes=random.randint(1, 60))).isoformat(),
            'urgency': random.choice(['low', 'medium', 'high', 'critical']),
            'rule_name': random.choice(THREAT_NAMES),
            'rule_description': f"Detected {random.choice(THREAT_NAMES).lower()} activity",
            'src': random_ip(),
            'dest': f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
            'src_user': random_user(),
            'host': random_host(),
            'count': random.randint(1, 100),
            'action': random.choice(['allowed', 'blocked', 'detected']),
            'signature': random_hash(32),
            'risk_score': random.randint(1, 100)
        }
        results.append(result)
    
    return jsonify({
        'results': results,
        'init_offset': 0,
        'messages': []
    })


@app.route('/services/notable', methods=['GET'])
def splunk_notable_events():
    """Mock Splunk Notable Events."""
    count = min(int(request.args.get('count', ALERTS_PER_REQUEST)), 50)
    
    results = []
    for _ in range(count):
        result = {
            'event_id': f"notable_{random_string(12)}",
            '_time': (datetime.now() - timedelta(minutes=random.randint(1, 60))).isoformat(),
            'urgency': random.choice(['low', 'medium', 'high', 'critical']),
            'rule_name': random.choice(THREAT_NAMES),
            'rule_description': f"Security alert: {random.choice(THREAT_NAMES)}",
            'src': random_ip(),
            'dest': f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
            'user': random_user(),
            'host': random_host(),
            'status': random.choice(['new', 'in_progress', 'resolved']),
            'owner': random.choice(['unassigned', 'analyst1', 'analyst2']),
            'security_domain': random.choice(['access', 'endpoint', 'network', 'threat']),
        }
        results.append(result)
    
    return jsonify({'results': results})


# ============================================
# Palo Alto Mock API
# ============================================

@app.route('/api/v1/alerts', methods=['GET'])
def paloalto_alerts():
    """Mock Palo Alto Cortex XDR Alerts."""
    count = min(int(request.args.get('limit', ALERTS_PER_REQUEST)), 50)
    
    alerts = []
    for _ in range(count):
        alert = {
            'alert_id': f"PA-{random.randint(100000, 999999)}",
            'detection_timestamp': int((datetime.now() - timedelta(minutes=random.randint(1, 60))).timestamp() * 1000),
            'severity': random.choice(['low', 'medium', 'high', 'critical']),
            'name': random.choice(THREAT_NAMES),
            'description': f"Palo Alto detected {random.choice(THREAT_NAMES).lower()}",
            'source_ip': random_ip(),
            'destination_ip': random_ip(),
            'source_port': random.randint(1024, 65535),
            'destination_port': random.choice([80, 443, 22, 3389, 445]),
            'protocol': random.choice(['TCP', 'UDP']),
            'action': random.choice(['allow', 'block', 'reset']),
            'category': random.choice(['vulnerability', 'malware', 'spyware', 'data-exfiltration']),
            'host_name': random_host(),
            'user': random_user(),
        }
        alerts.append(alert)
    
    return jsonify({'reply': {'alerts': alerts}})


# ============================================
# SentinelOne Mock API
# ============================================

@app.route('/web/api/v2.1/threats', methods=['GET'])
def sentinelone_threats():
    """Mock SentinelOne Threats API."""
    count = min(int(request.args.get('limit', ALERTS_PER_REQUEST)), 50)
    
    threats = []
    for _ in range(count):
        threat = {
            'id': random_string(18),
            'createdAt': (datetime.now() - timedelta(minutes=random.randint(1, 60))).isoformat() + 'Z',
            'threatInfo': {
                'threatName': random.choice(['Emotet', 'TrickBot', 'Ryuk', 'REvil', 'Cobalt Strike']),
                'classification': random.choice(['Malware', 'Trojan', 'Ransomware', 'PUP']),
                'confidenceLevel': random.choice(['low', 'medium', 'high']),
                'analystVerdict': random.choice(['undefined', 'true_positive', 'false_positive', 'suspicious']),
                'mitigationStatus': random.choice(['not_mitigated', 'mitigated', 'partially_mitigated']),
                'sha256': random_hash(64),
                'filePath': f"C:\\Users\\{random_user()}\\Downloads\\{random_string(8)}.exe"
            },
            'agentRealtimeInfo': {
                'agentComputerName': random_host(),
                'agentOsName': random.choice(['Windows 10 Pro', 'Windows 11 Enterprise', 'macOS Monterey']),
                'agentIp': f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
                'agentUuid': random_string(36),
                'siteName': random.choice(['HQ', 'Branch1', 'DataCenter'])
            },
            'indicators': [
                {'category': 'Process', 'description': 'Suspicious process execution'},
                {'category': 'Network', 'description': 'C2 communication detected'},
                {'category': 'File', 'description': 'Known malicious file'}
            ]
        }
        threats.append(threat)
    
    return jsonify({'data': threats, 'pagination': {'totalItems': len(threats)}})


# ============================================
# Configuration Endpoints
# ============================================

@app.route('/config/alerts-per-request', methods=['GET', 'POST'])
def config_alerts():
    """Get/Set number of alerts per request."""
    global ALERTS_PER_REQUEST
    
    if request.method == 'POST':
        data = request.get_json() or {}
        ALERTS_PER_REQUEST = min(max(int(data.get('count', 5)), 1), 100)
        return jsonify({'alerts_per_request': ALERTS_PER_REQUEST, 'status': 'updated'})
    
    return jsonify({'alerts_per_request': ALERTS_PER_REQUEST})


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'service': 'mock-sources',
        'timestamp': datetime.now().isoformat(),
        'alerts_per_request': ALERTS_PER_REQUEST,
        'available_sources': [
            'QRadar (/api/siem/offenses)',
            'CrowdStrike (/detects/queries/detects/v1)',
            'Defender (/api/alerts)',
            'Splunk (/services/notable)',
            'Palo Alto (/api/v1/alerts)',
            'SentinelOne (/web/api/v2.1/threats)'
        ]
    })


@app.route('/', methods=['GET'])
def index():
    """API Documentation."""
    return jsonify({
        'name': 'CyberWatch Mock Sources API',
        'version': '1.0.0',
        'description': 'Simulates security tool APIs for Pull mode testing',
        'endpoints': {
            'qradar': {
                'GET /api/siem/offenses': 'List offenses',
                'GET /api/siem/offenses/<id>': 'Offense detail'
            },
            'crowdstrike': {
                'GET /detects/queries/detects/v1': 'Get detection IDs',
                'POST /detects/entities/summaries/GET/v2': 'Get detection details'
            },
            'defender': {
                'GET /api/alerts': 'List alerts'
            },
            'splunk': {
                'POST /services/search/jobs': 'Create search',
                'GET /services/search/jobs/<sid>/results': 'Get results',
                'GET /services/notable': 'Get notable events'
            },
            'paloalto': {
                'GET /api/v1/alerts': 'List alerts'
            },
            'sentinelone': {
                'GET /web/api/v2.1/threats': 'List threats'
            },
            'config': {
                'GET/POST /config/alerts-per-request': 'Configure alerts count'
            }
        }
    })


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 9000))
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║       🛡️ CyberWatch Mock Sources API Server                  ║
╠══════════════════════════════════════════════════════════════╣
║  Simulating:                                                  ║
║  • IBM QRadar        → /api/siem/offenses                    ║
║  • CrowdStrike       → /detects/queries/detects/v1           ║
║  • Microsoft Defender → /api/alerts                          ║
║  • Splunk            → /services/notable                     ║
║  • Palo Alto         → /api/v1/alerts                        ║
║  • SentinelOne       → /web/api/v2.1/threats                 ║
╠══════════════════════════════════════════════════════════════╣
║  Port: {port}                                                    ║
║  Alerts per request: {ALERTS_PER_REQUEST}                                        ║
╚══════════════════════════════════════════════════════════════╝
""")
    app.run(host='0.0.0.0', port=port, debug=True)
