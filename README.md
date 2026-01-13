# 🛡️ CyberWatch - Alert Ingestion Pipeline

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.11-green.svg)
![Docker](https://img.shields.io/badge/docker-required-blue.svg)
![Kafka](https://img.shields.io/badge/kafka-7.5.0-orange.svg)

**نظام استقبال وتحليل التنبيهات الأمنية من مصادر متعددة**

</div>

---

## 📋 نظرة عامة

CyberWatch هو نظام **Decoupled Pipeline** لاستقبال التنبيهات الأمنية من مصادر مختلفة مثل:
- 🔵 **IBM QRadar** (SIEM)
- 🟠 **CrowdStrike Falcon** (EDR)
- 🔷 **Microsoft Defender** (EDR)
- 🟢 **Splunk** (SIEM)

### البنية المعمارية

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Alert Sources  │────▶│  Sensor Service │────▶│   Kafka Topic   │
│  (SIEM/EDR)     │     │  (Django/Celery)│     │  alerts.raw     │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                        │
                                                        ▼
                                                ┌─────────────────┐
                                                │ Parsing Service │
                                                │ (Consumer Group)│
                                                └────────┬────────┘
                                                         │
                                                         ▼
                                                ┌─────────────────┐
                                                │  alerts.parsed  │
                                                └─────────────────┘
```

### 📦 الصيغ المدعومة

النظام يقبل البيانات بـ **أي صيغة** ويحولها تلقائياً للصيغة المعيارية!

| الصيغة | Content-Type | مثال |
|--------|--------------|------|
| **JSON** | `application/json` | `{"alert_id": "123", "severity": "high"}` |
| **XML** | `application/xml`, `text/xml` | `<alert><id>123</id></alert>` |
| **Syslog RFC 3164** | `text/plain` | `<134>Jan 13 12:00:00 host app: message` |
| **Syslog RFC 5424** | `text/plain` | `<134>1 2026-01-13T12:00:00Z host app - - msg` |
| **CEF** | `text/plain` | `CEF:0|Vendor|Product|1.0|100|Name|7|src=1.2.3.4` |
| **LEEF** | `text/plain` | `LEEF:2.0|Vendor|Product|1.0|src=1.2.3.4` |
| **Key-Value** | `text/plain` | `src=1.2.3.4 dst=5.6.7.8 action=block` |
| **Plain Text** | `text/plain` | أي نص عادي |

---

## 🚀 التشغيل السريع

### المتطلبات
- ✅ **Docker Desktop** (Windows/Mac)
- ✅ **Git** (اختياري)

### التشغيل

```batch
# تشغيل المشروع
start.bat

# إيقاف المشروع
stop.bat
```

أو يدوياً:
```powershell
# تشغيل
docker-compose up -d --build

# إيقاف
docker-compose down
```

---

## 🌐 الخدمات والمنافذ

| الخدمة | المنفذ | الوصف |
|--------|--------|-------|
| **Kafka UI** | [localhost:8080](http://localhost:8080) | واجهة مراقبة Kafka |
| **Sensor API** | [localhost:8000](http://localhost:8000/api/) | REST API للتنبيهات |
| **Kafka** | localhost:9092 | Message Broker |
| **Redis** | localhost:6379 | Celery Broker |

---

## 📡 API Endpoints

### Health Check
```http
GET /api/health/
```
**Response:**
```json
{
    "status": "healthy",
    "service": "sensor",
    "timestamp": "2026-01-13T12:00:00Z"
}
```

### قائمة المصادر
```http
GET /api/sources/
```
**Response:**
```json
[
    {
        "name": "IBM QRadar",
        "source_id": "qradar",
        "source_type": "SIEM",
        "polling_enabled": true,
        "webhook_enabled": true
    }
]
```

### إحصائيات الاستقبال
```http
GET /api/stats/
```
**Response:**
```json
{
    "period": "last_24_hours",
    "alerts_received": 150,
    "alerts_sent_to_kafka": 150,
    "total_ingestions": 25
}
```

### Webhook - استقبال التنبيهات
```http
POST /api/webhook/{source_id}/
Content-Type: application/json

{
    "alert_id": "12345",
    "severity": "high",
    "title": "Suspicious Activity Detected",
    "description": "Multiple failed login attempts",
    "source_ip": "192.168.1.100",
    "timestamp": "2026-01-13T12:00:00Z"
}
```
**Response:**
```json
{
    "status": "accepted"
}
```

---

## 🧠 Universal Smart Parser

النظام يحتوي على **Universal Smart Parser** قادر على معالجة **أي نوع من البيانات** تلقائياً!

### كيف يعمل؟

```
البيانات الواردة (أي صيغة)  ──▶  Pattern Detection  ──▶  Field Mapping  ──▶  JSON معياري
```

| الميزة | الوصف |
|--------|-------|
| � **Pattern Detection** | يكتشف الحقول تلقائياً مثل severity, timestamp, IP |
| 🔗 **Field Mapping** | يربط الحقول غير المعروفة بالحقول المعيارية |
| 🎯 **IOC Extraction** | يستخرج IPs و Hashes تلقائياً |
| 📦 **Nested Flattening** | يفكك البيانات المتداخلة |
| ➕ **Extra Fields** | يحفظ الحقول الإضافية في `extra_fields` |

### الحقول التي يتعرف عليها تلقائياً

| الحقل المعياري | الأسماء المقبولة |
|----------------|------------------|
| `id` | alert_id, event_id, incident_id, offense_id, uuid, guid |
| `timestamp` | timestamp, time, date, created_at, event_time, @timestamp |
| `severity` | severity, priority, urgency, risk_level, threat_level |
| `title` | title, name, subject, summary, rule_name, alert_name |
| `description` | description, details, message, body, notes |
| `source_ip` | source_ip, src_ip, src, attacker_ip, remote_ip, origin_ip |
| `destination_ip` | destination_ip, dest_ip, dst, target_ip, victim_ip |
| `user` | user, username, account, src_user, actor |
| `hostname` | hostname, host, computer_name, device_name, endpoint |

### 🔄 كيف يتم التعامل مع الصيغ المختلفة؟

```
┌─────────────────────────────────────────────────────────────────────┐
│                     البيانات الواردة                                 │
│         (JSON, XML, Syslog, CEF, LEEF, Text, etc.)                  │
└────────────────────────────────┬────────────────────────────────────┘
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  1️⃣ FormatDetector                                                  │
│  يكتشف نوع الصيغة تلقائياً:                                          │
│  • JSON: يبدأ بـ { أو [                                              │
│  • XML: يبدأ بـ <                                                    │
│  • CEF: يبدأ بـ CEF:                                                 │
│  • LEEF: يبدأ بـ LEEF:                                               │
│  • Syslog: يبدأ بـ <priority>                                        │
│  • Key-Value: يحتوي على key=value                                   │
└────────────────────────────────┬────────────────────────────────────┘
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  2️⃣ Format Parser                                                   │
│  يحول البيانات إلى Dictionary                                       │
└────────────────────────────────┬────────────────────────────────────┘
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  3️⃣ UniversalParser                                                 │
│  يطابق الحقول ويحول للصيغة المعيارية                                 │
└────────────────────────────────┬────────────────────────────────────┘
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      JSON المعياري                                   │
│  { "id": "...", "severity": "...", "source_ip": "...", ... }        │
└─────────────────────────────────────────────────────────────────────┘
```

### مثال على التحويل من Syslog:

**الإدخال:**
```
<134>Jan 13 12:00:00 server01 sshd[1234]: Failed password for admin from 203.0.113.50
```

**الإخراج:**
```json
{
    "id": "alert_abc123",
    "severity": "medium",
    "hostname": "server01",
    "description": "Failed password for admin from 203.0.113.50",
    "source_ip": "203.0.113.50",
    "detected_format": "syslog",
    "extra_fields": {
        "priority": 134,
        "facility": 16,
        "application": "sshd",
        "pid": "1234"
    }
}
```

---

## 🧪 اختبار النظام

### المصادر المتاحة للاختبار

| Source ID | النوع | الوصف |
|-----------|-------|-------|
| `qradar` | SIEM | IBM QRadar |
| `crowdstrike` | EDR | CrowdStrike Falcon |
| `defender` | EDR | Microsoft Defender |
| `splunk` | SIEM | Splunk |
| `custom_siem` | SIEM | أي مصدر مخصص |

---

## 📝 أمثلة الاختبار (PowerShell)

### 1️⃣ تنبيه بسيط
```powershell
$alert = @{
    alert_id = "test-001"
    severity = "high"
    title = "Test Alert"
    description = "This is a test alert"
    source_ip = "192.168.1.100"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8000/api/webhook/qradar/" -Method POST -Body $alert -ContentType "application/json"
```

### 2️⃣ تنبيه بصيغة QRadar
```powershell
$qradarAlert = @{
    id = 12345
    description = "Excessive Firewall Denies"
    severity = 8
    offense_type = 1
    status = "OPEN"
    start_time = 1705147200000
    offense_source = "203.0.113.50"
    categories = @("Firewall", "Denial")
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8000/api/webhook/qradar/" -Method POST -Body $qradarAlert -ContentType "application/json"
```

### 3️⃣ تنبيه بصيغة CrowdStrike
```powershell
$crowdstrikeAlert = @{
    detection_id = "ldt:abc123"
    created_timestamp = "2026-01-13T12:00:00Z"
    max_severity = 85
    status = "new"
    device = @{
        hostname = "WORKSTATION-01"
        local_ip = "192.168.1.50"
        external_ip = "203.0.113.100"
    }
    behaviors = @(
        @{
            scenario = "Malicious PowerShell Execution"
            tactic = "Execution"
            user_name = "john.doe"
            sha256 = "abc123def456789..."
        }
    )
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Uri "http://localhost:8000/api/webhook/crowdstrike/" -Method POST -Body $crowdstrikeAlert -ContentType "application/json"
```

### 4️⃣ تنبيه بصيغة غير معروفة (Universal Parser)
```powershell
$unknownFormat = @{
    evt_uuid = "xyz-789-abc"
    risk_score = 9.5
    attack_type = "Ransomware Detected"
    event_details = "Encryption activity detected on multiple files"
    attacker_ip = "45.33.32.156"
    victim_host = "FILE-SERVER-01"
    affected_user = "admin@company.com"
    file_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    detected_at = "2026-01-13T13:00:00Z"
    custom_field_1 = "any value"
    custom_field_2 = 12345
    nested_data = @{
        process = @{
            name = "malware.exe"
            pid = 4567
            cmdline = "malware.exe --encrypt C:\"
        }
    }
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Uri "http://localhost:8000/api/webhook/custom_siem/" -Method POST -Body $unknownFormat -ContentType "application/json"
```

### 5️⃣ تنبيه Splunk
```powershell
$splunkAlert = @{
    event_id = "sp-001"
    _time = "2026-01-13T12:00:00Z"
    urgency = "critical"
    rule_name = "Brute Force Attack Detected"
    rule_description = "Multiple failed login attempts from single IP"
    src = "10.0.0.50"
    dest = "192.168.1.100"
    src_user = "attacker"
    host = "auth-server-01"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8000/api/webhook/splunk/" -Method POST -Body $splunkAlert -ContentType "application/json"
```

### 6️⃣ تنبيه Microsoft Defender
```powershell
$defenderAlert = @{
    id = "da-123456"
    createdDateTime = "2026-01-13T12:00:00Z"
    severity = "high"
    title = "Suspicious Process Execution"
    description = "A suspicious process was detected running on the endpoint"
    category = "Malware"
    status = "new"
    evidence = @(
        @{
            "@odata.type" = "#microsoft.graph.security.ipEvidence"
            ipAddress = "192.168.1.100"
        }
        @{
            "@odata.type" = "#microsoft.graph.security.userEvidence"
            userAccount = @{ accountName = "john.doe" }
        }
        @{
            "@odata.type" = "#microsoft.graph.security.deviceEvidence"
            deviceDnsName = "WORKSTATION-PC"
        }
    )
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Uri "http://localhost:8000/api/webhook/defender/" -Method POST -Body $defenderAlert -ContentType "application/json"
```

---

## � اختبار الصيغ المختلفة (Non-JSON)

### 7️⃣ تنبيه Syslog
```powershell
$syslogData = '<134>Jan 13 12:00:00 server01 sshd[1234]: Failed password for admin from 203.0.113.50 port 22 ssh2'

Invoke-RestMethod -Uri "http://localhost:8000/api/webhook/custom_siem/" -Method POST -Body $syslogData -ContentType "text/plain"
```

### 8️⃣ تنبيه CEF (Common Event Format)
```powershell
$cefData = 'CEF:0|Security|Firewall|1.0|100|Connection Blocked|7|src=192.168.1.100 dst=10.0.0.1 spt=49152 dpt=443 act=blocked msg=Suspicious outbound connection'

Invoke-RestMethod -Uri "http://localhost:8000/api/webhook/custom_siem/" -Method POST -Body $cefData -ContentType "text/plain"
```

### 9️⃣ تنبيه XML
```powershell
$xmlData = @'
<?xml version="1.0"?>
<alert>
    <id>xml-001</id>
    <severity>high</severity>
    <title>Malware Detected</title>
    <description>Trojan detected on endpoint</description>
    <source_ip>192.168.1.100</source_ip>
    <hostname>workstation-01</hostname>
    <user>john.doe</user>
    <timestamp>2026-01-13T12:00:00Z</timestamp>
    <indicators>
        <indicator type="md5">d41d8cd98f00b204e9800998ecf8427e</indicator>
        <indicator type="ip">45.33.32.156</indicator>
    </indicators>
</alert>
'@

Invoke-RestMethod -Uri "http://localhost:8000/api/webhook/custom_siem/" -Method POST -Body $xmlData -ContentType "application/xml"
```

### 🔟 تنبيه Key-Value
```powershell
$kvData = 'timestamp=2026-01-13T12:00:00Z severity=high src_ip=192.168.1.100 dst_ip=10.0.0.1 action=blocked user=admin host=firewall-01 msg="Connection blocked by policy"'

Invoke-RestMethod -Uri "http://localhost:8000/api/webhook/custom_siem/" -Method POST -Body $kvData -ContentType "text/plain"
```

### 1️⃣1️⃣ تنبيه LEEF
```powershell
$leefData = 'LEEF:2.0|IBM|QRadar|7.3|100|	devTime=2026-01-13T12:00:00Z	severity=8	src=192.168.1.100	dst=10.0.0.1	userName=admin	action=blocked'

Invoke-RestMethod -Uri "http://localhost:8000/api/webhook/custom_siem/" -Method POST -Body $leefData -ContentType "text/plain"
```

## �🔍 التحقق من النتائج

### 1. عبر Kafka UI
افتح http://localhost:8080 وانتقل إلى:
- **Topics** → **alerts.raw** → للرسائل الخام
- **Topics** → **alerts.parsed** → للرسائل المحللة

### 2. عبر PowerShell
```powershell
# التحقق من Health
Invoke-RestMethod -Uri "http://localhost:8000/api/health/"

# عرض الإحصائيات
Invoke-RestMethod -Uri "http://localhost:8000/api/stats/"

# عرض المصادر
Invoke-RestMethod -Uri "http://localhost:8000/api/sources/"
```

### 3. عبر Docker Logs
```powershell
# سجلات Sensor Service
docker-compose logs -f sensor-service

# سجلات Parsing Service
docker-compose logs -f parsing-service
```

---

## 📊 مثال على التحويل

### الإدخال (صيغة غير معروفة):
```json
{
    "evt_uuid": "xyz-789",
    "risk_score": 9.5,
    "attack_type": "Ransomware",
    "attacker_ip": "45.33.32.156",
    "victim_host": "SERVER-01"
}
```

### الإخراج (صيغة معيارية):
```json
{
    "id": "alert_abc123def456",
    "source_id": "custom_siem",
    "source_type": "SIEM",
    "timestamp": "2026-01-13T13:00:00Z",
    "severity": "critical",
    "title": "Ransomware",
    "source_ip": "45.33.32.156",
    "hostname": "SERVER-01",
    "indicators": [
        {"type": "ip", "value": "45.33.32.156"}
    ],
    "extra_fields": {
        "evt_uuid": "xyz-789",
        "risk_score": 9.5
    },
    "metadata": {
        "parser_type": "universal",
        "parser_version": "2.0.0",
        "parse_success": true
    }
}
```

---

## 📁 هيكل المشروع

```
CyberWatch/
├── 📄 docker-compose.yml      # تكوين Docker
├── 📄 start.bat               # سكريبت التشغيل
├── 📄 stop.bat                # سكريبت الإيقاف
├── 📄 .env.example            # متغيرات البيئة
├── 📄 README.md               # هذا الملف
│
├── 📁 sensor-service/         # خدمة استقبال التنبيهات
│   ├── 📄 Dockerfile
│   ├── 📄 requirements.txt
│   ├── 📄 manage.py
│   ├── 📁 sensor/
│   │   ├── settings.py        # إعدادات Django
│   │   ├── celery.py          # إعدادات Celery
│   │   └── urls.py
│   └── 📁 alerts/
│       ├── models.py          # نماذج البيانات
│       ├── views.py           # API Views
│       ├── tasks.py           # Celery Tasks
│       ├── kafka_producer.py  # Kafka Producer
│       └── 📁 source_connectors/
│           ├── base.py        # Base Connector
│           ├── qradar.py      # QRadar Connector
│           ├── crowdstrike.py # CrowdStrike Connector
│           ├── defender.py    # Defender Connector
│           └── splunk.py      # Splunk Connector
│
└── 📁 parsing-service/        # خدمة تحليل التنبيهات
    ├── 📄 Dockerfile
    ├── 📄 requirements.txt
    ├── 📄 main.py             # Kafka Consumer
    └── 📁 parsers/
        ├── registry.py        # Parser Registry
        ├── base.py            # Base Parser
        ├── qradar_parser.py
        ├── crowdstrike_parser.py
        ├── defender_parser.py
        └── splunk_parser.py
```

---

## 🔄 Kafka Topics

| Topic | الوصف |
|-------|-------|
| `alerts.raw` | التنبيهات الخام كما وردت من المصادر |
| `alerts.parsed` | التنبيهات بعد التحليل والتوحيد |

### صيغة الرسالة في alerts.raw
```json
{
    "envelope": {
        "source_id": "qradar",
        "source_type": "SIEM",
        "ingestion_time": "2026-01-13T12:00:00Z",
        "sensor_version": "1.0.0",
        "metadata": {}
    },
    "raw_data": {
        // البيانات الخام كما وردت
    }
}
```

### صيغة الرسالة في alerts.parsed
```json
{
    "id": "qradar_12345",
    "source_id": "qradar",
    "source_type": "SIEM",
    "timestamp": "2026-01-13T12:00:00Z",
    "severity": "high",
    "title": "Alert Title",
    "description": "Alert Description",
    "category": "intrusion",
    "status": "new",
    "source_ip": "192.168.1.100",
    "destination_ip": "10.0.0.1",
    "user": "admin",
    "hostname": "server01",
    "indicators": [
        {"type": "ip", "value": "192.168.1.100"}
    ],
    "metadata": {
        "ingestion_time": "...",
        "parsed_time": "...",
        "parser_version": "1.0.0"
    }
}
```

---

## ⚙️ التكوين

### متغيرات البيئة (.env)

```env
# Django
DJANGO_SECRET_KEY=your-secret-key
DEBUG=True

# Kafka
KAFKA_BOOTSTRAP_SERVERS=kafka:29092

# Redis
REDIS_URL=redis://redis:6379/0

# QRadar
QRADAR_API_URL=https://your-qradar-server/api
QRADAR_API_KEY=your-api-key

# CrowdStrike
CROWDSTRIKE_API_URL=https://api.crowdstrike.com
CROWDSTRIKE_CLIENT_ID=your-client-id
CROWDSTRIKE_CLIENT_SECRET=your-client-secret

# Microsoft Defender
DEFENDER_TENANT_ID=your-tenant-id
DEFENDER_CLIENT_ID=your-client-id
DEFENDER_CLIENT_SECRET=your-client-secret

# Splunk
SPLUNK_API_URL=https://your-splunk-server:8089
SPLUNK_USERNAME=your-username
SPLUNK_PASSWORD=your-password
```

---

## 🛠️ الأوامر المفيدة

```powershell
# عرض حالة الخدمات
docker-compose ps

# عرض السجلات
docker-compose logs -f

# عرض سجلات خدمة معينة
docker-compose logs -f sensor-service

# إعادة تشغيل خدمة
docker-compose restart sensor-service

# تنفيذ أمر داخل الحاوية
docker-compose exec sensor-service python manage.py shell

# إنشاء مستخدم Admin
docker-compose exec sensor-service python manage.py createsuperuser
```

---

## 📈 قابلية التوسع

تم تصميم النظام ليعمل كـ **Consumer Group** في Kafka، مما يسمح بتشغيل عدة نسخ متوازية:

```yaml
# في docker-compose.yml
parsing-service:
  deploy:
    replicas: 6  # 6 نسخ متوازية
```

---

## 🤝 المساهمة

1. Fork المشروع
2. أنشئ branch للميزة الجديدة
3. أرسل Pull Request

---

## 📄 الترخيص

MIT License - يمكنك استخدام المشروع بحرية.

---

<div align="center">

**صُنع بـ ❤️ لـ CyberWatch**

</div>
