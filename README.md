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

## 🔧 أمثلة الاستخدام

### إرسال تنبيه من PowerShell
```powershell
$body = @{
    alert_id = "test-001"
    severity = "high"
    title = "Test Alert"
    description = "This is a test alert"
    source_ip = "192.168.1.100"
    timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8000/api/webhook/qradar/" -Method POST -Body $body -ContentType "application/json"
```

### إرسال تنبيه من cURL
```bash
curl -X POST http://localhost:8000/api/webhook/qradar/ \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "test-001",
    "severity": "high",
    "title": "Test Alert",
    "description": "This is a test alert",
    "source_ip": "192.168.1.100"
  }'
```

### إرسال تنبيه من Python
```python
import requests

alert = {
    "alert_id": "test-001",
    "severity": "high",
    "title": "Test Alert",
    "description": "This is a test alert",
    "source_ip": "192.168.1.100"
}

response = requests.post(
    "http://localhost:8000/api/webhook/qradar/",
    json=alert
)
print(response.json())
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
