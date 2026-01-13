@echo off
title CyberWatch Pipeline Launcher
color 0A

echo.
echo ╔══════════════════════════════════════════════════════════════╗
echo ║                                                              ║
echo ║       ██████╗██╗   ██╗██████╗ ███████╗██████╗               ║
echo ║      ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗              ║
echo ║      ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝              ║
echo ║      ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗              ║
echo ║      ╚██████╗   ██║   ██████╔╝███████╗██║  ██║              ║
echo ║       ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝              ║
echo ║                    W A T C H                                 ║
echo ║                                                              ║
echo ║           Alert Ingestion Pipeline v1.0                      ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.

:: Check if Docker is running
echo [*] Checking Docker status...
docker info > nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Docker is not running. Starting Docker Desktop...
    start "" "C:\Program Files\Docker\Docker\Docker Desktop.exe"
    echo [*] Waiting for Docker to start (60 seconds)...
    timeout /t 60 /nobreak > nul
    
    :: Check again
    docker info > nul 2>&1
    if %errorlevel% neq 0 (
        echo [X] Failed to start Docker. Please start Docker Desktop manually.
        pause
        exit /b 1
    )
)
echo [OK] Docker is running!
echo.

:: Check if .env exists
if not exist ".env" (
    echo [*] Creating .env file from .env.example...
    copy .env.example .env > nul
    echo [OK] .env file created!
)
echo.

:: Start the services
echo [*] Starting CyberWatch services...
echo.
docker-compose up -d --build

if %errorlevel% neq 0 (
    echo.
    echo [X] Failed to start services. Check the error above.
    pause
    exit /b 1
)

echo.
echo [*] Running database migrations...
timeout /t 10 /nobreak > nul
docker-compose exec -T sensor-service python manage.py migrate --no-input > nul 2>&1

echo.
echo [*] Creating default alert sources...
docker-compose exec -T sensor-service python manage.py shell -c "from alerts.models import AlertSource; AlertSource.objects.get_or_create(source_id='qradar', defaults={'name': 'IBM QRadar', 'source_type': 'SIEM', 'webhook_enabled': True, 'is_active': True}); AlertSource.objects.get_or_create(source_id='crowdstrike', defaults={'name': 'CrowdStrike Falcon', 'source_type': 'EDR', 'webhook_enabled': True, 'is_active': True}); AlertSource.objects.get_or_create(source_id='defender', defaults={'name': 'Microsoft Defender', 'source_type': 'EDR', 'webhook_enabled': True, 'is_active': True}); AlertSource.objects.get_or_create(source_id='splunk', defaults={'name': 'Splunk', 'source_type': 'SIEM', 'webhook_enabled': True, 'is_active': True})" > nul 2>&1

echo.
echo ╔══════════════════════════════════════════════════════════════╗
echo ║                   STARTUP COMPLETE!                          ║
echo ╠══════════════════════════════════════════════════════════════╣
echo ║                                                              ║
echo ║   Services Running:                                          ║
echo ║   ─────────────────                                          ║
echo ║   [*] Kafka UI        : http://localhost:8080                ║
echo ║   [*] Sensor API      : http://localhost:8000/api/           ║
echo ║   [*] Kafka           : localhost:9092                       ║
echo ║   [*] Redis           : localhost:6379                       ║
echo ║                                                              ║
echo ║   Webhook Endpoints:                                         ║
echo ║   ──────────────────                                         ║
echo ║   POST /api/webhook/qradar/                                  ║
echo ║   POST /api/webhook/crowdstrike/                             ║
echo ║   POST /api/webhook/defender/                                ║
echo ║   POST /api/webhook/splunk/                                  ║
echo ║                                                              ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.

:: Open Kafka UI in browser
echo [*] Opening Kafka UI in browser...
start http://localhost:8080

echo.
echo Press any key to view logs (Ctrl+C to exit)...
pause > nul

docker-compose logs -f
