@echo off
title CyberWatch Pipeline - Stopping
color 0C

echo.
echo ╔══════════════════════════════════════════════════════════════╗
echo ║              Stopping CyberWatch Pipeline...                 ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.

docker-compose down

echo.
echo [OK] All services stopped!
echo.
pause
