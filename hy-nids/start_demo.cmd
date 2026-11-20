@echo off
cd /d "%~dp0"
docker compose up -d --build --wait
if errorlevel 1 (
  echo Start Docker Desktop, check port 15007, then retry.
  pause
  exit /b 1
)
start "" "http://127.0.0.1:15007/"
