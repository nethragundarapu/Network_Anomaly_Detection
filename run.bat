@echo off
title Sentinel AI - SOC Defense Platform Launcher
echo ===================================================================
echo     SENTINEL AI: DEFENSIVE NETWORK ANOMALY DETECTION PLATFORM
echo ===================================================================
echo.
echo Activating Python virtual environment...
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
) else (
    echo [INFO] Virtual environment not found at .venv, using system python...
)

echo Starting High-Performance SOC Web Platform...
python run_webapp.py
pause
