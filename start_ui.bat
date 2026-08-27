@echo off
title HackerAI - Agent Web UI
cd /d "%~dp0"

set "PY=C:\Users\GLOBAL IT STORE\AppData\Local\Python\bin\python.exe"
if not exist "%PY%" set "PY=python"

"%PY%" --version >nul 2>nul
if errorlevel 1 (
  echo [!] Python nahi mila. Install karo: https://www.python.org/downloads/
  pause
  exit /b 1
)

echo ============================================================
echo   HACKERAI - AGENT WEB UI  (mock mode default)
echo   URL  : http://127.0.0.1:5000
echo   Stop : is window mein koi key dabao
echo ============================================================
echo.

start /b "" "%PY%" webui.py --port 5000
timeout /t 3 /nobreak >nul
start "" "http://127.0.0.1:5000"

:loop
timeout /t 2 /nobreak >nul
tasklist /fi "IMAGENAME eq python.exe" 2>nul | find /i "python.exe" >nul
if not errorlevel 1 goto loop

echo.
echo [*] Server band ho gaya. Alvida!
timeout /t 2 /nobreak >nul
