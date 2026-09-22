@echo off
rem HackerAI Agent Hub - silent autostart launcher (Windows logon task)
rem flashfix: use pythonw + /b so NO console/cmd window appears.
title HackerAI Agent Hub
cd /d "E:\HackerAI\my-agent"
set "PY=C:\Users\GLOBAL IT STORE\AppData\Local\Python\bin\python.exe"
set "PYW=C:\Users\GLOBAL IT STORE\AppData\Local\Python\bin\pythonw.exe"
if not exist "%PY%" set "PY=python"
if not exist "%PYW%" set "PYW=pythonw"
"%PY%" --version >nul 2>nul
if errorlevel 1 (
  echo [!] Python not found > _hub_error.txt
  exit /b 1
)
start "" /b "%PYW%" webui.py --port 5000 >> _hub.log 2>&1
exit /b 0
