@echo off
setlocal enabledelayedexpansion

:: ICS Cybersecurity System - Windows Server Setup Script
:: This script handles deployment and management of the ICS system

set "INSTALL_DIR=C:\ICS-Cybersecurity"
set "SERVICE_NAME=ICSCybersecurity"
set "PYTHON_PATH=python"

echo ========================================
echo ICS Cybersecurity System - Windows Setup
echo ========================================

if "%1"=="" (
    echo Usage: %0 [install^|start^|stop^|status^|uninstall^|test]
    echo.
    echo Commands:
    echo   install   - Install the system
    echo   start     - Start the service
    echo   stop      - Stop the service
    echo   status    - Check service status
    echo   uninstall - Remove the system
    echo   test      - Run system tests
    echo.
    goto :end
)

if "%1"=="install" goto :install
if "%1"=="start" goto :start
if "%1"=="stop" goto :stop
if "%1"=="status" goto :status
if "%1"=="uninstall" goto :uninstall
if "%1"=="test" goto :test

echo Unknown command: %1
goto :end

:install
echo.
echo Installing ICS Cybersecurity System...
echo ========================================

:: Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This script must be run as Administrator
    echo Right-click and select "Run as administrator"
    pause
    goto :end
)

:: Check Python installation
echo Checking Python installation...
%PYTHON_PATH% --version >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ and try again
    pause
    goto :end
)

:: Create installation directory
echo Creating installation directory...
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

:: Copy files
echo Copying system files...
xcopy /E /I /Y "src" "%INSTALL_DIR%\src"
xcopy /E /I /Y "config" "%INSTALL_DIR%\config"
xcopy /E /I /Y "scripts" "%INSTALL_DIR%\scripts"
xcopy /E /I /Y "tests" "%INSTALL_DIR%\tests"
xcopy /E /I /Y "docs" "%INSTALL_DIR%\docs"
copy "main.py" "%INSTALL_DIR%\"
copy "requirements.txt" "%INSTALL_DIR%\"
copy "README.md" "%INSTALL_DIR%\"
copy "test_system.py" "%INSTALL_DIR%\"

:: Create virtual environment
echo Creating virtual environment...
cd /d "%INSTALL_DIR%"
%PYTHON_PATH% -m venv venv

:: Install dependencies
echo Installing dependencies...
call venv\Scripts\activate.bat
pip install -r requirements.txt
pip install pywin32

:: Initialize system
echo Initializing system...
python scripts\init_database.py

:: Configure firewall
echo Configuring firewall...
netsh advfirewall firewall add rule name="ICS Cybersecurity API" dir=in action=allow protocol=TCP localport=8000
netsh advfirewall firewall add rule name="ICS Cybersecurity Dashboard" dir=in action=allow protocol=TCP localport=8050
netsh advfirewall firewall add rule name="ICS Network Monitoring" dir=in action=allow protocol=TCP localport=any

:: Create service wrapper
echo Creating service wrapper...
(
echo import sys
echo import os
echo import time
echo import signal
echo import asyncio
echo from pathlib import Path
echo.
echo sys.path.insert(0, r"%INSTALL_DIR%")
echo.
echo from main import ICSCybersecuritySystem
echo.
echo class WindowsService:
echo     def __init__(self^):
echo         self.system = None
echo         self.running = False
echo         
echo     def start(self^):
echo         try:
echo             self.system = ICSCybersecuritySystem(^)
echo             asyncio.run(self.system.initialize_components(^)^)
echo             asyncio.run(self.system.start_services(^)^)
echo             self.running = True
echo             print("ICS Cybersecurity System started successfully"^)
echo             
echo             while self.running:
echo                 time.sleep(1^)
echo                 
echo         except Exception as e:
echo             print(f"Service error: {e}"^)
echo             self.stop(^)
echo     
echo     def stop(self^):
echo         self.running = False
echo         if self.system:
echo             try:
echo                 asyncio.run(self.system.stop_services(^)^)
echo                 print("ICS Cybersecurity System stopped successfully"^)
echo             except Exception as e:
echo                 print(f"Error stopping service: {e}"^)
echo.
echo if __name__ == "__main__":
echo     service = WindowsService(^)
echo     
echo     def signal_handler(signum, frame^):
echo         service.stop(^)
echo     
echo     signal.signal(signal.SIGINT, signal_handler^)
echo     signal.signal(signal.SIGTERM, signal_handler^)
echo     
echo     service.start(^)
) > "%INSTALL_DIR%\service_wrapper.py"

:: Create Windows service
echo Creating Windows service...
sc create "%SERVICE_NAME%" binPath= "%INSTALL_DIR%\venv\Scripts\python.exe %INSTALL_DIR%\service_wrapper.py" DisplayName= "ICS Cybersecurity System" start= auto
sc description "%SERVICE_NAME%" "Industrial Control System Cybersecurity Platform"

:: Create management scripts
echo Creating management scripts...

:: Start script
(
echo @echo off
echo echo Starting ICS Cybersecurity System...
echo sc start "%SERVICE_NAME%"
echo if %%ERRORLEVEL%% EQU 0 ^(
echo     echo Service started successfully
echo     echo API available at: http://localhost:8000
echo     echo Dashboard available at: http://localhost:8050
echo ^) else ^(
echo     echo Failed to start service
echo ^)
echo pause
) > "%INSTALL_DIR%\start_service.bat"

:: Stop script
(
echo @echo off
echo echo Stopping ICS Cybersecurity System...
echo sc stop "%SERVICE_NAME%"
echo if %%ERRORLEVEL%% EQU 0 ^(
echo     echo Service stopped successfully
echo ^) else ^(
echo     echo Failed to stop service
echo ^)
echo pause
) > "%INSTALL_DIR%\stop_service.bat"

:: Status script
(
echo @echo off
echo echo Checking ICS Cybersecurity System status...
echo sc query "%SERVICE_NAME%"
echo echo.
echo echo Testing API connectivity...
echo powershell -Command "try { Invoke-WebRequest -Uri 'http://localhost:8000/health' -TimeoutSec 5 ^| Select-Object StatusCode } catch { Write-Host 'API not responding' }"
echo echo.
echo echo Testing Dashboard connectivity...
echo powershell -Command "try { Invoke-WebRequest -Uri 'http://localhost:8050' -TimeoutSec 5 ^| Select-Object StatusCode } catch { Write-Host 'Dashboard not responding' }"
echo pause
) > "%INSTALL_DIR%\service_status.bat"

:: Uninstall script
(
echo @echo off
echo echo Uninstalling ICS Cybersecurity System...
echo echo Stopping service...
echo sc stop "%SERVICE_NAME%"
echo echo Removing service...
echo sc delete "%SERVICE_NAME%"
echo echo Removing firewall rules...
echo netsh advfirewall firewall delete rule name="ICS Cybersecurity API"
echo netsh advfirewall firewall delete rule name="ICS Cybersecurity Dashboard"
echo netsh advfirewall firewall delete rule name="ICS Network Monitoring"
echo echo Uninstall complete.
echo pause
) > "%INSTALL_DIR%\uninstall.bat"

:: Create desktop shortcuts
echo Creating desktop shortcuts...
powershell -Command "$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%USERPROFILE%\Desktop\ICS API.lnk'); $Shortcut.TargetPath = 'http://localhost:8000'; $Shortcut.Save()"
powershell -Command "$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%USERPROFILE%\Desktop\ICS Dashboard.lnk'); $Shortcut.TargetPath = 'http://localhost:8050'; $Shortcut.Save()"

echo.
echo ========================================
echo Installation Complete!
echo ========================================
echo Installation Directory: %INSTALL_DIR%
echo Service Name: %SERVICE_NAME%
echo API: http://localhost:8000
echo Dashboard: http://localhost:8050
echo.
echo To start the service, run: %0 start
echo To check status, run: %0 status
echo.
goto :end

:start
echo.
echo Starting ICS Cybersecurity System...
sc start "%SERVICE_NAME%"
if %ERRORLEVEL% EQU 0 (
    echo Service started successfully
    echo API available at: http://localhost:8000
    echo Dashboard available at: http://localhost:8050
    echo.
    echo Waiting for services to initialize...
    timeout /t 10 /nobreak >nul
    echo.
    echo Testing connectivity...
    powershell -Command "try { $response = Invoke-WebRequest -Uri 'http://localhost:8000/health' -TimeoutSec 5; Write-Host 'API Status:' $response.StatusCode } catch { Write-Host 'API not responding yet' }"
    powershell -Command "try { $response = Invoke-WebRequest -Uri 'http://localhost:8050' -TimeoutSec 5; Write-Host 'Dashboard Status:' $response.StatusCode } catch { Write-Host 'Dashboard not responding yet' }"
) else (
    echo Failed to start service
    echo Check Windows Event Viewer for errors
)
goto :end

:stop
echo.
echo Stopping ICS Cybersecurity System...
sc stop "%SERVICE_NAME%"
if %ERRORLEVEL% EQU 0 (
    echo Service stopped successfully
) else (
    echo Failed to stop service
)
goto :end

:status
echo.
echo ========================================
echo ICS Cybersecurity System Status
echo ========================================
echo.
echo Service Status:
sc query "%SERVICE_NAME%"
echo.
echo API Connectivity:
powershell -Command "try { $response = Invoke-WebRequest -Uri 'http://localhost:8000/health' -TimeoutSec 5; Write-Host 'API: OK (Status: ' $response.StatusCode ')' } catch { Write-Host 'API: Not responding' }"
echo.
echo Dashboard Connectivity:
powershell -Command "try { $response = Invoke-WebRequest -Uri 'http://localhost:8050' -TimeoutSec 5; Write-Host 'Dashboard: OK (Status: ' $response.StatusCode ')' } catch { Write-Host 'Dashboard: Not responding' }"
echo.
echo Firewall Rules:
netsh advfirewall firewall show rule name="ICS Cybersecurity API" | findstr "Enabled"
netsh advfirewall firewall show rule name="ICS Cybersecurity Dashboard" | findstr "Enabled"
echo.
goto :end

:uninstall
echo.
echo Uninstalling ICS Cybersecurity System...
echo.
echo Stopping service...
sc stop "%SERVICE_NAME%"
echo.
echo Removing service...
sc delete "%SERVICE_NAME%"
echo.
echo Removing firewall rules...
netsh advfirewall firewall delete rule name="ICS Cybersecurity API"
netsh advfirewall firewall delete rule name="ICS Cybersecurity Dashboard"
netsh advfirewall firewall delete rule name="ICS Network Monitoring"
echo.
echo Removing installation directory...
if exist "%INSTALL_DIR%" (
    rmdir /S /Q "%INSTALL_DIR%"
    echo Installation directory removed
)
echo.
echo Removing desktop shortcuts...
if exist "%USERPROFILE%\Desktop\ICS API.lnk" del "%USERPROFILE%\Desktop\ICS API.lnk"
if exist "%USERPROFILE%\Desktop\ICS Dashboard.lnk" del "%USERPROFILE%\Desktop\ICS Dashboard.lnk"
echo.
echo Uninstall complete!
goto :end

:test
echo.
echo Running ICS Cybersecurity System tests...
echo ========================================
if exist "%INSTALL_DIR%\test_system.py" (
    cd /d "%INSTALL_DIR%"
    call venv\Scripts\activate.bat
    python test_system.py
) else (
    echo Test script not found. Please install the system first.
)
goto :end

:end
echo.
pause 