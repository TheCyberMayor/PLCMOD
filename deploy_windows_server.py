#!/usr/bin/env python3
"""
Windows Server Deployment Script for ICS Cybersecurity System
This script handles deployment on Windows Server including:
1. Prerequisites installation
2. System configuration
3. Windows Service setup
4. Firewall configuration
5. Monitoring setup
"""

import os
import sys
import subprocess
import json
import time
import shutil
from pathlib import Path
from typing import Dict, List, Any
import logging
import winreg
import ctypes

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('deployment.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class WindowsServerDeployer:
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.install_dir = Path("C:\\ICS-Cybersecurity")
        self.service_name = "ICSCybersecurity"
        self.service_display_name = "ICS Cybersecurity System"
        self.service_description = "Industrial Control System Cybersecurity Platform"
        self.python_path = None
        self.requirements_file = self.base_dir / "requirements.txt"
        
    def log_step(self, step_name: str, success: bool, message: str = ""):
        """Log deployment step results"""
        status = "✅ SUCCESS" if success else "❌ FAILED"
        logger.info(f"{status} {step_name}: {message}")
        
    def is_admin(self) -> bool:
        """Check if running with administrator privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def check_prerequisites(self) -> bool:
        """Step 1: Check and install prerequisites"""
        logger.info("=" * 60)
        logger.info("STEP 1: Checking Prerequisites")
        logger.info("=" * 60)
        
        try:
            # Check if running as administrator
            if not self.is_admin():
                self.log_step("Administrator Privileges", False, "Script must be run as Administrator")
                logger.error("Please run this script as Administrator (Right-click -> Run as Administrator)")
                return False
            else:
                self.log_step("Administrator Privileges", True, "Running with admin privileges")
            
            # Check Windows version
            try:
                result = subprocess.run(["ver"], capture_output=True, text=True, shell=True)
                if result.returncode == 0:
                    self.log_step("Windows Version", True, f"Windows detected: {result.stdout.strip()}")
                else:
                    self.log_step("Windows Version", False, "Could not determine Windows version")
            except Exception as e:
                self.log_step("Windows Version", False, f"Error: {e}")
            
            # Check Python installation
            python_versions = ["python", "python3", "py"]
            for py_cmd in python_versions:
                try:
                    result = subprocess.run([py_cmd, "--version"], capture_output=True, text=True)
                    if result.returncode == 0:
                        self.python_path = py_cmd
                        version = result.stdout.strip()
                        self.log_step("Python Installation", True, f"Found: {version}")
                        break
                except:
                    continue
            
            if not self.python_path:
                self.log_step("Python Installation", False, "Python not found. Installing...")
                if not self.install_python():
                    return False
            
            # Check pip
            try:
                result = subprocess.run([self.python_path, "-m", "pip", "--version"], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    self.log_step("Pip Installation", True, "Pip is available")
                else:
                    self.log_step("Pip Installation", False, "Pip not working")
                    return False
            except Exception as e:
                self.log_step("Pip Installation", False, f"Error: {e}")
                return False
            
            # Check if Visual C++ Redistributable is needed
            self.check_vcredist()
            
            return True
            
        except Exception as e:
            self.log_step("Prerequisites Check", False, f"Unexpected error: {e}")
            return False
    
    def install_python(self) -> bool:
        """Install Python if not present"""
        try:
            logger.info("Installing Python...")
            
            # Download Python installer
            python_url = "https://www.python.org/ftp/python/3.9.7/python-3.9.7-amd64.exe"
            installer_path = Path("C:\\temp\\python-installer.exe")
            
            # Create temp directory
            installer_path.parent.mkdir(exist_ok=True)
            
            # Download using PowerShell
            download_cmd = f'powershell -Command "Invoke-WebRequest -Uri \'{python_url}\' -OutFile \'{installer_path}\'"'
            result = subprocess.run(download_cmd, shell=True)
            
            if result.returncode != 0:
                self.log_step("Python Download", False, "Failed to download Python installer")
                return False
            
            # Install Python silently
            install_cmd = f'"{installer_path}" /quiet InstallAllUsers=1 PrependPath=1 Include_test=0'
            result = subprocess.run(install_cmd, shell=True)
            
            if result.returncode == 0:
                self.python_path = "python"
                self.log_step("Python Installation", True, "Python installed successfully")
                return True
            else:
                self.log_step("Python Installation", False, "Failed to install Python")
                return False
                
        except Exception as e:
            self.log_step("Python Installation", False, f"Error: {e}")
            return False
    
    def check_vcredist(self):
        """Check and install Visual C++ Redistributable if needed"""
        try:
            # Check if Visual C++ Redistributable is installed
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                   r"SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64")
                winreg.CloseKey(key)
                self.log_step("Visual C++ Redistributable", True, "Already installed")
                return
            except:
                pass
            
            # Download and install Visual C++ Redistributable
            logger.info("Installing Visual C++ Redistributable...")
            vcredist_url = "https://aka.ms/vs/16/release/vc_redist.x64.exe"
            installer_path = Path("C:\\temp\\vcredist-installer.exe")
            
            # Create temp directory
            installer_path.parent.mkdir(exist_ok=True)
            
            # Download
            download_cmd = f'powershell -Command "Invoke-WebRequest -Uri \'{vcredist_url}\' -OutFile \'{installer_path}\'"'
            result = subprocess.run(download_cmd, shell=True)
            
            if result.returncode == 0:
                # Install silently
                install_cmd = f'"{installer_path}" /quiet /norestart'
                result = subprocess.run(install_cmd, shell=True)
                
                if result.returncode == 0:
                    self.log_step("Visual C++ Redistributable", True, "Installed successfully")
                else:
                    self.log_step("Visual C++ Redistributable", False, "Installation failed")
            else:
                self.log_step("Visual C++ Redistributable", False, "Download failed")
                
        except Exception as e:
            self.log_step("Visual C++ Redistributable", False, f"Error: {e}")
    
    def install_system(self) -> bool:
        """Step 2: Install the ICS system"""
        logger.info("=" * 60)
        logger.info("STEP 2: Installing ICS Cybersecurity System")
        logger.info("=" * 60)
        
        try:
            # Create installation directory
            if self.install_dir.exists():
                logger.info(f"Installation directory {self.install_dir} already exists")
            else:
                self.install_dir.mkdir(parents=True, exist_ok=True)
                self.log_step("Create Install Directory", True, f"Created: {self.install_dir}")
            
            # Copy system files
            files_to_copy = [
                "main.py",
                "requirements.txt",
                "README.md",
                "test_system.py"
            ]
            
            for file_name in files_to_copy:
                src_file = self.base_dir / file_name
                dst_file = self.install_dir / file_name
                
                if src_file.exists():
                    shutil.copy2(src_file, dst_file)
                    self.log_step(f"Copy {file_name}", True)
                else:
                    self.log_step(f"Copy {file_name}", False, f"Source file not found: {src_file}")
            
            # Copy directories
            dirs_to_copy = ["src", "config", "scripts", "tests", "docs"]
            for dir_name in dirs_to_copy:
                src_dir = self.base_dir / dir_name
                dst_dir = self.install_dir / dir_name
                
                if src_dir.exists():
                    if dst_dir.exists():
                        shutil.rmtree(dst_dir)
                    shutil.copytree(src_dir, dst_dir)
                    self.log_step(f"Copy Directory {dir_name}", True)
                else:
                    self.log_step(f"Copy Directory {dir_name}", False, f"Source directory not found: {src_dir}")
            
            # Create virtual environment
            venv_path = self.install_dir / "venv"
            if venv_path.exists():
                logger.info("Virtual environment already exists")
            else:
                logger.info("Creating virtual environment...")
                result = subprocess.run([self.python_path, "-m", "venv", str(venv_path)], 
                                      cwd=self.install_dir)
                
                if result.returncode == 0:
                    self.log_step("Virtual Environment", True, f"Created: {venv_path}")
                else:
                    self.log_step("Virtual Environment", False, "Failed to create virtual environment")
                    return False
            
            # Install dependencies
            pip_path = venv_path / "Scripts" / "pip.exe"
            if pip_path.exists():
                logger.info("Installing dependencies...")
                result = subprocess.run([str(pip_path), "install", "-r", "requirements.txt"], 
                                      cwd=self.install_dir)
                
                if result.returncode == 0:
                    self.log_step("Dependencies Installation", True, "All dependencies installed")
                else:
                    self.log_step("Dependencies Installation", False, "Failed to install dependencies")
                    return False
            else:
                self.log_step("Dependencies Installation", False, "Pip not found in virtual environment")
                return False
            
            # Initialize the system
            python_path = venv_path / "Scripts" / "python.exe"
            init_script = self.install_dir / "scripts" / "init_database.py"
            
            if init_script.exists():
                logger.info("Initializing system...")
                result = subprocess.run([str(python_path), str(init_script)], 
                                      cwd=self.install_dir)
                
                if result.returncode == 0:
                    self.log_step("System Initialization", True, "System initialized successfully")
                else:
                    self.log_step("System Initialization", False, "Failed to initialize system")
                    return False
            else:
                self.log_step("System Initialization", False, "Initialization script not found")
                return False
            
            return True
            
        except Exception as e:
            self.log_step("System Installation", False, f"Unexpected error: {e}")
            return False
    
    def configure_firewall(self) -> bool:
        """Step 3: Configure Windows Firewall"""
        logger.info("=" * 60)
        logger.info("STEP 3: Configuring Windows Firewall")
        logger.info("=" * 60)
        
        try:
            # Add firewall rules for API
            api_rule_name = "ICS Cybersecurity API"
            api_cmd = f'netsh advfirewall firewall add rule name="{api_rule_name}" dir=in action=allow protocol=TCP localport=8000'
            result = subprocess.run(api_cmd, shell=True)
            
            if result.returncode == 0:
                self.log_step("API Firewall Rule", True, "Port 8000 opened for API")
            else:
                self.log_step("API Firewall Rule", False, "Failed to add API firewall rule")
            
            # Add firewall rules for Dashboard
            dashboard_rule_name = "ICS Cybersecurity Dashboard"
            dashboard_cmd = f'netsh advfirewall firewall add rule name="{dashboard_rule_name}" dir=in action=allow protocol=TCP localport=8050'
            result = subprocess.run(dashboard_cmd, shell=True)
            
            if result.returncode == 0:
                self.log_step("Dashboard Firewall Rule", True, "Port 8050 opened for Dashboard")
            else:
                self.log_step("Dashboard Firewall Rule", False, "Failed to add Dashboard firewall rule")
            
            # Add firewall rules for network monitoring (if needed)
            network_rule_name = "ICS Network Monitoring"
            network_cmd = f'netsh advfirewall firewall add rule name="{network_rule_name}" dir=in action=allow protocol=TCP localport=any'
            result = subprocess.run(network_cmd, shell=True)
            
            if result.returncode == 0:
                self.log_step("Network Monitoring Firewall Rule", True, "Network monitoring enabled")
            else:
                self.log_step("Network Monitoring Firewall Rule", False, "Failed to add network monitoring rule")
            
            return True
            
        except Exception as e:
            self.log_step("Firewall Configuration", False, f"Error: {e}")
            return False
    
    def create_windows_service(self) -> bool:
        """Step 4: Create Windows Service"""
        logger.info("=" * 60)
        logger.info("STEP 4: Creating Windows Service")
        logger.info("=" * 60)
        
        try:
            # Create service wrapper script
            service_wrapper = self.install_dir / "service_wrapper.py"
            
            wrapper_content = f'''#!/usr/bin/env python3
import sys
import os
import time
import signal
import asyncio
from pathlib import Path

# Add the installation directory to Python path
sys.path.insert(0, r"{self.install_dir}")

from main import ICSCybersecuritySystem

class WindowsService:
    def __init__(self):
        self.system = None
        self.running = False
        
    def start(self):
        """Start the service"""
        try:
            self.system = ICSCybersecuritySystem()
            asyncio.run(self.system.initialize_components())
            asyncio.run(self.system.start_services())
            self.running = True
            print("ICS Cybersecurity System started successfully")
            
            # Keep the service running
            while self.running:
                time.sleep(1)
                
        except Exception as e:
            print(f"Service error: {{e}}")
            self.stop()
    
    def stop(self):
        """Stop the service"""
        self.running = False
        if self.system:
            try:
                asyncio.run(self.system.stop_services())
                print("ICS Cybersecurity System stopped successfully")
            except Exception as e:
                print(f"Error stopping service: {{e}}")

if __name__ == "__main__":
    service = WindowsService()
    
    def signal_handler(signum, frame):
        service.stop()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    service.start()
'''
            
            with open(service_wrapper, 'w') as f:
                f.write(wrapper_content)
            
            self.log_step("Service Wrapper", True, "Created service wrapper script")
            
            # Install pywin32 if not present
            pip_path = self.install_dir / "venv" / "Scripts" / "pip.exe"
            result = subprocess.run([str(pip_path), "install", "pywin32"], 
                                  cwd=self.install_dir)
            
            if result.returncode == 0:
                self.log_step("PyWin32 Installation", True, "PyWin32 installed for service support")
            else:
                self.log_step("PyWin32 Installation", False, "Failed to install PyWin32")
                return False
            
            # Create service using sc command
            python_path = self.install_dir / "venv" / "Scripts" / "python.exe"
            service_cmd = f'sc create "{self.service_name}" binPath= "{python_path} {service_wrapper}" DisplayName= "{self.service_display_name}" start= auto'
            
            result = subprocess.run(service_cmd, shell=True)
            
            if result.returncode == 0:
                self.log_step("Windows Service Creation", True, f"Service '{self.service_name}' created")
                
                # Set service description
                desc_cmd = f'sc description "{self.service_name}" "{self.service_description}"'
                subprocess.run(desc_cmd, shell=True)
                
                return True
            else:
                self.log_step("Windows Service Creation", False, "Failed to create Windows service")
                return False
                
        except Exception as e:
            self.log_step("Windows Service Creation", False, f"Error: {e}")
            return False
    
    def create_startup_scripts(self) -> bool:
        """Step 5: Create startup and management scripts"""
        logger.info("=" * 60)
        logger.info("STEP 5: Creating Management Scripts")
        logger.info("=" * 60)
        
        try:
            # Create start script
            start_script = self.install_dir / "start_service.bat"
            start_content = f'''@echo off
echo Starting ICS Cybersecurity System...
sc start "{self.service_name}"
if %ERRORLEVEL% EQU 0 (
    echo Service started successfully
    echo API available at: http://localhost:8000
    echo Dashboard available at: http://localhost:8050
) else (
    echo Failed to start service
)
pause
'''
            
            with open(start_script, 'w') as f:
                f.write(start_content)
            
            self.log_step("Start Script", True, "Created start_service.bat")
            
            # Create stop script
            stop_script = self.install_dir / "stop_service.bat"
            stop_content = f'''@echo off
echo Stopping ICS Cybersecurity System...
sc stop "{self.service_name}"
if %ERRORLEVEL% EQU 0 (
    echo Service stopped successfully
) else (
    echo Failed to stop service
)
pause
'''
            
            with open(stop_script, 'w') as f:
                f.write(stop_content)
            
            self.log_step("Stop Script", True, "Created stop_service.bat")
            
            # Create status script
            status_script = self.install_dir / "service_status.bat"
            status_content = f'''@echo off
echo Checking ICS Cybersecurity System status...
sc query "{self.service_name}"
echo.
echo Testing API connectivity...
powershell -Command "try {{ Invoke-WebRequest -Uri 'http://localhost:8000/health' -TimeoutSec 5 | Select-Object StatusCode }} catch {{ Write-Host 'API not responding' }}"
echo.
echo Testing Dashboard connectivity...
powershell -Command "try {{ Invoke-WebRequest -Uri 'http://localhost:8050' -TimeoutSec 5 | Select-Object StatusCode }} catch {{ Write-Host 'Dashboard not responding' }}"
pause
'''
            
            with open(status_script, 'w') as f:
                f.write(status_content)
            
            self.log_step("Status Script", True, "Created service_status.bat")
            
            # Create uninstall script
            uninstall_script = self.install_dir / "uninstall.bat"
            uninstall_content = f'''@echo off
echo Uninstalling ICS Cybersecurity System...
echo Stopping service...
sc stop "{self.service_name}"
echo Removing service...
sc delete "{self.service_name}"
echo Removing firewall rules...
netsh advfirewall firewall delete rule name="ICS Cybersecurity API"
netsh advfirewall firewall delete rule name="ICS Cybersecurity Dashboard"
netsh advfirewall firewall delete rule name="ICS Network Monitoring"
echo Uninstall complete.
pause
'''
            
            with open(uninstall_script, 'w') as f:
                f.write(uninstall_content)
            
            self.log_step("Uninstall Script", True, "Created uninstall.bat")
            
            return True
            
        except Exception as e:
            self.log_step("Management Scripts", False, f"Error: {e}")
            return False
    
    def create_desktop_shortcuts(self) -> bool:
        """Step 6: Create desktop shortcuts"""
        logger.info("=" * 60)
        logger.info("STEP 6: Creating Desktop Shortcuts")
        logger.info("=" * 60)
        
        try:
            # Get desktop path
            desktop = Path.home() / "Desktop"
            
            # Create shortcut for API
            api_shortcut = desktop / "ICS API.lnk"
            api_url = "http://localhost:8000"
            
            # Use PowerShell to create shortcut
            api_cmd = f'''powershell -Command "$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('{api_shortcut}'); $Shortcut.TargetPath = '{api_url}'; $Shortcut.Save()"'''
            result = subprocess.run(api_cmd, shell=True)
            
            if result.returncode == 0:
                self.log_step("API Shortcut", True, "Created API desktop shortcut")
            else:
                self.log_step("API Shortcut", False, "Failed to create API shortcut")
            
            # Create shortcut for Dashboard
            dashboard_shortcut = desktop / "ICS Dashboard.lnk"
            dashboard_url = "http://localhost:8050"
            
            dashboard_cmd = f'''powershell -Command "$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('{dashboard_shortcut}'); $Shortcut.TargetPath = '{dashboard_url}'; $Shortcut.Save()"'''
            result = subprocess.run(dashboard_cmd, shell=True)
            
            if result.returncode == 0:
                self.log_step("Dashboard Shortcut", True, "Created Dashboard desktop shortcut")
            else:
                self.log_step("Dashboard Shortcut", False, "Failed to create Dashboard shortcut")
            
            return True
            
        except Exception as e:
            self.log_step("Desktop Shortcuts", False, f"Error: {e}")
            return False
    
    def run_post_installation_tests(self) -> bool:
        """Step 7: Run post-installation tests"""
        logger.info("=" * 60)
        logger.info("STEP 7: Running Post-Installation Tests")
        logger.info("=" * 60)
        
        try:
            # Test the installation
            python_path = self.install_dir / "venv" / "Scripts" / "python.exe"
            test_script = self.install_dir / "test_system.py"
            
            if test_script.exists():
                logger.info("Running system tests...")
                result = subprocess.run([str(python_path), str(test_script)], 
                                      cwd=self.install_dir, timeout=300)
                
                if result.returncode == 0:
                    self.log_step("System Tests", True, "All tests passed")
                else:
                    self.log_step("System Tests", False, "Some tests failed")
                    return False
            else:
                self.log_step("System Tests", False, "Test script not found")
                return False
            
            return True
            
        except subprocess.TimeoutExpired:
            self.log_step("System Tests", False, "Tests timed out")
            return False
        except Exception as e:
            self.log_step("System Tests", False, f"Error: {e}")
            return False
    
    def create_documentation(self) -> bool:
        """Step 8: Create deployment documentation"""
        logger.info("=" * 60)
        logger.info("STEP 8: Creating Documentation")
        logger.info("=" * 60)
        
        try:
            # Create deployment guide
            deployment_guide = self.install_dir / "DEPLOYMENT_GUIDE.md"
            
            guide_content = f"""# ICS Cybersecurity System - Windows Server Deployment Guide

## Installation Location
The system is installed at: `{self.install_dir}`

## Service Information
- **Service Name**: {self.service_name}
- **Display Name**: {self.service_display_name}
- **Description**: {self.service_description}

## Quick Start

### Start the Service
```cmd
cd {self.install_dir}
start_service.bat
```

### Stop the Service
```cmd
cd {self.install_dir}
stop_service.bat
```

### Check Service Status
```cmd
cd {self.install_dir}
service_status.bat
```

### Access the System
- **API**: http://localhost:8000
- **Dashboard**: http://localhost:8050
- **API Key**: test-api-key-123

## Management Commands

### Using Windows Services
```cmd
# Start service
sc start {self.service_name}

# Stop service
sc stop {self.service_name}

# Check status
sc query {self.service_name}

# Set to auto-start
sc config {self.service_name} start= auto
```

### Using PowerShell
```powershell
# Start service
Start-Service "{self.service_name}"

# Stop service
Stop-Service "{self.service_name}"

# Get service status
Get-Service "{self.service_name}"
```

## Configuration
- Configuration files are located in: `{self.install_dir}\\config\\`
- Logs are stored in: `{self.install_dir}\\logs\\`
- Models are stored in: `{self.install_dir}\\models\\`

## Troubleshooting

### Service Won't Start
1. Check Windows Event Viewer for errors
2. Verify Python installation: `{self.install_dir}\\venv\\Scripts\\python.exe --version`
3. Check dependencies: `{self.install_dir}\\venv\\Scripts\\pip.exe list`

### API Not Responding
1. Check if service is running: `sc query {self.service_name}`
2. Verify firewall rules: `netsh advfirewall firewall show rule name="ICS Cybersecurity API"`
3. Check logs: `{self.install_dir}\\logs\\`

### Dashboard Not Accessible
1. Verify service is running
2. Check firewall rules for port 8050
3. Try accessing: http://localhost:8050

## Uninstallation
To completely remove the system:
```cmd
cd {self.install_dir}
uninstall.bat
```

## Support
For issues and support, check the logs in: `{self.install_dir}\\logs\\`
"""
            
            with open(deployment_guide, 'w') as f:
                f.write(guide_content)
            
            self.log_step("Deployment Guide", True, "Created DEPLOYMENT_GUIDE.md")
            
            return True
            
        except Exception as e:
            self.log_step("Documentation", False, f"Error: {e}")
            return False
    
    def deploy(self) -> bool:
        """Run complete deployment"""
        logger.info("🚀 Starting Windows Server Deployment")
        logger.info(f"Deployment started at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        try:
            # Step 1: Check prerequisites
            if not self.check_prerequisites():
                logger.error("Prerequisites check failed. Stopping deployment.")
                return False
            
            # Step 2: Install system
            if not self.install_system():
                logger.error("System installation failed. Stopping deployment.")
                return False
            
            # Step 3: Configure firewall
            if not self.configure_firewall():
                logger.warning("Firewall configuration failed, but continuing...")
            
            # Step 4: Create Windows service
            if not self.create_windows_service():
                logger.error("Windows service creation failed. Stopping deployment.")
                return False
            
            # Step 5: Create management scripts
            if not self.create_startup_scripts():
                logger.warning("Management scripts creation failed, but continuing...")
            
            # Step 6: Create desktop shortcuts
            if not self.create_desktop_shortcuts():
                logger.warning("Desktop shortcuts creation failed, but continuing...")
            
            # Step 7: Run tests
            if not self.run_post_installation_tests():
                logger.warning("Post-installation tests failed, but continuing...")
            
            # Step 8: Create documentation
            if not self.create_documentation():
                logger.warning("Documentation creation failed, but continuing...")
            
            # Final summary
            logger.info("=" * 60)
            logger.info("DEPLOYMENT COMPLETE")
            logger.info("=" * 60)
            logger.info(f"Installation Directory: {self.install_dir}")
            logger.info(f"Service Name: {self.service_name}")
            logger.info("API: http://localhost:8000")
            logger.info("Dashboard: http://localhost:8050")
            logger.info("")
            logger.info("Next Steps:")
            logger.info("1. Start the service: start_service.bat")
            logger.info("2. Access the dashboard: http://localhost:8050")
            logger.info("3. Test the API: http://localhost:8000")
            logger.info("4. Check service status: service_status.bat")
            
            return True
            
        except Exception as e:
            logger.error(f"Deployment failed with error: {e}")
            return False

def main():
    """Main function"""
    deployer = WindowsServerDeployer()
    
    if deployer.deploy():
        logger.info("✅ Deployment completed successfully!")
        sys.exit(0)
    else:
        logger.error("❌ Deployment failed!")
        sys.exit(1)

if __name__ == "__main__":
    main() 