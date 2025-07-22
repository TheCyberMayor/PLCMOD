# ICS Cybersecurity System - Windows Server Deployment Guide

## 🚀 Quick Start

### Option 1: Automated Deployment (Recommended)
```cmd
# Run as Administrator
windows_server_setup.bat install
```

### Option 2: Manual Deployment
```cmd
# Run as Administrator
python deploy_windows_server.py
```

## 📋 Prerequisites

### System Requirements
- **Windows Server 2016/2019/2022** or **Windows 10/11**
- **Python 3.8+** installed
- **Administrator privileges**
- **4GB RAM minimum** (8GB recommended)
- **2GB free disk space**

### Network Requirements
- **Port 8000** available for API
- **Port 8050** available for Dashboard
- **Network monitoring permissions** (if using packet capture)

## 🔧 Installation Steps

### Step 1: Download and Prepare
1. Download the ICS system files to your server
2. Extract to a directory (e.g., `C:\ICS-Setup`)
3. Open Command Prompt as **Administrator**

### Step 2: Run Installation
```cmd
cd C:\ICS-Setup
windows_server_setup.bat install
```

### Step 3: Verify Installation
```cmd
windows_server_setup.bat status
```

## 🎯 System Management

### Start the System
```cmd
# Method 1: Using batch script
windows_server_setup.bat start

# Method 2: Using Windows Services
sc start ICSCybersecurity

# Method 3: Using PowerShell
Start-Service "ICSCybersecurity"
```

### Stop the System
```cmd
# Method 1: Using batch script
windows_server_setup.bat stop

# Method 2: Using Windows Services
sc stop ICSCybersecurity

# Method 3: Using PowerShell
Stop-Service "ICSCybersecurity"
```

### Check Status
```cmd
# Method 1: Using batch script
windows_server_setup.bat status

# Method 2: Using Windows Services
sc query ICSCybersecurity

# Method 3: Using PowerShell
Get-Service "ICSCybersecurity"
```

### Run Tests
```cmd
windows_server_setup.bat test
```

## 🌐 Accessing the System

### Web Interface
- **API**: http://localhost:8000
- **Dashboard**: http://localhost:8050
- **API Key**: `test-api-key-123`

### Desktop Shortcuts
After installation, desktop shortcuts are created:
- **ICS API** - Opens the API interface
- **ICS Dashboard** - Opens the dashboard

## ⚙️ Configuration

### Configuration Files
Located in: `C:\ICS-Cybersecurity\config\`

#### Main Configuration (`settings.yaml`)
```yaml
network:
  interface: "Ethernet"  # Change to your network interface
  capture_mode: "simulation"  # or "live"
  packet_buffer_size: 1000

api:
  host: "0.0.0.0"
  port: 8000
  api_key: "test-api-key-123"  # Change for production

dashboard:
  host: "0.0.0.0"
  port: 8050
  refresh_interval: 5
```

### Network Interface Configuration
To monitor a specific network interface:

1. **Find your interface name**:
```cmd
netsh interface show interface
```

2. **Update configuration**:
```yaml
network:
  interface: "Your-Interface-Name"
  capture_mode: "live"
```

## 🔒 Security Configuration

### Firewall Rules
The installation automatically creates these firewall rules:
- **ICS Cybersecurity API** - Allows inbound TCP on port 8000
- **ICS Cybersecurity Dashboard** - Allows inbound TCP on port 8050
- **ICS Network Monitoring** - Allows network monitoring

### API Security
For production use, change the default API key:

1. **Edit the configuration**:
```yaml
api:
  api_key: "your-secure-api-key-here"
```

2. **Restart the service**:
```cmd
windows_server_setup.bat stop
windows_server_setup.bat start
```

### SSL/TLS Configuration (Optional)
To enable HTTPS:

1. **Install certificates** in Windows Certificate Store
2. **Update configuration**:
```yaml
api:
  ssl_cert: "path/to/certificate.pem"
  ssl_key: "path/to/private.key"
```

## 📊 Monitoring and Logging

### Log Files
Located in: `C:\ICS-Cybersecurity\logs\`
- `system.log` - System events
- `api.log` - API requests
- `network.log` - Network monitoring
- `threats.log` - Threat detection

### Windows Event Log
The service logs to Windows Event Log:
- **Source**: ICSCybersecurity
- **View**: Event Viewer → Windows Logs → Application

### Performance Monitoring
Monitor system performance:
```cmd
# Check service performance
sc query ICSCybersecurity

# Monitor resource usage
tasklist /FI "IMAGENAME eq python.exe"
```

## 🔧 Troubleshooting

### Service Won't Start
1. **Check Windows Event Viewer**:
   - Open Event Viewer
   - Navigate to Windows Logs → Application
   - Look for errors from ICSCybersecurity

2. **Check Python installation**:
```cmd
C:\ICS-Cybersecurity\venv\Scripts\python.exe --version
```

3. **Check dependencies**:
```cmd
C:\ICS-Cybersecurity\venv\Scripts\pip.exe list
```

4. **Manual start for debugging**:
```cmd
cd C:\ICS-Cybersecurity
venv\Scripts\activate.bat
python main.py
```

### API Not Responding
1. **Check service status**:
```cmd
sc query ICSCybersecurity
```

2. **Check firewall rules**:
```cmd
netsh advfirewall firewall show rule name="ICS Cybersecurity API"
```

3. **Test connectivity**:
```cmd
curl http://localhost:8000/health
```

4. **Check logs**:
```cmd
type C:\ICS-Cybersecurity\logs\api.log
```

### Dashboard Not Accessible
1. **Verify service is running**
2. **Check port 8050**:
```cmd
netstat -an | findstr :8050
```

3. **Test dashboard**:
```cmd
curl http://localhost:8050
```

### Network Monitoring Issues
1. **Check interface name**:
```cmd
netsh interface show interface
```

2. **Verify permissions**:
   - Run as Administrator
   - Check Windows Defender settings

3. **Test packet capture**:
```cmd
cd C:\ICS-Cybersecurity
venv\Scripts\activate.bat
python -c "from src.data_collection.network_monitor import NetworkMonitor; print('Network monitor test')"
```

## 🔄 Updates and Maintenance

### Updating the System
1. **Stop the service**:
```cmd
windows_server_setup.bat stop
```

2. **Backup configuration**:
```cmd
xcopy C:\ICS-Cybersecurity\config C:\ICS-Backup\config /E /I
```

3. **Update files** and restart:
```cmd
windows_server_setup.bat start
```

### Backup and Recovery
1. **Create backup**:
```cmd
xcopy C:\ICS-Cybersecurity C:\ICS-Backup /E /I
```

2. **Restore from backup**:
```cmd
xcopy C:\ICS-Backup C:\ICS-Cybersecurity /E /I
sc start ICSCybersecurity
```

## 🗑️ Uninstallation

### Complete Removal
```cmd
# Run as Administrator
windows_server_setup.bat uninstall
```

This will:
- Stop and remove the Windows service
- Remove firewall rules
- Delete installation directory
- Remove desktop shortcuts

### Manual Cleanup
If the uninstall script fails:
```cmd
# Stop service
sc stop ICSCybersecurity
sc delete ICSCybersecurity

# Remove firewall rules
netsh advfirewall firewall delete rule name="ICS Cybersecurity API"
netsh advfirewall firewall delete rule name="ICS Cybersecurity Dashboard"
netsh advfirewall firewall delete rule name="ICS Network Monitoring"

# Remove directory
rmdir /S /Q C:\ICS-Cybersecurity
```

## 📞 Support and Resources

### Log Locations
- **System logs**: `C:\ICS-Cybersecurity\logs\`
- **Windows Event Log**: Event Viewer → Application
- **Deployment log**: `deployment.log` (in setup directory)

### Configuration Files
- **Main config**: `C:\ICS-Cybersecurity\config\settings.yaml`
- **Python config**: `C:\ICS-Cybersecurity\config\settings.py`

### Service Information
- **Service Name**: `ICSCybersecurity`
- **Display Name**: `ICS Cybersecurity System`
- **Description**: `Industrial Control System Cybersecurity Platform`
- **Startup Type**: Automatic
- **Log On As**: Local System

### Performance Tuning
For high-traffic environments:

1. **Increase packet buffer**:
```yaml
network:
  packet_buffer_size: 5000
```

2. **Adjust API limits**:
```yaml
api:
  rate_limit: 1000
  max_connections: 100
```

3. **Optimize dashboard refresh**:
```yaml
dashboard:
  refresh_interval: 2
```

## 🎯 Production Deployment Checklist

- [ ] Change default API key
- [ ] Configure SSL/TLS certificates
- [ ] Set up proper network interface
- [ ] Configure backup strategy
- [ ] Set up monitoring and alerting
- [ ] Test failover procedures
- [ ] Document network topology
- [ ] Train operators on system use
- [ ] Establish maintenance schedule
- [ ] Set up log rotation
- [ ] Configure Windows Task Scheduler for backups
- [ ] Test disaster recovery procedures

## 🔗 Integration Examples

### PowerShell Integration
```powershell
# Get system status
$service = Get-Service "ICSCybersecurity"
Write-Host "Service Status: $($service.Status)"

# Test API
try {
    $response = Invoke-RestMethod -Uri "http://localhost:8000/health" -Method Get
    Write-Host "API Status: $($response.status)"
} catch {
    Write-Host "API Error: $($_.Exception.Message)"
}
```

### Windows Task Scheduler
Create automated tasks:
```cmd
# Daily backup
schtasks /create /tn "ICS Backup" /tr "C:\ICS-Cybersecurity\backup.bat" /sc daily /st 02:00

# Weekly log cleanup
schtasks /create /tn "ICS Log Cleanup" /tr "C:\ICS-Cybersecurity\cleanup_logs.bat" /sc weekly /d SUN /st 03:00
```

### Network Monitoring Integration
```cmd
# Monitor specific network segments
netsh interface set interface "Your-Interface" admin=enable
```

This comprehensive guide covers all aspects of deploying and managing the ICS cybersecurity system on Windows Server. The automated scripts handle most of the complexity, making deployment straightforward and reliable. 