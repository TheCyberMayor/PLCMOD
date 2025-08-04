# ICS Cybersecurity System - Technical Documentation

## Table of Contents
1. [System Overview](#system-overview)
2. [Architecture](#architecture)
3. [Core Components](#core-components)
4. [Workflow](#workflow)
5. [Data Flow](#data-flow)
6. [Threat Detection Process](#threat-detection-process)
7. [Risk Assessment Algorithm](#risk-assessment-algorithm)
8. [Response System](#response-system)
9. [API Endpoints](#api-endpoints)
10. [Configuration](#configuration)
11. [Testing and Validation](#testing-and-validation)
12. [Deployment Guide](#deployment-guide)

---

## System Overview

The ICS Cybersecurity System is a comprehensive industrial control system security platform designed to protect critical infrastructure from cyber threats. It combines real-time network monitoring, machine learning-based risk assessment, graph-theoretic analysis, and automated response mechanisms to provide a complete cybersecurity solution for industrial environments.

### Key Features
- **Real-time Threat Detection**: Monitors network traffic and system logs for suspicious activities
- **ML-based Risk Assessment**: Uses machine learning algorithms to calculate threat risk scores
- **Attack Graph Analysis**: Visualizes attack paths and identifies critical network nodes
- **Automated Response**: Executes context-aware mitigation strategies
- **RESTful API**: Provides integration capabilities for external systems
- **Web Dashboard**: Real-time monitoring and visualization interface

---

## Architecture

The system follows a modular, microservices-based architecture with the following layers:

```
┌─────────────────────────────────────────────────────────────┐
│                    Presentation Layer                       │
├─────────────────────────────────────────────────────────────┤
│  Web Dashboard (Port 8050)  │  REST API (Port 8000)        │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                    Business Logic Layer                     │
├─────────────────────────────────────────────────────────────┤
│  Threat Detection  │  Risk Assessment  │  Response System   │
│  Graph Analysis    │  Model Validation │  Data Collection   │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                    Data Layer                               │
├─────────────────────────────────────────────────────────────┤
│  Network Packets  │  System Logs  │  Threat Database       │
│  Risk Scores      │  Response History │  Configuration     │
└─────────────────────────────────────────────────────────────┘
```

---

## Core Components

### 1. Data Collection Module (`src/data_collection/`)
**Purpose**: Captures and analyzes network traffic and system logs

**Key Functions**:
- Network packet capture using Scapy/PyShark
- Log file monitoring and parsing
- Protocol analysis (Modbus, EtherNet/IP, DNP3, BACnet, S7, OPC UA)
- Real-time data preprocessing

**Input Sources**:
- Network interface traffic
- System log files (`/var/log/syslog`, `/var/log/auth.log`)
- ICS protocol packets
- MITRE ATT&CK database integration

### 2. Graph Analysis Module (`src/graph_analysis/`)
**Purpose**: Creates and analyzes attack graphs for threat visualization

**Key Functions**:
- Attack path identification
- Centrality analysis (betweenness, closeness, eigenvector, pagerank)
- Critical node identification
- Dynamic graph updates
- Neo4j database integration

**Graph Elements**:
- **Nodes**: Network devices (PLCs, HMIs, SCADA, RTUs, Firewalls)
- **Edges**: Network connections and attack paths
- **Attributes**: Criticality scores, vulnerabilities, attack probabilities

### 3. Risk Assessment Module (`src/risk_assessment/`)
**Purpose**: Calculates threat risk scores using machine learning algorithms

**ML Models**:
- Random Forest Classifier
- Support Vector Machine (SVM)
- XGBoost Classifier
- Ensemble methods

**Risk Factors**:
- Threat severity (low, medium, high, critical)
- Confidence scores (0.0 - 1.0)
- Historical threat patterns
- Network topology criticality
- MITRE ATT&CK technique mapping

### 4. Threat Mitigation Module (`src/threat_mitigation/`)
**Purpose**: Executes automated response strategies based on threat analysis

**Response Levels**:
- **Low**: Log alerts, increase monitoring
- **Medium**: Block IP, isolate device, update rules
- **High**: Emergency shutdown, full lockdown, alert authorities
- **Critical**: All high-level actions + contact emergency services

**Reinforcement Learning**:
- Q-Learning algorithm for adaptive responses
- Response effectiveness tracking
- Strategy optimization over time

### 5. Dashboard Module (`src/dashboard/`)
**Purpose**: Provides web-based visualization and monitoring interface

**Features**:
- Real-time threat monitoring
- Interactive attack graphs
- Risk score visualization
- Response history tracking
- System statistics dashboard

### 6. API Module (`src/api/`)
**Purpose**: RESTful API for system integration and external access

**Endpoints**:
- Threat management (`/threats`)
- Risk assessment (`/risk/`)
- Graph analysis (`/graph/`)
- Response execution (`/response/`)
- System status (`/system/`)

---

## Workflow

### 1. System Initialization
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Load Config   │───▶│ Initialize DB   │───▶│ Start Services  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

**Steps**:
1. Load configuration from `config/settings.yaml`
2. Initialize database and create required directories
3. Start all background services (network monitor, graph analyzer, etc.)
4. Launch API server and dashboard

### 2. Continuous Monitoring Workflow
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Network Monitor │───▶│ Packet Analysis │───▶│ Threat Detection│
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Log Collection  │    │ Protocol Parse  │    │ MITRE Mapping   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

**Process**:
1. **Data Collection**: Capture network packets and system logs
2. **Analysis**: Parse protocols and extract features
3. **Detection**: Identify suspicious patterns and behaviors
4. **Classification**: Map to MITRE ATT&CK techniques

### 3. Threat Processing Workflow
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Threat Detected │───▶│ Risk Assessment │───▶│ Response Gen.   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Graph Update    │    │ Score Calc.     │    │ Action Select   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

**Process**:
1. **Threat Detection**: Identify new threats from monitoring data
2. **Risk Assessment**: Calculate risk score using ML models
3. **Graph Update**: Update attack graph with new threat information
4. **Response Generation**: Select appropriate mitigation strategy
5. **Action Execution**: Execute automated response actions

### 4. Response Execution Workflow
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Response Plan   │───▶│ Action Execute  │───▶│ Effectiveness   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Manual Approval │    │ System Update   │    │ Learning Update│
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

**Process**:
1. **Plan Generation**: Create response plan based on threat level
2. **Approval Check**: Verify if manual approval is required
3. **Action Execution**: Execute mitigation actions
4. **Effectiveness Monitoring**: Track response effectiveness
5. **Learning Update**: Update ML models with new data

---

## Data Flow

### Input Data Flow
```
Network Traffic ──▶ Packet Capture ──▶ Protocol Analysis ──▶ Feature Extraction
     │                    │                    │                    │
     ▼                    ▼                    ▼                    ▼
System Logs ──▶ Log Parser ──▶ Event Correlation ──▶ Threat Indicators
     │                    │                    │                    │
     ▼                    ▼                    ▼                    ▼
MITRE DB ──▶ Technique Mapping ──▶ Attack Pattern ──▶ Risk Context
```

### Processing Data Flow
```
Raw Data ──▶ Preprocessing ──▶ Feature Engineering ──▶ ML Models ──▶ Risk Scores
   │            │                    │                    │            │
   ▼            ▼                    ▼                    ▼            ▼
Threats ──▶ Graph Update ──▶ Path Analysis ──▶ Response Selection ──▶ Actions
```

### Output Data Flow
```
Risk Scores ──▶ Dashboard ──▶ Real-time Alerts
     │              │              │
     ▼              ▼              ▼
Graph Data ──▶ API Endpoints ──▶ External Systems
     │              │              │
     ▼              ▼              ▼
Response History ──▶ Logs ──▶ Audit Trail
```

---

## Threat Detection Process

### 1. Network Packet Analysis
```python
def analyze_packet(packet_data):
    # Extract packet features
    features = {
        'source_ip': packet_data['source_ip'],
        'destination_ip': packet_data['destination_ip'],
        'protocol': packet_data['protocol'],
        'port': packet_data['destination_port'],
        'packet_size': packet_data['packet_size'],
        'flags': packet_data['flags'],
        'payload_pattern': extract_payload_pattern(packet_data['payload'])
    }
    
    # Apply detection rules
    threat_score = apply_detection_rules(features)
    
    # Check against known patterns
    if threat_score > threshold:
        return create_threat_alert(features, threat_score)
    
    return None
```

### 2. Log Analysis
```python
def analyze_logs(log_entries):
    threats = []
    
    for entry in log_entries:
        # Parse log entry
        parsed = parse_log_entry(entry)
        
        # Check for suspicious patterns
        if is_suspicious_login(parsed):
            threats.append(create_login_threat(parsed))
        
        if is_privilege_escalation(parsed):
            threats.append(create_privilege_threat(parsed))
        
        if is_data_exfiltration(parsed):
            threats.append(create_exfiltration_threat(parsed))
    
    return threats
```

### 3. Protocol-Specific Detection
```python
def detect_modbus_attack(packet):
    # Modbus-specific attack detection
    if packet.function_code in [1, 2, 3, 4]:  # Read functions
        if packet.unit_id not in authorized_devices:
            return create_unauthorized_access_threat(packet)
    
    if packet.function_code in [5, 6, 15, 16]:  # Write functions
        if not is_authorized_write(packet):
            return create_unauthorized_write_threat(packet)
    
    return None
```

---

## Risk Assessment Algorithm

### 1. Feature Extraction
```python
def extract_risk_features(threat_data):
    features = {
        'threat_type': encode_threat_type(threat_data['threat_type']),
        'severity': encode_severity(threat_data['severity']),
        'confidence': threat_data['confidence'],
        'source_criticality': get_node_criticality(threat_data['source_ip']),
        'target_criticality': get_node_criticality(threat_data['destination_ip']),
        'historical_frequency': get_historical_frequency(threat_data['source_ip']),
        'mitre_technique_risk': get_mitre_risk_score(threat_data['mitre_technique']),
        'time_of_day': extract_time_features(threat_data['timestamp']),
        'network_segment': get_network_segment(threat_data['destination_ip'])
    }
    return features
```

### 2. Risk Score Calculation
```python
def calculate_risk_score(features):
    # Base risk from severity
    base_risk = severity_weights[features['severity']]
    
    # Confidence adjustment
    confidence_factor = features['confidence']
    
    # Criticality adjustment
    criticality_factor = (features['source_criticality'] + features['target_criticality']) / 2
    
    # Historical pattern adjustment
    historical_factor = 1 + (features['historical_frequency'] * 0.2)
    
    # MITRE technique risk
    mitre_factor = features['mitre_technique_risk']
    
    # Calculate final risk score
    risk_score = base_risk * confidence_factor * criticality_factor * historical_factor * mitre_factor
    
    # Normalize to 0-1 range
    return min(1.0, risk_score)
```

### 3. Threat Level Classification
```python
def classify_threat_level(risk_score):
    if risk_score >= 0.8:
        return "critical"
    elif risk_score >= 0.6:
        return "high"
    elif risk_score >= 0.4:
        return "medium"
    else:
        return "low"
```

---

## Response System

### 1. Response Strategy Selection
```python
def select_response_strategy(threat_level, threat_type):
    strategies = {
        'low': {
            'actions': ['log_alert', 'increase_monitoring'],
            'priority': 1,
            'auto_execute': True
        },
        'medium': {
            'actions': ['block_ip', 'isolate_device', 'update_rules'],
            'priority': 2,
            'auto_execute': True
        },
        'high': {
            'actions': ['emergency_shutdown', 'full_lockdown', 'alert_authorities'],
            'priority': 3,
            'auto_execute': False  # Requires manual approval
        },
        'critical': {
            'actions': ['emergency_shutdown', 'full_lockdown', 'alert_authorities', 'contact_emergency_services'],
            'priority': 4,
            'auto_execute': False  # Requires manual approval
        }
    }
    
    return strategies.get(threat_level, strategies['low'])
```

### 2. Action Execution
```python
def execute_response_actions(actions, threat_data):
    results = []
    
    for action in actions:
        try:
            if action == 'block_ip':
                result = block_ip_address(threat_data['source_ip'])
            elif action == 'isolate_device':
                result = isolate_network_device(threat_data['destination_ip'])
            elif action == 'emergency_shutdown':
                result = initiate_emergency_shutdown(threat_data['destination_ip'])
            elif action == 'alert_authorities':
                result = send_alert_to_authorities(threat_data)
            else:
                result = {'success': False, 'error': f'Unknown action: {action}'}
            
            results.append({'action': action, 'result': result})
            
        except Exception as e:
            results.append({'action': action, 'result': {'success': False, 'error': str(e)}})
    
    return results
```

### 3. Reinforcement Learning Integration
```python
def update_q_table(state, action, reward, next_state):
    # Q-Learning update
    current_q = q_table.get((state, action), 0)
    max_next_q = max([q_table.get((next_state, a), 0) for a in available_actions])
    
    new_q = current_q + learning_rate * (reward + discount_factor * max_next_q - current_q)
    q_table[(state, action)] = new_q
```

---

## API Endpoints

### Core Endpoints

#### 1. System Status
```
GET /health
GET /system/status
```
**Purpose**: Monitor system health and operational status

#### 2. Threat Management
```
GET /threats?limit=100&severity=high
POST /threats
```
**Purpose**: Retrieve and create threat records

#### 3. Risk Assessment
```
GET /risk/scores?limit=100
POST /risk/assess
GET /risk/performance
```
**Purpose**: Access risk assessment data and model performance

#### 4. Graph Analysis
```
GET /graph/nodes
GET /graph/edges
POST /graph/paths
GET /graph/critical-nodes
GET /graph/statistics
```
**Purpose**: Access attack graph data and analysis

#### 5. Response Management
```
POST /response/execute
GET /response/history
GET /response/statistics
GET /response/q-table
```
**Purpose**: Execute and monitor response actions

### Authentication
All endpoints require API key authentication:
```
Authorization: Bearer test-api-key-123
```

---

## Configuration

### Network Configuration
```yaml
network:
  interface: "eth0"
  packet_count: 1000
  timeout: 30
  protocols:
    - "modbus"
    - "ethernet/ip"
    - "dnp3"
    - "bacnet"
    - "s7"
    - "opc_ua"
  log_sources:
    - "/var/log/syslog"
    - "/var/log/auth.log"
  authorized_ips:
    - "192.168.1.100"
    - "192.168.1.101"
```

### ML Model Configuration
```yaml
ml_models:
  models:
    - "random_forest"
    - "svm"
    - "xgboost"
  test_size: 0.2
  random_state: 42
  feature_window: 60
  anomaly_threshold: 0.8
  retrain_interval: 3600
```

### Response Configuration
```yaml
mitigation:
  response_levels:
    low:
      - "log_alert"
      - "increase_monitoring"
    medium:
      - "block_ip"
      - "isolate_device"
      - "update_rules"
    high:
      - "emergency_shutdown"
      - "full_lockdown"
      - "alert_authorities"
  auto_response: true
  manual_approval: false
```

---

## Testing and Validation

### 1. Unit Testing
```bash
# Run unit tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html
```

### 2. Integration Testing
```bash
# Run integration tests
python test_system.py

# Test API endpoints
python test_api.py
```

### 3. Performance Testing
```bash
# Test system performance
python -m pytest tests/test_performance.py -v
```

### 4. Security Testing
```bash
# Test authentication
python -m pytest tests/test_security.py -v

# Test input validation
python -m pytest tests/test_validation.py -v
```

---

## Deployment Guide

### Local Development Setup
```bash
# 1. Clone repository
git clone <repository-url>
cd ICS

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Initialize system
python scripts/init_database.py

# 5. Run system
python main.py
```

### Production Deployment
```bash
# 1. Install system dependencies
sudo apt update
sudo apt install python3 python3-venv python3-pip

# 2. Set up systemd service
sudo cp ics.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ics
sudo systemctl start ics

# 3. Configure firewall
sudo ufw allow 8000  # API
sudo ufw allow 8050  # Dashboard
```

### Docker Deployment
```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 8000 8050

CMD ["python", "main.py"]
```

---

## Monitoring and Maintenance

### 1. Log Monitoring
- **System Logs**: `logs/ics_system.log`
- **API Logs**: `logs/api.log`
- **Network Logs**: `logs/network.log`
- **Threat Logs**: `logs/threats.log`

### 2. Performance Metrics
- **Response Time**: Average API response time
- **Throughput**: Threats processed per second
- **Accuracy**: ML model prediction accuracy
- **False Positive Rate**: Incorrect threat detections

### 3. Health Checks
```bash
# Check system status
curl http://localhost:8000/health

# Check service status
sudo systemctl status ics

# Monitor resource usage
htop
```

### 4. Backup and Recovery
```bash
# Backup configuration
tar -czf backup_$(date +%Y%m%d).tar.gz config/ data/ models/

# Restore from backup
tar -xzf backup_20231201.tar.gz
```

---

## Troubleshooting

### Common Issues

#### 1. API Not Responding
```bash
# Check if service is running
sudo systemctl status ics

# Check logs
tail -f logs/api.log

# Restart service
sudo systemctl restart ics
```

#### 2. Network Monitoring Issues
```bash
# Check interface permissions
sudo setcap cap_net_raw=eip /path/to/python

# Verify interface exists
ip link show

# Test packet capture
sudo tcpdump -i eth0 -c 10
```

#### 3. Database Connection Issues
```bash
# Check Neo4j status
sudo systemctl status neo4j

# Test connection
python -c "from neo4j import GraphDatabase; print('Connected')"
```

#### 4. ML Model Issues
```bash
# Check model files
ls -la models/

# Retrain models
python scripts/retrain_models.py

# Validate model performance
python scripts/validate_models.py
```

---

## Security Considerations

### 1. Access Control
- Use strong API keys
- Implement role-based access control
- Enable HTTPS in production
- Regular key rotation

### 2. Network Security
- Isolate ICS network from corporate network
- Use VPN for remote access
- Implement network segmentation
- Regular security audits

### 3. Data Protection
- Encrypt sensitive data at rest
- Secure log storage
- Regular backup encryption
- Data retention policies

### 4. System Hardening
- Regular security updates
- Disable unnecessary services
- Implement intrusion detection
- Monitor system integrity

---

## Future Enhancements

### 1. Advanced ML Features
- Deep learning models for threat detection
- Natural language processing for log analysis
- Anomaly detection improvements
- Predictive threat modeling

### 2. Integration Capabilities
- SIEM system integration
- Threat intelligence feeds
- Incident response platforms
- Asset management systems

### 3. Scalability Improvements
- Microservices architecture
- Load balancing
- Distributed processing
- Cloud deployment options

### 4. Advanced Analytics
- Threat hunting capabilities
- Advanced visualization
- Custom dashboards
- Reporting automation

---

## Conclusion

The ICS Cybersecurity System provides a comprehensive solution for protecting industrial control systems from cyber threats. Its modular architecture, advanced ML capabilities, and automated response mechanisms make it suitable for both development/testing and production environments.

The system's ability to adapt to new threats through machine learning and its integration capabilities ensure it can evolve with the changing cybersecurity landscape while providing robust protection for critical infrastructure.

For additional support and documentation, refer to the project repository and contact the development team. 