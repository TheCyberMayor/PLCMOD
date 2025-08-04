# ICS Cybersecurity System - Technical Guide

## System Overview

The ICS Cybersecurity System is a comprehensive industrial control system security platform that protects critical infrastructure from cyber threats using:

- **Real-time Network Monitoring**: Packet capture and protocol analysis
- **Machine Learning Risk Assessment**: ML algorithms for threat scoring
- **Attack Graph Analysis**: Visual representation of attack paths
- **Automated Response System**: Context-aware mitigation strategies
- **RESTful API**: Integration capabilities for external systems
- **Web Dashboard**: Real-time monitoring interface

## Architecture

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

## Core Components

### 1. Data Collection (`src/data_collection/`)
- **Network Monitor**: Captures packets using Scapy/PyShark
- **Log Parser**: Monitors system logs for suspicious activities
- **Protocol Analyzer**: Supports Modbus, EtherNet/IP, DNP3, BACnet, S7, OPC UA
- **MITRE Integration**: Maps threats to ATT&CK framework

### 2. Graph Analysis (`src/graph_analysis/`)
- **Attack Graph**: Visualizes network topology and attack paths
- **Centrality Analysis**: Identifies critical network nodes
- **Path Finding**: Discovers potential attack routes
- **Neo4j Integration**: Graph database for complex queries

### 3. Risk Assessment (`src/risk_assessment/`)
- **ML Models**: Random Forest, SVM, XGBoost classifiers
- **Risk Scoring**: Calculates threat risk (0.0 - 1.0)
- **Feature Engineering**: Extracts relevant threat features
- **Model Validation**: Continuous performance monitoring

### 4. Threat Mitigation (`src/threat_mitigation/`)
- **Response Levels**: Low, Medium, High, Critical
- **Automated Actions**: Block IP, isolate device, shutdown
- **Reinforcement Learning**: Q-Learning for adaptive responses
- **Manual Override**: Human approval for critical actions

### 5. Dashboard (`src/dashboard/`)
- **Real-time Monitoring**: Live threat visualization
- **Interactive Graphs**: Attack path exploration
- **Statistics**: System performance metrics
- **Alerts**: Real-time notifications

### 6. API (`src/api/`)
- **RESTful Endpoints**: Full CRUD operations
- **Authentication**: API key-based security
- **Documentation**: Auto-generated OpenAPI docs
- **Integration**: External system connectivity

## Workflow

### 1. System Initialization
```
Load Configuration → Initialize Database → Start Services → Launch API/Dashboard
```

### 2. Continuous Monitoring
```
Network Traffic → Packet Analysis → Threat Detection → Risk Assessment
     ↓              ↓                ↓                ↓
System Logs → Log Parsing → Event Correlation → Response Generation
```

### 3. Threat Processing
```
Threat Detected → Risk Score Calculation → Graph Update → Response Selection → Action Execution
```

### 4. Response Execution
```
Response Plan → Approval Check → Action Execute → Effectiveness Monitor → Learning Update
```

## Data Flow

### Input Processing
```
Raw Data → Preprocessing → Feature Extraction → ML Models → Risk Scores
```

### Output Generation
```
Risk Scores → Dashboard → Real-time Alerts
     ↓           ↓           ↓
Graph Data → API Endpoints → External Systems
     ↓           ↓           ↓
Response History → Logs → Audit Trail
```

## Threat Detection Process

### Network Packet Analysis
```python
def analyze_packet(packet_data):
    features = extract_features(packet_data)
    threat_score = apply_detection_rules(features)
    
    if threat_score > threshold:
        return create_threat_alert(features, threat_score)
    return None
```

### Log Analysis
```python
def analyze_logs(log_entries):
    threats = []
    for entry in log_entries:
        if is_suspicious_pattern(entry):
            threats.append(create_threat(entry))
    return threats
```

### Protocol-Specific Detection
```python
def detect_modbus_attack(packet):
    if packet.function_code in [5, 6, 15, 16]:  # Write functions
        if not is_authorized_write(packet):
            return create_unauthorized_write_threat(packet)
    return None
```

## Risk Assessment Algorithm

### Feature Extraction
```python
def extract_risk_features(threat_data):
    return {
        'threat_type': encode_threat_type(threat_data['threat_type']),
        'severity': encode_severity(threat_data['severity']),
        'confidence': threat_data['confidence'],
        'source_criticality': get_node_criticality(threat_data['source_ip']),
        'target_criticality': get_node_criticality(threat_data['destination_ip']),
        'historical_frequency': get_historical_frequency(threat_data['source_ip']),
        'mitre_technique_risk': get_mitre_risk_score(threat_data['mitre_technique'])
    }
```

### Risk Score Calculation
```python
def calculate_risk_score(features):
    base_risk = severity_weights[features['severity']]
    confidence_factor = features['confidence']
    criticality_factor = (features['source_criticality'] + features['target_criticality']) / 2
    historical_factor = 1 + (features['historical_frequency'] * 0.2)
    mitre_factor = features['mitre_technique_risk']
    
    risk_score = base_risk * confidence_factor * criticality_factor * historical_factor * mitre_factor
    return min(1.0, risk_score)
```

## Response System

### Response Strategy Selection
```python
def select_response_strategy(threat_level):
    strategies = {
        'low': ['log_alert', 'increase_monitoring'],
        'medium': ['block_ip', 'isolate_device', 'update_rules'],
        'high': ['emergency_shutdown', 'full_lockdown', 'alert_authorities'],
        'critical': ['emergency_shutdown', 'full_lockdown', 'alert_authorities', 'contact_emergency_services']
    }
    return strategies.get(threat_level, strategies['low'])
```

### Action Execution
```python
def execute_response_actions(actions, threat_data):
    results = []
    for action in actions:
        if action == 'block_ip':
            result = block_ip_address(threat_data['source_ip'])
        elif action == 'isolate_device':
            result = isolate_network_device(threat_data['destination_ip'])
        elif action == 'emergency_shutdown':
            result = initiate_emergency_shutdown(threat_data['destination_ip'])
        results.append({'action': action, 'result': result})
    return results
```

## API Endpoints

### Core Endpoints
- `GET /health` - System health check
- `GET /system/status` - Overall system status
- `GET /threats` - Retrieve threats
- `POST /threats` - Create new threat
- `GET /risk/scores` - Risk assessment data
- `GET /graph/nodes` - Attack graph nodes
- `GET /graph/edges` - Attack graph edges
- `POST /response/execute` - Execute response actions
- `GET /response/history` - Response history

### Authentication
All endpoints require API key:
```
Authorization: Bearer test-api-key-123
```

## Configuration

### Network Settings
```yaml
network:
  interface: "eth0"
  protocols: ["modbus", "ethernet/ip", "dnp3", "bacnet", "s7", "opc_ua"]
  authorized_ips: ["192.168.1.100", "192.168.1.101"]
```

### ML Models
```yaml
ml_models:
  models: ["random_forest", "svm", "xgboost"]
  anomaly_threshold: 0.8
  retrain_interval: 3600
```

### Response Levels
```yaml
mitigation:
  response_levels:
    low: ["log_alert", "increase_monitoring"]
    medium: ["block_ip", "isolate_device", "update_rules"]
    high: ["emergency_shutdown", "full_lockdown", "alert_authorities"]
    critical: ["emergency_shutdown", "full_lockdown", "alert_authorities", "contact_emergency_services"]
```

## Testing

### Quick Test
```bash
python simple_test.py
```

### API Testing
```bash
# Start API server
python simple_api_server.py

# Test API endpoints
python test_api.py
```

### Full System Test
```bash
python test_system.py
```

## Deployment

### Local Development
```bash
# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements_minimal.txt

# Run system
python main.py
```

### Production Setup
```bash
# Install full dependencies
pip install -r requirements.txt

# Initialize database
python scripts/init_database.py

# Start as service
python main.py
```

### Windows Deployment
```bash
# Use Windows setup script
windows_server_setup.bat install
windows_server_setup.bat start
```

## Monitoring

### Log Files
- `logs/ics_system.log` - System events
- `logs/api.log` - API requests
- `logs/network.log` - Network monitoring
- `logs/threats.log` - Threat detection

### Health Checks
```bash
# Check API health
curl http://localhost:8000/health

# Check system status
curl http://localhost:8000/system/status
```

### Performance Metrics
- Response time: Average API response time
- Throughput: Threats processed per second
- Accuracy: ML model prediction accuracy
- False positive rate: Incorrect detections

## Security Considerations

### Access Control
- Use strong API keys
- Enable HTTPS in production
- Implement role-based access
- Regular key rotation

### Network Security
- Isolate ICS network
- Use VPN for remote access
- Network segmentation
- Regular security audits

### Data Protection
- Encrypt sensitive data
- Secure log storage
- Regular backups
- Data retention policies

## Troubleshooting

### Common Issues

#### API Not Responding
```bash
# Check service status
curl http://localhost:8000/health

# Check logs
tail -f logs/api.log

# Restart service
python main.py
```

#### Network Monitoring Issues
```bash
# Check interface permissions
sudo setcap cap_net_raw=eip /path/to/python

# Test packet capture
sudo tcpdump -i eth0 -c 10
```

#### Database Issues
```bash
# Check Neo4j status
sudo systemctl status neo4j

# Test connection
python -c "from neo4j import GraphDatabase; print('Connected')"
```

## System Capabilities

### Threat Detection
- **Network-based**: Packet analysis, protocol violations
- **Host-based**: Log analysis, system call monitoring
- **Behavioral**: Anomaly detection, pattern recognition
- **Signature-based**: Known threat pattern matching

### Risk Assessment
- **Multi-factor scoring**: Severity, confidence, criticality
- **Historical analysis**: Pattern recognition over time
- **Context awareness**: Network topology consideration
- **MITRE mapping**: ATT&CK framework integration

### Response Automation
- **Level-based actions**: Escalating response strategies
- **Context-aware**: Threat-specific responses
- **Learning capability**: Reinforcement learning optimization
- **Manual override**: Human approval for critical actions

### Visualization
- **Real-time dashboards**: Live threat monitoring
- **Attack graphs**: Network topology visualization
- **Trend analysis**: Historical data visualization
- **Alert management**: Notification system

## Integration Capabilities

### External Systems
- **SIEM Integration**: Security information and event management
- **Threat Intelligence**: External threat feeds
- **Incident Response**: Automated incident handling
- **Asset Management**: Device inventory integration

### APIs and Protocols
- **RESTful API**: Standard HTTP endpoints
- **WebSocket**: Real-time data streaming
- **GraphQL**: Flexible data querying
- **Message Queues**: Asynchronous processing

## Future Enhancements

### Advanced Features
- **Deep Learning**: Neural network-based detection
- **Natural Language Processing**: Log text analysis
- **Predictive Analytics**: Threat prediction models
- **Cloud Integration**: Multi-cloud deployment

### Scalability
- **Microservices**: Distributed architecture
- **Load Balancing**: High availability
- **Distributed Processing**: Parallel threat analysis
- **Containerization**: Docker/Kubernetes deployment

## Conclusion

The ICS Cybersecurity System provides comprehensive protection for industrial control systems through advanced threat detection, risk assessment, and automated response capabilities. Its modular architecture and integration features make it suitable for both development and production environments.

The system's machine learning capabilities and automated response mechanisms ensure it can adapt to new threats while providing robust protection for critical infrastructure.

For additional support, refer to the project documentation and contact the development team. 