# ICS Cybersecurity System API Documentation

## Overview

The ICS Cybersecurity System provides a comprehensive RESTful API for managing and monitoring industrial control system security. The API is built using FastAPI and provides endpoints for threat detection, risk assessment, graph analysis, and automated response.

## Base URL

```
http://localhost:8000
```

## Authentication

The API uses Bearer token authentication. Include your API key in the Authorization header:

```
Authorization: Bearer your-api-key-here
```

Valid API keys:
- `test-api-key-123` (for testing)
- `admin-key-456` (for administration)

## Endpoints

### System Endpoints

#### GET /
Root endpoint providing basic system information.

**Response:**
```json
{
  "message": "ICS Cybersecurity API",
  "version": "1.0.0",
  "status": "operational"
}
```

#### GET /health
Health check endpoint for monitoring system status.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00",
  "components": {
    "network_monitor": "running",
    "graph_analyzer": "running",
    "risk_scorer": "running",
    "response_system": "running"
  },
  "uptime": 3600.5
}
```

### Threat Management

#### GET /threats
Retrieve recent threats with optional filtering.

**Parameters:**
- `limit` (int, optional): Maximum number of threats to return (default: 100)
- `severity` (string, optional): Filter by threat severity (low, medium, high, critical)
- `source_ip` (string, optional): Filter by source IP address
- `time_range` (string, optional): Time range filter (1h, 6h, 24h, 7d, default: 24h)

**Response:**
```json
[
  {
    "timestamp": 1705312200.0,
    "source_ip": "192.168.1.100",
    "destination_ip": "192.168.1.10",
    "threat_type": "port_scan",
    "severity": "medium",
    "confidence": 0.8,
    "description": "Port scan detected on Modbus port",
    "mitre_technique": "T1595.001"
  }
]
```

#### POST /threats
Create a new threat entry.

**Request Body:**
```json
{
  "source_ip": "192.168.1.100",
  "destination_ip": "192.168.1.10",
  "threat_type": "unauthorized_access",
  "severity": "high",
  "confidence": 0.9,
  "description": "Unauthorized access attempt",
  "mitre_technique": "T1078"
}
```

**Response:**
```json
{
  "message": "Threat created successfully",
  "threat_id": "threat_1705312200",
  "threat": {
    "source_ip": "192.168.1.100",
    "destination_ip": "192.168.1.10",
    "threat_type": "unauthorized_access",
    "severity": "high",
    "confidence": 0.9,
    "description": "Unauthorized access attempt",
    "mitre_technique": "T1078",
    "timestamp": 1705312200.0
  }
}
```

### Risk Assessment

#### POST /risk/assess
Assess risk for packet data.

**Request Body:**
```json
{
  "packet_data": {
    "timestamp": 1705312200.0,
    "source_ip": "192.168.1.100",
    "destination_ip": "192.168.1.10",
    "protocol": "TCP",
    "packet_size": 100,
    "source_port": 12345,
    "destination_port": 502,
    "flags": {
      "syn": true,
      "ack": false
    }
  },
  "threat_data": [
    {
      "threat_type": "port_scan",
      "severity": "medium",
      "confidence": 0.8
    }
  ]
}
```

**Response:**
```json
{
  "source_ip": "192.168.1.100",
  "destination_ip": "192.168.1.10",
  "risk_score": 0.75,
  "threat_level": "high",
  "confidence": 0.85,
  "contributing_factors": [
    "active_threats",
    "ics_protocol_targeted",
    "suspicious_tcp_flags"
  ],
  "description": "High risk detected due to: active_threats, ics_protocol_targeted, suspicious_tcp_flags"
}
```

#### GET /risk/scores
Retrieve recent risk assessments.

**Parameters:**
- `limit` (int, optional): Maximum number of scores to return (default: 100)

**Response:**
```json
[
  {
    "timestamp": 1705312200.0,
    "source_ip": "192.168.1.100",
    "destination_ip": "192.168.1.10",
    "risk_score": 0.75,
    "confidence": 0.85,
    "threat_level": "high",
    "contributing_factors": ["active_threats"],
    "ml_model": "random_forest",
    "features": {
      "packet_size": 100.0,
      "protocol": 1.0,
      "is_ics_protocol": 1.0
    },
    "description": "High risk detected"
  }
]
```

#### GET /risk/performance
Get machine learning model performance metrics.

**Response:**
```json
{
  "random_forest": {
    "model_name": "random_forest",
    "accuracy": 0.92,
    "precision": 0.89,
    "recall": 0.91,
    "f1_score": 0.90,
    "false_alarm_rate": 0.08,
    "mcc": 0.84,
    "training_time": 15.5,
    "prediction_time": 0.002,
    "last_updated": 1705312200.0
  },
  "svm": {
    "model_name": "svm",
    "accuracy": 0.88,
    "precision": 0.85,
    "recall": 0.87,
    "f1_score": 0.86,
    "false_alarm_rate": 0.12,
    "mcc": 0.76,
    "training_time": 25.3,
    "prediction_time": 0.005,
    "last_updated": 1705312200.0
  }
}
```

### Graph Analysis

#### GET /graph/nodes
Retrieve all nodes in the attack graph.

**Response:**
```json
[
  {
    "id": "plc_001",
    "type": "plc",
    "ip_address": "192.168.1.10",
    "hostname": "PLC-001",
    "criticality": 0.9,
    "vulnerabilities": ["CVE-2021-1234"],
    "location": "Production Floor A",
    "description": "Primary PLC controlling production line"
  }
]
```

#### GET /graph/edges
Retrieve all edges in the attack graph.

**Response:**
```json
[
  {
    "source": "scada_server",
    "target": "plc_001",
    "protocol": "Modbus",
    "port": 502,
    "attack_probability": 0.6,
    "impact": 0.9,
    "vulnerability": "CVE-2021-1234",
    "description": "Modbus communication to PLC"
  }
]
```

#### POST /graph/paths
Find attack paths between two nodes.

**Request Body:**
```json
{
  "source_node": "firewall_001",
  "target_node": "plc_001",
  "max_paths": 10
}
```

**Response:**
```json
[
  {
    "path_id": "path_0_1705312200",
    "nodes": ["firewall_001", "scada_server", "plc_001"],
    "total_risk": 0.85,
    "attack_steps": [
      "Exploit TCP connection on port 22 from firewall_001 to scada_server",
      "Exploit Modbus connection on port 502 from scada_server to plc_001 using CVE-2021-1234"
    ],
    "mitre_techniques": ["T1078", "T1059"],
    "estimated_time": 45
  }
]
```

#### GET /graph/critical-nodes
Get most critical nodes in the network.

**Parameters:**
- `top_k` (int, optional): Number of critical nodes to return (default: 10)

**Response:**
```json
[
  {
    "node_id": "scada_server",
    "score": 0.95,
    "node_info": {
      "id": "scada_server",
      "type": "scada",
      "ip_address": "192.168.1.20",
      "hostname": "SCADA-SERVER",
      "criticality": 0.95,
      "location": "Control Room",
      "description": "Main SCADA server"
    }
  }
]
```

#### GET /graph/statistics
Get graph statistics.

**Response:**
```json
{
  "total_nodes": 6,
  "total_edges": 5,
  "node_types": {
    "plc": 1,
    "rtu": 1,
    "scada": 1,
    "hmi": 1,
    "firewall": 1,
    "database": 1
  },
  "connectivity": 0.33,
  "diameter": 3,
  "average_clustering": 0.25
}
```

### Response Management

#### POST /response/execute
Execute threat response.

**Request Body:**
```json
{
  "threat_data": {
    "source_ip": "192.168.1.100",
    "destination_ip": "192.168.1.10",
    "threat_type": "port_scan",
    "severity": "medium",
    "confidence": 0.8,
    "description": "Port scan detected",
    "mitre_technique": "T1595.001",
    "timestamp": 1705312200.0
  },
  "response_level": "medium",
  "auto_execute": true,
  "priority": 3
}
```

**Response:**
```json
{
  "message": "Response executed successfully",
  "action_id": "block_ip_1705312200",
  "success": true,
  "execution_time": 2.5,
  "description": "IP address 192.168.1.100 blocked for 1 hour"
}
```

#### GET /response/history
Get response history.

**Parameters:**
- `limit` (int, optional): Maximum number of responses to return (default: 50)

**Response:**
```json
[
  {
    "action_id": "block_ip_1705312200",
    "success": true,
    "execution_time": 2.5,
    "impact_assessment": {
      "threat_mitigation": 0.8,
      "system_availability": -0.3,
      "user_experience": -0.2,
      "security_posture": 0.6
    },
    "side_effects": ["legitimate_traffic_blocked"],
    "timestamp": 1705312200.0,
    "description": "IP address 192.168.1.100 blocked for 1 hour"
  }
]
```

#### GET /response/statistics
Get response system statistics.

**Response:**
```json
{
  "total_responses": 25,
  "successful_responses": 22,
  "success_rate": 0.88,
  "active_strategies": 4,
  "q_table_size": 64,
  "strategy_performance": {
    "low_monitoring": [0.9, 0.85, 0.92],
    "medium_isolation": [0.8, 0.75, 0.85],
    "high_lockdown": [0.7, 0.65, 0.75]
  }
}
```

#### GET /response/q-table
Get Q-Learning table for response optimization.

**Response:**
```json
{
  "low_port_scan_normal": {
    "monitor_only": 0.5,
    "log_alert": 0.8,
    "block_ip": 0.3
  },
  "medium_unauthorized_access_normal": {
    "block_ip": 0.9,
    "isolate_device": 0.7,
    "update_firewall_rules": 0.6
  }
}
```

### System Management

#### GET /system/status
Get overall system status.

**Response:**
```json
{
  "overall_status": "operational",
  "components": {
    "network_monitor": "running",
    "graph_analyzer": "running",
    "risk_scorer": "running",
    "response_system": "running"
  },
  "uptime": 3600.5,
  "last_update": "2024-01-15T10:30:00",
  "statistics": {
    "network": {
      "total_packets": 15000,
      "ics_packets": 2500,
      "threats_detected": 15,
      "uptime": 3600.5
    },
    "response": {
      "total_responses": 25,
      "successful_responses": 22,
      "success_rate": 0.88
    },
    "graph": {
      "total_nodes": 6,
      "total_edges": 5,
      "connectivity": 0.33
    }
  }
}
```

#### POST /system/export
Export system data.

**Parameters:**
- `data_type` (string, optional): Type of data to export (all, threats, risk, responses, graph, default: all)
- `format` (string, optional): Export format (json, csv, default: json)

**Response:**
```json
{
  "message": "Data exported successfully",
  "filename": "export_all_20240115_103000.json",
  "filepath": "exports/export_all_20240115_103000.json",
  "data_types": ["threats", "risk_scores", "responses", "graph"]
}
```

## Error Handling

The API uses standard HTTP status codes:

- `200 OK`: Request successful
- `400 Bad Request`: Invalid request parameters
- `401 Unauthorized`: Invalid or missing API key
- `404 Not Found`: Resource not found
- `500 Internal Server Error`: Server error
- `503 Service Unavailable`: Component not available

Error responses include a JSON object with error details:

```json
{
  "error": "Bad Request",
  "message": "Invalid threat level specified",
  "path": "/threats"
}
```

## Rate Limiting

The API implements rate limiting of 100 requests per minute per API key. When the limit is exceeded, the API returns:

```json
{
  "error": "Rate limit exceeded",
  "message": "Too many requests",
  "retry_after": 60
}
```

## WebSocket Support

For real-time updates, the API supports WebSocket connections at `/ws`. Subscribe to different channels:

- `/ws/threats` - Real-time threat notifications
- `/ws/risk` - Real-time risk assessment updates
- `/ws/responses` - Real-time response execution updates

## SDK Examples

### Python Client

```python
import requests

class ICSClient:
    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
    
    def get_threats(self, limit=100):
        response = requests.get(
            f"{self.base_url}/threats",
            headers=self.headers,
            params={'limit': limit}
        )
        return response.json()
    
    def assess_risk(self, packet_data, threat_data=None):
        payload = {
            'packet_data': packet_data,
            'threat_data': threat_data or []
        }
        response = requests.post(
            f"{self.base_url}/risk/assess",
            headers=self.headers,
            json=payload
        )
        return response.json()
    
    def execute_response(self, threat_data, response_level="medium"):
        payload = {
            'threat_data': threat_data,
            'response_level': response_level,
            'auto_execute': True
        }
        response = requests.post(
            f"{self.base_url}/response/execute",
            headers=self.headers,
            json=payload
        )
        return response.json()

# Usage
client = ICSClient('http://localhost:8000', 'test-api-key-123')
threats = client.get_threats(limit=50)
```

### JavaScript Client

```javascript
class ICSClient {
    constructor(baseUrl, apiKey) {
        this.baseUrl = baseUrl;
        this.headers = {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json'
        };
    }
    
    async getThreats(limit = 100) {
        const response = await fetch(
            `${this.baseUrl}/threats?limit=${limit}`,
            { headers: this.headers }
        );
        return response.json();
    }
    
    async assessRisk(packetData, threatData = null) {
        const payload = {
            packet_data: packetData,
            threat_data: threatData || []
        };
        const response = await fetch(
            `${this.baseUrl}/risk/assess`,
            {
                method: 'POST',
                headers: this.headers,
                body: JSON.stringify(payload)
            }
        );
        return response.json();
    }
    
    async executeResponse(threatData, responseLevel = 'medium') {
        const payload = {
            threat_data: threatData,
            response_level: responseLevel,
            auto_execute: true
        };
        const response = await fetch(
            `${this.baseUrl}/response/execute`,
            {
                method: 'POST',
                headers: this.headers,
                body: JSON.stringify(payload)
            }
        );
        return response.json();
    }
}

// Usage
const client = new ICSClient('http://localhost:8000', 'test-api-key-123');
const threats = await client.getThreats(50);
```

## Integration Examples

### SIEM Integration

```python
# Send threats to SIEM system
def send_to_siem(threat_data):
    siem_payload = {
        'event_type': 'ics_threat',
        'timestamp': threat_data['timestamp'],
        'source_ip': threat_data['source_ip'],
        'destination_ip': threat_data['destination_ip'],
        'threat_type': threat_data['threat_type'],
        'severity': threat_data['severity'],
        'mitre_technique': threat_data['mitre_technique'],
        'description': threat_data['description']
    }
    
    # Send to SIEM
    requests.post('https://siem.company.com/api/events', json=siem_payload)

# Subscribe to threat events
def on_threat_detected(threat_data):
    send_to_siem(threat_data)
    # Additional processing...
```

### Firewall Integration

```python
# Block IP addresses on firewall
def block_ip_on_firewall(ip_address, duration=3600):
    firewall_payload = {
        'action': 'block',
        'ip_address': ip_address,
        'duration': duration,
        'reason': 'ICS threat detected'
    }
    
    response = requests.post(
        'https://firewall.company.com/api/rules',
        json=firewall_payload,
        headers={'Authorization': 'Bearer firewall-api-key'}
    )
    return response.json()

# Execute firewall response
def execute_firewall_response(threat_data):
    if threat_data['severity'] in ['high', 'critical']:
        block_ip_on_firewall(threat_data['source_ip'])
```

## Best Practices

1. **API Key Security**: Store API keys securely and rotate them regularly
2. **Rate Limiting**: Implement client-side rate limiting to avoid hitting API limits
3. **Error Handling**: Always handle API errors gracefully in your applications
4. **Data Validation**: Validate data before sending to the API
5. **Monitoring**: Monitor API usage and performance
6. **Backup**: Regularly backup configuration and data
7. **Updates**: Keep the API client libraries updated

## Support

For API support and questions:
- Check the API documentation at `/docs` (Swagger UI)
- Review the interactive documentation at `/redoc`
- Contact the development team for additional support 