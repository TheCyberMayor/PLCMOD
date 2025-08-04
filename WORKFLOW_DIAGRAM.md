# ICS Cybersecurity System - Workflow Diagram

## Complete System Workflow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              ICS CYBERSECURITY SYSTEM                           │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   SYSTEM INIT   │───▶│  LOAD CONFIG    │───▶│  INIT DATABASE  │───▶│  START SERVICES │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │                       │
         ▼                       ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  VIRTUAL ENV    │    │  SETTINGS.YAML  │    │  CREATE DIRS    │    │  API + DASHBOARD│
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘

                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              CONTINUOUS MONITORING                              │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ NETWORK MONITOR │───▶│ PACKET CAPTURE  │───▶│ PROTOCOL PARSE  │───▶│ THREAT DETECT   │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │                       │
         ▼                       ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  LOG MONITOR    │    │  SCAPY/PYSHARK  │    │  MODBUS/DNP3    │    │  PATTERN MATCH  │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘

                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              THREAT PROCESSING                                  │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ THREAT DETECTED │───▶│ FEATURE EXTRACT │───▶│ RISK ASSESSMENT │───▶│ GRAPH UPDATE   │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │                       │
         ▼                       ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  ALERT TRIGGER  │    │  ML FEATURES    │    │  ML MODELS      │    │  NEO4J GRAPH    │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘

                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              RESPONSE EXECUTION                                 │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ RESPONSE SELECT │───▶│ APPROVAL CHECK  │───▶│ ACTION EXECUTE  │───▶│ EFFECTIVENESS   │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │                       │
         ▼                       ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  STRATEGY MAP   │    │  MANUAL OVERRIDE│    │  BLOCK/ISOLATE  │    │  SUCCESS TRACK  │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘

                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              OUTPUT & VISUALIZATION                             │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  API ENDPOINTS  │───▶│  WEB DASHBOARD  │───   ▶│  REAL-TIME ALERTS│───▶│  EXTERNAL SYS   │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │                       │
         ▼                       ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  REST API       │    │  ATTACK GRAPHS  │    │  NOTIFICATIONS  │    │  SIEM/IRP       │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Detailed Component Workflow

### 1. Data Collection Workflow
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  NETWORK TRAFFIC│───▶│  PACKET CAPTURE │───▶│  PROTOCOL PARSE │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  SYSTEM LOGS    │    │  SCAPY/PYSHARK  │    │  MODBUS/DNP3    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  LOG PARSER     │    │  FEATURE EXTRACT│    │  THREAT INDICAT │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### 2. Threat Detection Workflow
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  RAW DATA       │───▶│  PREPROCESSING  │───▶│  FEATURE ENG    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  PACKETS/LOGS   │    │  NORMALIZATION  │    │  ML FEATURES    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  ML MODELS      │───▶│  THREAT SCORE   │───▶│  ALERT GENERATE │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### 3. Risk Assessment Workflow
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  THREAT DATA    │───▶│  FEATURE EXTRACT│───▶│  ML PREDICTION  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  SEVERITY       │    │  CONFIDENCE     │    │  CRITICALITY    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  HISTORICAL     │───▶│  MITRE MAPPING  │───▶│  RISK SCORE     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### 4. Response System Workflow
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  RISK SCORE     │───▶│  LEVEL DETERMINE│───▶│  STRATEGY SELECT│
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  THREAT LEVEL   │    │  LOW/MED/HIGH   │    │  ACTION MAP     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  APPROVAL CHECK │───▶│  ACTION EXECUTE │───▶│  EFFECTIVENESS  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Response Level Matrix

| Threat Level | Risk Score | Actions | Auto Execute | Manual Approval |
|--------------|------------|---------|--------------|-----------------|
| **Low**      | 0.0 - 0.4  | Log alert, Increase monitoring | ✅ Yes | ❌ No |
| **Medium**   | 0.4 - 0.6  | Block IP, Isolate device, Update rules | ✅ Yes | ❌ No |
| **High**     | 0.6 - 0.8  | Emergency shutdown, Full lockdown, Alert authorities | ❌ No | ✅ Yes |
| **Critical** | 0.8 - 1.0  | All high actions + Contact emergency services | ❌ No | ✅ Yes |

## Data Flow Diagram

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  INPUT SOURCES  │───▶│  PROCESSING     │───▶│  OUTPUT TARGETS │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ • Network       │    │ • Feature       │    │ • Dashboard     │
│ • System Logs   │    │ • ML Models     │    │ • API           │
│ • MITRE DB      │    │ • Graph Analysis│    │ • Alerts        │
│ • Config        │    │ • Risk Scoring  │    │ • External Sys  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## API Workflow

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  CLIENT REQUEST │───▶│  API GATEWAY    │───▶│  AUTHENTICATION │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  HTTP/HTTPS     │    │  ROUTING        │    │  API KEY CHECK  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  BUSINESS LOGIC │───▶│  DATA ACCESS    │───▶│  RESPONSE       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  THREAT/RISK    │    │  DATABASE       │    │  JSON/XML       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Dashboard Workflow

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  USER ACCESS    │───▶│  DASHBOARD APP  │───▶│  DATA FETCH     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  WEB BROWSER    │    │  DASH/PLOTLY    │    │  API CALLS      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  VISUALIZATION  │───▶│  REAL-TIME      │───▶│  INTERACTIVE    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  GRAPHS/CHARTS  │    │  UPDATES        │    │  USER ACTIONS   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Error Handling Workflow

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  ERROR DETECTED │───▶│  ERROR CLASSIFY │───▶│  ERROR HANDLE   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  EXCEPTION      │    │  SEVERITY       │    │  RECOVERY       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  LOG ERROR      │───▶│  ALERT ADMIN    │───▶│  CONTINUE/STOP  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Performance Monitoring Workflow

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  METRICS COLLECT│───▶│  PERFORMANCE    │───▶│  THRESHOLD CHECK│
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  RESPONSE TIME  │    │  THROUGHPUT     │    │  ACCURACY       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  ALERT IF HIGH  │───▶│  LOG METRICS    │───▶│  OPTIMIZE       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Security Workflow

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  ACCESS REQUEST │───▶│  AUTHENTICATION │───▶│  AUTHORIZATION  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  API KEY        │    │  VALIDATE KEY   │    │  CHECK PERMISS  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  GRANT ACCESS   │───▶│  AUDIT LOG      │───▶│  MONITOR        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Integration Workflow

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  EXTERNAL SYS   │───▶│  API GATEWAY    │───▶│  DATA PROCESS   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  SIEM/IRP       │    │  AUTHENTICATION │    │  FORMAT CONVERT │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  SYNC/ASYNC     │───▶│  RESPONSE       │───▶│  STATUS UPDATE  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Key Decision Points

### 1. Threat Detection Decision
```
IF threat_score > threshold:
    CREATE threat_alert
    TRIGGER risk_assessment
ELSE:
    CONTINUE monitoring
```

### 2. Risk Level Decision
```
IF risk_score >= 0.8:
    level = "critical"
    require_manual_approval = True
ELIF risk_score >= 0.6:
    level = "high"
    require_manual_approval = True
ELIF risk_score >= 0.4:
    level = "medium"
    require_manual_approval = False
ELSE:
    level = "low"
    require_manual_approval = False
```

### 3. Response Action Decision
```
IF level == "critical":
    actions = ["emergency_shutdown", "full_lockdown", "alert_authorities", "contact_emergency_services"]
ELIF level == "high":
    actions = ["emergency_shutdown", "full_lockdown", "alert_authorities"]
ELIF level == "medium":
    actions = ["block_ip", "isolate_device", "update_rules"]
ELSE:
    actions = ["log_alert", "increase_monitoring"]
```

### 4. Manual Approval Decision
```
IF require_manual_approval:
    SEND approval_request
    WAIT for human_decision
    IF approved:
        EXECUTE actions
    ELSE:
        LOG decision
        CONTINUE monitoring
ELSE:
    EXECUTE actions immediately
```

This workflow diagram provides a comprehensive view of how the ICS Cybersecurity System operates, from initial setup through continuous monitoring, threat detection, risk assessment, and automated response execution. 