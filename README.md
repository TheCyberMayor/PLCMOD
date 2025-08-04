# ICS Cybersecurity System

A comprehensive Industrial Control System (ICS) cybersecurity platform that combines graph-theoretic analysis, machine learning, and real-time threat detection to protect industrial infrastructure.

## 🏗️ Architecture Overview

The system is built around six core components:

1. **Threat Identification & Data Collection** - Network packet analysis and log collection
2. **Graph-Theoretic Representation** - Attack graph modeling and visualization
3. **Risk Scoring & Threat Classification** - ML-based risk assessment
4. **Dynamic Threat Mitigation** - Automated response strategies
5. **Dashboard & API** - Real-time monitoring and integration
6. **Model Validation** - Performance evaluation and testing

## 📁 Project Structure

```
ICS/
├── src/
│   ├── data_collection/          # Network monitoring and log collection
│   ├── graph_analysis/           # Graph-theoretic modeling
│   ├── risk_assessment/          # ML-based risk scoring
│   ├── threat_mitigation/        # Automated response systems
│   ├── dashboard/                # Web-based visualization
│   ├── api/                      # RESTful API endpoints
│   └── validation/               # Model testing and evaluation
├── config/                       # Configuration files
├── data/                         # Sample data and logs
├── tests/                        # Unit and integration tests
├── docs/                         # Documentation
└── scripts/                      # Utility scripts
```

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Neo4j Database
- Elasticsearch (optional)
- Network access to ICS components

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd ICS
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. Initialize the database:
```bash
python scripts/init_database.py
```

5. Start the system:
```bash
python main.py
```

## 🔧 Configuration

The system uses configuration files in the `config/` directory:

- `network_config.yaml` - Network monitoring settings
- `ml_models.yaml` - Machine learning model parameters
- `dashboard_config.yaml` - Dashboard appearance and layout
- `api_config.yaml` - API endpoints and authentication

## 📊 Features

### Real-time Threat Detection
- Network packet analysis using Wireshark/Scapy
- Log correlation and anomaly detection
- MITRE ATT&CK framework integration

### Graph-Based Analysis
- Attack path visualization
- Centrality analysis for critical nodes
- Dynamic graph updates based on threats

### Machine Learning Risk Assessment
- Random Forest, SVM, and XGBoost classifiers
- Dynamic risk scoring (GRS)
- Anomaly detection algorithms

### Automated Response
- Rule-based threat mitigation
- Reinforcement learning for adaptive responses
- Integration with ICS components

### Dashboard & API
- Real-time threat monitoring
- Interactive attack graphs
- RESTful API for system integration

## 🧪 Testing

Run the test suite:
```bash
pytest tests/ -v
```

Run with coverage:
```bash
pytest tests/ --cov=src --cov-report=html
```

## 📈 Performance Metrics

The system evaluates performance using:
- Accuracy, Precision, Recall
- False Alarm Rate (FAR)
- Matthews Correlation Coefficient (MCC)
- Response time measurements

## 🔒 Security Considerations

- All communications are encrypted
- API authentication required
- Audit logging for all actions
- Secure storage of sensitive data

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Check the documentation in `docs/`
- Review the configuration examples 


EXPORT SKLEARN_ALLOW_DEPRECATED_SKLEARN_PACKAGE_INSTALL=True