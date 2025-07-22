#!/usr/bin/env python3
"""
Database initialization script for ICS cybersecurity system.
"""

import sys
import json
from pathlib import Path

# Add src to path for imports
sys.path.append(str(Path(__file__).parent.parent / "src"))

from src.graph_analysis.attack_graph import Node, Edge
from config.settings import load_config


def init_neo4j_database():
    """Initialize Neo4j database with sample data."""
    try:
        from neo4j import GraphDatabase
        
        config = load_config()
        graph_config = config['graph']
        
        # Connect to Neo4j
        driver = GraphDatabase.driver(
            graph_config['neo4j_uri'],
            auth=(graph_config['neo4j_user'], graph_config['neo4j_password'])
        )
        
        with driver.session() as session:
            # Clear existing data
            session.run("MATCH (n) DETACH DELETE n")
            print("Cleared existing Neo4j data")
            
            # Create sample ICS nodes
            sample_nodes = [
                Node(
                    id="plc_001",
                    type="plc",
                    ip_address="192.168.1.10",
                    hostname="PLC-001",
                    vulnerabilities=["CVE-2021-1234", "CVE-2021-5678"],
                    criticality=0.9,
                    location="Production Floor A",
                    description="Primary PLC controlling production line"
                ),
                Node(
                    id="rtu_001",
                    type="rtu",
                    ip_address="192.168.1.11",
                    hostname="RTU-001",
                    vulnerabilities=["CVE-2021-9012"],
                    criticality=0.8,
                    location="Remote Site 1",
                    description="Remote terminal unit for monitoring"
                ),
                Node(
                    id="scada_server",
                    type="scada",
                    ip_address="192.168.1.20",
                    hostname="SCADA-SERVER",
                    vulnerabilities=["CVE-2021-3456", "CVE-2021-7890"],
                    criticality=0.95,
                    location="Control Room",
                    description="Main SCADA server"
                ),
                Node(
                    id="hmi_001",
                    type="hmi",
                    ip_address="192.168.1.21",
                    hostname="HMI-001",
                    vulnerabilities=["CVE-2021-2345"],
                    criticality=0.7,
                    location="Control Room",
                    description="Human Machine Interface"
                ),
                Node(
                    id="firewall_001",
                    type="firewall",
                    ip_address="192.168.1.1",
                    hostname="FW-001",
                    vulnerabilities=[],
                    criticality=0.6,
                    location="Network Room",
                    description="Network firewall"
                ),
                Node(
                    id="database_server",
                    type="database",
                    ip_address="192.168.1.30",
                    hostname="DB-SERVER",
                    vulnerabilities=["CVE-2021-6789"],
                    criticality=0.85,
                    location="Server Room",
                    description="Historical database server"
                )
            ]
            
            # Create nodes in Neo4j
            for node in sample_nodes:
                session.run("""
                    CREATE (n:Node {
                        id: $id,
                        type: $type,
                        ip_address: $ip_address,
                        hostname: $hostname,
                        criticality: $criticality,
                        location: $location,
                        description: $description
                    })
                """, **node.__dict__)
            
            print(f"Created {len(sample_nodes)} nodes in Neo4j")
            
            # Create sample edges
            sample_edges = [
                Edge(
                    source="firewall_001",
                    target="scada_server",
                    protocol="TCP",
                    port=22,
                    vulnerability="CVE-2021-3456",
                    attack_probability=0.3,
                    impact=0.8,
                    description="SSH access to SCADA server"
                ),
                Edge(
                    source="scada_server",
                    target="plc_001",
                    protocol="Modbus",
                    port=502,
                    vulnerability="CVE-2021-1234",
                    attack_probability=0.6,
                    impact=0.9,
                    description="Modbus communication to PLC"
                ),
                Edge(
                    source="scada_server",
                    target="rtu_001",
                    protocol="DNP3",
                    port=20000,
                    vulnerability="CVE-2021-9012",
                    attack_probability=0.4,
                    impact=0.7,
                    description="DNP3 communication to RTU"
                ),
                Edge(
                    source="hmi_001",
                    target="scada_server",
                    protocol="HTTP",
                    port=80,
                    vulnerability="CVE-2021-2345",
                    attack_probability=0.5,
                    impact=0.6,
                    description="Web interface access"
                ),
                Edge(
                    source="scada_server",
                    target="database_server",
                    protocol="TCP",
                    port=1433,
                    vulnerability="CVE-2021-6789",
                    attack_probability=0.2,
                    impact=0.8,
                    description="Database connection"
                )
            ]
            
            # Create edges in Neo4j
            for edge in sample_edges:
                session.run("""
                    MATCH (source:Node {id: $source})
                    MATCH (target:Node {id: $target})
                    CREATE (source)-[r:CONNECTS_TO {
                        protocol: $protocol,
                        port: $port,
                        vulnerability: $vulnerability,
                        attack_probability: $attack_probability,
                        impact: $impact,
                        description: $description
                    }]->(target)
                """, **edge.__dict__)
            
            print(f"Created {len(sample_edges)} edges in Neo4j")
        
        driver.close()
        print("Neo4j database initialized successfully")
        
    except ImportError:
        print("Neo4j not available. Skipping Neo4j initialization.")
    except Exception as e:
        print(f"Error initializing Neo4j: {e}")


def create_sample_data():
    """Create sample data files."""
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)
    
    # Sample MITRE ATT&CK ICS data
    mitre_data = {
        "techniques": {
            "T1595.001": {
                "name": "Active Scanning: Scanning IP Blocks",
                "description": "Adversaries may scan IP blocks to identify active hosts",
                "tactic": "reconnaissance",
                "platforms": ["ics"]
            },
            "T1078": {
                "name": "Valid Accounts",
                "description": "Adversaries may obtain and abuse credentials of existing accounts",
                "tactic": "initial_access",
                "platforms": ["ics"]
            },
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "description": "Adversaries may abuse command and script interpreters to execute commands",
                "tactic": "execution",
                "platforms": ["ics"]
            },
            "T1562.001": {
                "name": "Impair Defenses: Disable or Modify Tools",
                "description": "Adversaries may disable security tools to avoid detection",
                "tactic": "defense_evasion",
                "platforms": ["ics"]
            }
        },
        "tactics": {
            "reconnaissance": {
                "name": "Reconnaissance",
                "description": "The adversary is trying to gather information they can use to plan future operations"
            },
            "initial_access": {
                "name": "Initial Access",
                "description": "The adversary is trying to get into your network"
            },
            "execution": {
                "name": "Execution",
                "description": "The adversary is trying to run malicious code"
            },
            "defense_evasion": {
                "name": "Defense Evasion",
                "description": "The adversary is trying to avoid being detected"
            }
        }
    }
    
    with open(data_dir / "mitre_attack_ics.json", "w") as f:
        json.dump(mitre_data, f, indent=2)
    
    print("Created sample MITRE ATT&CK data")
    
    # Sample attack graph data
    attack_graph_data = {
        "nodes": [
            {
                "id": "plc_001",
                "type": "plc",
                "ip_address": "192.168.1.10",
                "hostname": "PLC-001",
                "vulnerabilities": ["CVE-2021-1234"],
                "criticality": 0.9,
                "location": "Production Floor A",
                "description": "Primary PLC"
            },
            {
                "id": "scada_server",
                "type": "scada",
                "ip_address": "192.168.1.20",
                "hostname": "SCADA-SERVER",
                "vulnerabilities": ["CVE-2021-3456"],
                "criticality": 0.95,
                "location": "Control Room",
                "description": "Main SCADA server"
            }
        ],
        "edges": [
            {
                "source": "scada_server",
                "target": "plc_001",
                "protocol": "Modbus",
                "port": 502,
                "vulnerability": "CVE-2021-1234",
                "attack_probability": 0.6,
                "impact": 0.9,
                "description": "Modbus communication"
            }
        ]
    }
    
    with open(data_dir / "attack_graph.json", "w") as f:
        json.dump(attack_graph_data, f, indent=2)
    
    print("Created sample attack graph data")


def create_directories():
    """Create necessary directories."""
    directories = [
        "logs",
        "models",
        "exports",
        "data",
        "config"
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
    
    print("Created necessary directories")


def main():
    """Main initialization function."""
    print("Initializing ICS Cybersecurity System...")
    
    # Create directories
    create_directories()
    
    # Create sample data
    create_sample_data()
    
    # Initialize Neo4j database
    init_neo4j_database()
    
    print("Initialization completed successfully!")


if __name__ == "__main__":
    main() 