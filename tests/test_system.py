"""
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.graph_analysis.attack_graph import Node, Edge
Unit tests for ICS cybersecurity system.
"""

import pytest
import asyncio
import json
import time
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock

# Add src to path for imports
import sys
sys.path.append(str(Path(__file__).parent.parent / "src"))

from src.data_collection.network_monitor import NetworkMonitor, PacketData, ThreatIndicator
from src.graph_analysis.attack_graph import AttackGraphAnalyzer, Node, Edge
from src.risk_assessment.ml_risk_scorer import MLRiskScorer, RiskScore
from src.threat_mitigation.response_system import ThreatResponseSystem, MitigationAction
from src.validation.model_validator import ModelValidator, AttackScenario


class TestNetworkMonitor:
    """Test cases for NetworkMonitor."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = {
            'interface': 'eth0',
            'packet_count': 100,
            'timeout': 10,
            'protocols': ['modbus', 'ethernet/ip'],
            'authorized_ips': ['192.168.1.100']
        }
        self.monitor = NetworkMonitor(self.config)
    
    def test_initialization(self):
        """Test NetworkMonitor initialization."""
        assert self.monitor.interface == 'eth0'
        assert self.monitor.packet_count == 100
        assert self.monitor.protocols == ['modbus', 'ethernet/ip']
        assert not self.monitor.running
    
    def test_is_ics_protocol(self):
        """Test ICS protocol detection."""
        assert self.monitor._is_ics_protocol(502)  # Modbus
        assert self.monitor._is_ics_protocol(44818)  # EtherNet/IP
        assert not self.monitor._is_ics_protocol(80)  # HTTP
    
    def test_get_protocol_name(self):
        """Test protocol name retrieval."""
        assert self.monitor._get_protocol_name(502) == 'modbus'
        assert self.monitor._get_protocol_name(44818) == 'ethernet/ip'
        assert self.monitor._get_protocol_name(80) is None
    
    def test_is_unauthorized_access(self):
        """Test unauthorized access detection."""
        # Test unauthorized IP
        packet_data = PacketData(
            timestamp=time.time(),
            source_ip="192.168.1.200",
            destination_ip="192.168.1.10",
            source_port=12345,
            destination_port=502,
            protocol="TCP",
            packet_size=100,
            payload=b"",
            flags={},
            ttl=64,
            window_size=8192,
            sequence_number=1000,
            acknowledgment_number=1001
        )
        assert self.monitor._is_unauthorized_access(packet_data)
        
        # Test authorized IP
        packet_data.source_ip = "192.168.1.100"
        assert not self.monitor._is_unauthorized_access(packet_data)
    
    def test_is_malicious_payload(self):
        """Test malicious payload detection."""
        # Test malicious payload
        packet_data = PacketData(
            timestamp=time.time(),
            source_ip="192.168.1.100",
            destination_ip="192.168.1.10",
            source_port=12345,
            destination_port=502,
            protocol="TCP",
            packet_size=100,
            payload=b"admin password exec",
            flags={},
            ttl=64,
            window_size=8192,
            sequence_number=1000,
            acknowledgment_number=1001
        )
        assert self.monitor._is_malicious_payload(packet_data)
        
        # Test normal payload
        packet_data.payload = b"normal data"
        assert not self.monitor._is_malicious_payload(packet_data)
    
    def test_get_statistics(self):
        """Test statistics retrieval."""
        stats = self.monitor.get_statistics()
        assert 'total_packets' in stats
        assert 'ics_packets' in stats
        assert 'threats_detected' in stats
        assert 'uptime' in stats


class TestAttackGraphAnalyzer:
    """Test cases for AttackGraphAnalyzer."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = {
            'centrality_metrics': ['betweenness', 'closeness'],
            'max_path_length': 5,
            'graph_layout': 'spring',
            'node_size': 20,
            'edge_width': 2
        }
        self.analyzer = AttackGraphAnalyzer(self.config)
    
    def test_initialization(self):
        """Test AttackGraphAnalyzer initialization."""
        assert self.analyzer.centrality_metrics == ['betweenness', 'closeness']
        assert self.analyzer.max_path_length == 5
        assert len(self.analyzer.nodes) == 0
        assert len(self.analyzer.edges) == 0
    
    def test_add_node(self):
        """Test node addition."""
        node = Node(
            id="test_node",
            type="plc",
            ip_address="192.168.1.10",
            hostname="TEST-PLC",
            vulnerabilities=["CVE-2021-1234"],
            criticality=0.8,
            location="Test Location",
            description="Test PLC"
        )
        
        self.analyzer.add_node(node)
        assert "test_node" in self.analyzer.nodes
        assert self.analyzer.nodes["test_node"] == node
        assert "test_node" in self.analyzer.graph.nodes()
    
    def test_add_edge(self):
        """Test edge addition."""
        # Add nodes first
        source_node = Node(
            id="source",
            type="plc",
            ip_address="192.168.1.10",
            hostname="SOURCE",
            vulnerabilities=[],
            criticality=0.7,
            location="Location A",
            description="Source node"
        )
        target_node = Node(
            id="target",
            type="scada",
            ip_address="192.168.1.20",
            hostname="TARGET",
            vulnerabilities=[],
            criticality=0.9,
            location="Location B",
            description="Target node"
        )
        
        self.analyzer.add_node(source_node)
        self.analyzer.add_node(target_node)
        
        # Add edge
        edge = Edge(
            source="source",
            target="target",
            protocol="Modbus",
            port=502,
            vulnerability="CVE-2021-1234",
            attack_probability=0.6,
            impact=0.8,
            description="Test connection"
        )
        
        self.analyzer.add_edge(edge)
        assert ("source", "target") in self.analyzer.edges
        assert self.analyzer.edges[("source", "target")] == edge
        assert self.analyzer.graph.has_edge("source", "target")
    
    def test_calculate_path_risk(self):
        """Test path risk calculation."""
        # Create a simple path
        path = ["node1", "node2", "node3"]
        
        # Add nodes and edges
        for i, node_id in enumerate(path):
            node = Node(
                id=node_id,
                type="plc",
                ip_address=f"192.168.1.{10+i}",
                hostname=f"NODE-{i+1}",
                vulnerabilities=[],
                criticality=0.8,
                location=f"Location {i+1}",
                description=f"Node {i+1}"
            )
            self.analyzer.add_node(node)
        
        # Add edges
        for i in range(len(path) - 1):
            edge = Edge(
                source=path[i],
                target=path[i+1],
                protocol="TCP",
                port=502,
                attack_probability=0.5,
                impact=0.6,
                description=f"Edge {i+1}"
            )
            self.analyzer.add_edge(edge)
        
        risk = self.analyzer._calculate_path_risk(path)
        assert 0 <= risk <= 1
        assert risk > 0  # Should have some risk
    
    def test_get_graph_statistics(self):
        """Test graph statistics retrieval."""
        # Add some test data
        node = Node(
            id="test",
            type="plc",
            ip_address="192.168.1.10",
            hostname="TEST",
            vulnerabilities=[],
            criticality=0.8,
            location="Test",
            description="Test"
        )
        self.analyzer.add_node(node)
        
        stats = self.analyzer.get_graph_statistics()
        assert 'total_nodes' in stats
        assert 'total_edges' in stats
        assert 'node_types' in stats
        assert stats['total_nodes'] == 1


class TestMLRiskScorer:
    """Test cases for MLRiskScorer."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = {
            'models': ['random_forest'],
            'test_size': 0.2,
            'random_state': 42,
            'feature_window': 60,
            'anomaly_threshold': 0.8,
            'model_path': 'models/',
            'authorized_ips': ['192.168.1.100']
        }
        self.scorer = MLRiskScorer(self.config)
    
    def test_initialization(self):
        """Test MLRiskScorer initialization."""
        assert self.scorer.model_types == ['random_forest']
        assert self.scorer.test_size == 0.2
        assert self.scorer.random_state == 42
        assert len(self.scorer.models) == 0
    
    def test_extract_features(self):
        """Test feature extraction."""
        packet_data = {
            'timestamp': time.time(),
            'source_ip': '192.168.1.100',
            'destination_ip': '192.168.1.10',
            'source_port': 12345,
            'destination_port': 502,
            'protocol': 'TCP',
            'packet_size': 100,
            'payload': b'test data',
            'flags': {'syn': True, 'ack': False},
            'ttl': 64,
            'window_size': 8192,
            'sequence_number': 1000,
            'acknowledgment_number': 0
        }
        
        features = self.scorer.extract_features(packet_data)
        assert 'packet_size' in features
        assert 'protocol' in features
        assert 'source_port' in features
        assert 'destination_port' in features
        assert 'syn_flag' in features
        assert 'ack_flag' in features
        assert 'is_ics_protocol' in features
        assert 'is_authorized_ip' in features
    
    def test_encode_protocol(self):
        """Test protocol encoding."""
        assert self.scorer._encode_protocol('TCP') == 1.0
        assert self.scorer._encode_protocol('UDP') == 2.0
        assert self.scorer._encode_protocol('modbus') == 4.0
        assert self.scorer._encode_protocol('unknown') == 0.0
    
    def test_is_ics_protocol(self):
        """Test ICS protocol detection."""
        assert self.scorer._is_ics_protocol(502) == 1.0  # Modbus
        assert self.scorer._is_ics_protocol(44818) == 1.0  # EtherNet/IP
        assert self.scorer._is_ics_protocol(80) == 0.0  # HTTP
    
    def test_is_authorized_ip(self):
        """Test authorized IP detection."""
        assert self.scorer._is_authorized_ip('192.168.1.100') == 1.0
        assert self.scorer._is_authorized_ip('192.168.1.200') == 0.0
    
    def test_determine_threat_level(self):
        """Test threat level determination."""
        assert self.scorer._determine_threat_level(0.9) == 'critical'
        assert self.scorer._determine_threat_level(0.7) == 'high'
        assert self.scorer._determine_threat_level(0.5) == 'medium'
        assert self.scorer._determine_threat_level(0.3) == 'low'
    
    def test_identify_contributing_factors(self):
        """Test contributing factors identification."""
        features = {
            'threat_count': 5,
            'high_severity_threats': 2,
            'is_ics_protocol': 1.0,
            'is_authorized_ip': 0.0,
            'syn_flag': 1.0,
            'ack_flag': 0.0,
            'source_threat_count': 10
        }
        
        factors = self.scorer._identify_contributing_factors(features, 0.8)
        assert 'active_threats' in factors
        assert 'high_severity_threats' in factors
        assert 'ics_protocol_targeted' in factors
        assert 'unauthorized_source' in factors
        assert 'suspicious_tcp_flags' in factors
        assert 'source_threat_history' in factors


class TestThreatResponseSystem:
    """Test cases for ThreatResponseSystem."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = {
            'response_levels': {
                'low': ['log_alert'],
                'medium': ['block_ip'],
                'high': ['isolate_device']
            },
            'rl_algorithm': 'q_learning',
            'learning_rate': 0.1,
            'discount_factor': 0.9,
            'auto_response': True,
            'manual_approval': False
        }
        self.response_system = ThreatResponseSystem(self.config)
    
    def test_initialization(self):
        """Test ThreatResponseSystem initialization."""
        assert self.response_system.auto_response is True
        assert self.response_system.manual_approval is False
        assert len(self.response_system.response_strategies) > 0
        assert self.response_system.q_agent is not None
    
    def test_q_learning_agent(self):
        """Test Q-Learning agent functionality."""
        agent = self.response_system.q_agent
        
        # Test state definition
        assert len(agent.states) > 0
        assert len(agent.actions) > 0
        
        # Test action selection
        state = "low_port_scan_normal"
        action = agent.select_action(state)
        assert action in agent.actions
        
        # Test Q-value update
        agent.update_q_value(state, action, 1.0, "medium_port_scan_normal")
        assert state in agent.q_table
        assert action in agent.q_table[state]
    
    def test_response_strategies(self):
        """Test response strategies."""
        strategies = self.response_system.response_strategies
        
        # Check that strategies exist for different threat levels
        assert 'low_monitoring' in strategies
        assert 'medium_isolation' in strategies
        assert 'high_lockdown' in strategies
        assert 'critical_shutdown' in strategies
        
        # Check strategy properties
        low_strategy = strategies['low_monitoring']
        assert low_strategy.threat_level == 'low'
        assert len(low_strategy.actions) > 0
        assert low_strategy.success_rate > 0
    
    def test_select_response_strategy(self):
        """Test response strategy selection."""
        threat_data = {
            'threat_level': 'medium',
            'threat_type': 'port_scan',
            'confidence': 0.8
        }
        system_status = {'overall_status': 'normal'}
        
        strategy = self.response_system.select_response_strategy(threat_data, system_status)
        assert strategy is not None
        assert strategy.threat_level == 'medium'
    
    def test_evaluate_action_success(self):
        """Test action success evaluation."""
        action = MitigationAction(
            action_id="test_action",
            action_type="block_ip",
            target="192.168.1.100",
            parameters={},
            priority=3,
            estimated_impact=0.5,
            execution_time=10,
            description="Test action"
        )
        
        threat_data = {'threat_level': 'medium'}
        
        # Test multiple times to check randomness
        results = []
        for _ in range(10):
            success = self.response_system._evaluate_action_success(action, threat_data)
            results.append(success)
        
        # Should have some variation due to randomness
        assert len(set(results)) > 1
    
    def test_assess_action_impact(self):
        """Test action impact assessment."""
        action = MitigationAction(
            action_id="test_action",
            action_type="emergency_shutdown",
            target="critical_systems",
            parameters={},
            priority=5,
            estimated_impact=1.0,
            execution_time=60,
            description="Emergency shutdown"
        )
        
        # Test successful action
        impact = self.response_system._assess_action_impact(action, True)
        assert 'threat_mitigation' in impact
        assert 'system_availability' in impact
        assert 'user_experience' in impact
        assert 'security_posture' in impact
        
        # Test failed action
        impact = self.response_system._assess_action_impact(action, False)
        assert impact['threat_mitigation'] < 0
        assert impact['security_posture'] < 0
    
    def test_identify_side_effects(self):
        """Test side effects identification."""
        action = MitigationAction(
            action_id="test_action",
            action_type="emergency_shutdown",
            target="critical_systems",
            parameters={},
            priority=5,
            estimated_impact=1.0,
            execution_time=60,
            description="Emergency shutdown"
        )
        
        # Test successful action
        side_effects = self.response_system._identify_side_effects(action, True)
        assert 'production_stopped' in side_effects
        assert 'data_loss_risk' in side_effects
        assert 'recovery_time_needed' in side_effects
        
        # Test failed action
        side_effects = self.response_system._identify_side_effects(action, False)
        assert 'action_failure' in side_effects
    
    def test_get_response_statistics(self):
        """Test response statistics retrieval."""
        stats = self.response_system.get_response_statistics()
        assert 'total_responses' in stats
        assert 'successful_responses' in stats
        assert 'success_rate' in stats
        assert 'active_strategies' in stats
        assert 'q_table_size' in stats


class TestModelValidator:
    """Test cases for ModelValidator."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = {
            'testbeds': ['minicps', 'digital_twin'],
            'metrics': ['accuracy', 'precision', 'recall', 'f1', 'mcc'],
            'test_duration': 3600,
            'attack_scenarios': ['reconnaissance', 'initial_access', 'execution']
        }
        self.validator = ModelValidator(self.config)
    
    def test_initialization(self):
        """Test ModelValidator initialization."""
        assert self.validator.testbeds == ['minicps', 'digital_twin']
        assert self.validator.metrics == ['accuracy', 'precision', 'recall', 'f1', 'mcc']
        assert len(self.validator.scenarios) > 0
        assert len(self.validator.baselines) > 0
    
    def test_attack_scenarios(self):
        """Test attack scenarios initialization."""
        scenarios = self.validator.scenarios
        
        # Check scenario types
        scenario_types = [s.attack_type for s in scenarios]
        assert 'reconnaissance' in scenario_types
        assert 'initial_access' in scenario_types
        assert 'execution' in scenario_types
        
        # Check scenario properties
        for scenario in scenarios:
            assert scenario.scenario_id is not None
            assert scenario.name is not None
            assert scenario.mitre_technique is not None
            assert scenario.severity in ['low', 'medium', 'high', 'critical']
            assert scenario.expected_detection in [True, False]
            assert scenario.expected_response is not None
    
    def test_baselines(self):
        """Test performance baselines."""
        baselines = self.validator.baselines
        
        assert 'accuracy' in baselines
        assert 'precision' in baselines
        assert 'recall' in baselines
        assert 'f1_score' in baselines
        assert 'false_alarm_rate' in baselines
        assert 'mcc' in baselines
        assert 'response_time' in baselines
        
        # Check baseline values are reasonable
        assert 0 <= baselines['accuracy'] <= 1
        assert 0 <= baselines['precision'] <= 1
        assert 0 <= baselines['recall'] <= 1
        assert 0 <= baselines['f1_score'] <= 1
        assert 0 <= baselines['false_alarm_rate'] <= 1
        assert 0 <= baselines['mcc'] <= 1
        assert baselines['response_time'] > 0
    
    @pytest.mark.asyncio
    async def test_simulate_attack(self):
        """Test attack simulation."""
        scenario = self.validator.scenarios[0]
        components = {
            'network_monitor': Mock(),
            'risk_scorer': Mock(),
            'response_system': Mock()
        }
        
        # Mock component responses
        components['network_monitor'].get_recent_threats.return_value = []
        components['risk_scorer'].assess_risk.return_value = Mock(risk_score=0.7)
        components['response_system'].execute_response = AsyncMock(return_value=Mock(success=True))
        
        detected = await self.validator._simulate_attack(scenario, components)
        assert isinstance(detected, bool)
    
    def test_get_validation_results(self):
        """Test validation results retrieval."""
        results = self.validator.get_validation_results(limit=10)
        assert isinstance(results, list)
    
    def test_get_benchmark_results(self):
        """Test benchmark results retrieval."""
        results = self.validator.get_benchmark_results(limit=5)
        assert isinstance(results, list)


if __name__ == "__main__":
    pytest.main([__file__]) 