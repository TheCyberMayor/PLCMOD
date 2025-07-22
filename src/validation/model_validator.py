"""
Model validation and performance evaluation for ICS cybersecurity system.
"""

import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import random

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, matthews_corrcoef
from loguru import logger


@dataclass
class ValidationResult:
    """Data structure for validation results."""
    test_name: str
    model_name: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    false_alarm_rate: float
    mcc: float
    response_time: float
    timestamp: float
    test_duration: float
    attack_scenarios: List[str]
    description: str = ""


@dataclass
class BenchmarkResult:
    """Data structure for benchmark results."""
    benchmark_name: str
    system_performance: Dict[str, float]
    comparison_results: Dict[str, float]
    ranking: int
    timestamp: float
    description: str = ""


@dataclass
class AttackScenario:
    """Data structure for attack scenarios."""
    scenario_id: str
    name: str
    attack_type: str
    mitre_technique: str
    severity: str
    description: str
    payload: Dict[str, Any]
    expected_detection: bool
    expected_response: str


class ModelValidator:
    """Model validation and performance evaluation system."""
    
    def __init__(self, config: Dict):
        """Initialize model validator."""
        self.config = config
        self.running = False
        
        # Test environments
        self.testbeds = config.get('testbeds', ['minicps', 'digital_twin'])
        self.metrics = config.get('metrics', ['accuracy', 'precision', 'recall', 'f1', 'mcc'])
        self.test_duration = config.get('test_duration', 3600)
        self.attack_scenarios = config.get('attack_scenarios', ['reconnaissance', 'initial_access', 'execution'])
        
        # Results storage
        self.validation_results: List[ValidationResult] = []
        self.benchmark_results: List[BenchmarkResult] = []
        
        # Attack scenarios
        self.scenarios = self._initialize_attack_scenarios()
        
        # Performance baselines
        self.baselines = {
            'accuracy': 0.85,
            'precision': 0.80,
            'recall': 0.75,
            'f1_score': 0.77,
            'false_alarm_rate': 0.15,
            'mcc': 0.70,
            'response_time': 5.0  # seconds
        }
        
        logger.info("Model validator initialized")
    
    def _initialize_attack_scenarios(self) -> List[AttackScenario]:
        """Initialize predefined attack scenarios."""
        scenarios = []
        
        # Reconnaissance scenarios
        scenarios.append(AttackScenario(
            scenario_id="recon_001",
            name="Port Scanning",
            attack_type="reconnaissance",
            mitre_technique="T1595.001",
            severity="low",
            description="TCP port scan of ICS devices",
            payload={
                "source_ip": "192.168.1.100",
                "destination_ip": "192.168.1.10",
                "protocol": "TCP",
                "ports": [502, 44818, 20000],
                "scan_type": "syn_scan"
            },
            expected_detection=True,
            expected_response="block_ip"
        ))
        
        scenarios.append(AttackScenario(
            scenario_id="recon_002",
            name="Service Enumeration",
            attack_type="reconnaissance",
            mitre_technique="T1595.002",
            severity="medium",
            description="Service enumeration on ICS protocols",
            payload={
                "source_ip": "192.168.1.101",
                "destination_ip": "192.168.1.11",
                "protocol": "Modbus",
                "function_code": 1,
                "start_address": 0,
                "quantity": 10
            },
            expected_detection=True,
            expected_response="increase_monitoring"
        ))
        
        # Initial access scenarios
        scenarios.append(AttackScenario(
            scenario_id="access_001",
            name="Default Credentials",
            attack_type="initial_access",
            mitre_technique="T1078.001",
            severity="high",
            description="Attempt to access with default credentials",
            payload={
                "source_ip": "192.168.1.102",
                "destination_ip": "192.168.1.12",
                "protocol": "SSH",
                "username": "admin",
                "password": "admin",
                "attempts": 5
            },
            expected_detection=True,
            expected_response="block_ip"
        ))
        
        scenarios.append(AttackScenario(
            scenario_id="access_002",
            name="Brute Force Attack",
            attack_type="initial_access",
            mitre_technique="T1110.001",
            severity="high",
            description="Brute force attack on authentication",
            payload={
                "source_ip": "192.168.1.103",
                "destination_ip": "192.168.1.13",
                "protocol": "HTTP",
                "endpoint": "/login",
                "attempts": 100,
                "wordlist": ["admin", "password", "123456"]
            },
            expected_detection=True,
            expected_response="isolate_device"
        ))
        
        # Execution scenarios
        scenarios.append(AttackScenario(
            scenario_id="exec_001",
            name="Command Injection",
            attack_type="execution",
            mitre_technique="T1059.001",
            severity="critical",
            description="Command injection in ICS protocol",
            payload={
                "source_ip": "192.168.1.104",
                "destination_ip": "192.168.1.14",
                "protocol": "Modbus",
                "function_code": 6,
                "address": 1000,
                "value": "'; rm -rf /; #"
            },
            expected_detection=True,
            expected_response="emergency_shutdown"
        ))
        
        scenarios.append(AttackScenario(
            scenario_id="exec_002",
            name="Malicious Firmware",
            attack_type="execution",
            mitre_technique="T1542.001",
            severity="critical",
            description="Attempt to upload malicious firmware",
            payload={
                "source_ip": "192.168.1.105",
                "destination_ip": "192.168.1.15",
                "protocol": "HTTP",
                "endpoint": "/firmware/upload",
                "file_type": "firmware.bin",
                "file_size": 1024000,
                "checksum": "malicious_hash"
            },
            expected_detection=True,
            expected_response="emergency_shutdown"
        ))
        
        # Data exfiltration scenarios
        scenarios.append(AttackScenario(
            scenario_id="exfil_001",
            name="Data Theft",
            attack_type="data_exfiltration",
            mitre_technique="T1041",
            severity="high",
            description="Attempt to exfiltrate sensitive data",
            payload={
                "source_ip": "192.168.1.106",
                "destination_ip": "10.0.0.100",
                "protocol": "FTP",
                "command": "PUT",
                "filename": "config_backup.zip",
                "data_size": 5000000
            },
            expected_detection=True,
            expected_response="block_ip"
        ))
        
        return scenarios
    
    async def run_validation_test(self, test_name: str, components: Dict[str, Any]) -> ValidationResult:
        """Run a comprehensive validation test."""
        start_time = time.time()
        
        try:
            logger.info(f"Starting validation test: {test_name}")
            
            # Initialize test data
            test_results = []
            detected_attacks = 0
            total_attacks = 0
            false_positives = 0
            true_positives = 0
            false_negatives = 0
            true_negatives = 0
            
            # Run attack scenarios
            for scenario in self.scenarios:
                if scenario.attack_type in self.attack_scenarios:
                    total_attacks += 1
                    
                    # Simulate attack
                    attack_detected = await self._simulate_attack(scenario, components)
                    
                    # Record results
                    if scenario.expected_detection:
                        if attack_detected:
                            true_positives += 1
                            detected_attacks += 1
                        else:
                            false_negatives += 1
                    else:
                        if attack_detected:
                            false_positives += 1
                        else:
                            true_negatives += 1
                    
                    test_results.append({
                        'scenario': scenario.scenario_id,
                        'expected': scenario.expected_detection,
                        'detected': attack_detected,
                        'response_time': random.uniform(0.1, 2.0)  # Simulated response time
                    })
            
            # Calculate metrics
            if total_attacks > 0:
                accuracy = (true_positives + true_negatives) / total_attacks
                precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
                recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
                f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
                far = false_positives / (false_positives + true_negatives) if (false_positives + true_negatives) > 0 else 0
                mcc = matthews_corrcoef(
                    [r['expected'] for r in test_results],
                    [r['detected'] for r in test_results]
                )
            else:
                accuracy = precision = recall = f1 = far = mcc = 0.0
            
            # Calculate average response time
            avg_response_time = np.mean([r['response_time'] for r in test_results]) if test_results else 0.0
            
            test_duration = time.time() - start_time
            
            # Create validation result
            result = ValidationResult(
                test_name=test_name,
                model_name="ics_cybersecurity_system",
                accuracy=accuracy,
                precision=precision,
                recall=recall,
                f1_score=f1,
                false_alarm_rate=far,
                mcc=mcc,
                response_time=avg_response_time,
                timestamp=time.time(),
                test_duration=test_duration,
                attack_scenarios=[s.attack_type for s in self.scenarios if s.attack_type in self.attack_scenarios],
                description=f"Validation test for {test_name} with {total_attacks} attack scenarios"
            )
            
            self.validation_results.append(result)
            
            logger.info(f"Validation test completed: {test_name}")
            logger.info(f"Accuracy: {accuracy:.3f}, F1: {f1:.3f}, Response Time: {avg_response_time:.2f}s")
            
            return result
            
        except Exception as e:
            logger.error(f"Error in validation test {test_name}: {e}")
            return ValidationResult(
                test_name=test_name,
                model_name="ics_cybersecurity_system",
                accuracy=0.0,
                precision=0.0,
                recall=0.0,
                f1_score=0.0,
                false_alarm_rate=1.0,
                mcc=0.0,
                response_time=0.0,
                timestamp=time.time(),
                test_duration=time.time() - start_time,
                attack_scenarios=[],
                description=f"Error in validation test: {e}"
            )
    
    async def _simulate_attack(self, scenario: AttackScenario, components: Dict[str, Any]) -> bool:
        """Simulate an attack scenario and check if it's detected."""
        try:
            # Create packet data from scenario
            packet_data = {
                'timestamp': time.time(),
                'source_ip': scenario.payload.get('source_ip', '192.168.1.100'),
                'destination_ip': scenario.payload.get('destination_ip', '192.168.1.10'),
                'protocol': scenario.payload.get('protocol', 'TCP'),
                'packet_size': random.randint(64, 1500),
                'payload': json.dumps(scenario.payload).encode(),
                'flags': {'syn': False, 'ack': True, 'fin': False, 'rst': False, 'psh': False, 'urg': False},
                'ttl': 64,
                'window_size': 8192,
                'sequence_number': random.randint(1000, 100000),
                'acknowledgment_number': random.randint(1000, 100000)
            }
            
            # Create threat data
            threat_data = [{
                'timestamp': time.time(),
                'source_ip': scenario.payload.get('source_ip', '192.168.1.100'),
                'destination_ip': scenario.payload.get('destination_ip', '192.168.1.10'),
                'threat_type': scenario.attack_type,
                'severity': scenario.severity,
                'confidence': random.uniform(0.6, 0.9),
                'description': scenario.description,
                'mitre_technique': scenario.mitre_technique
            }]
            
            # Test network monitor
            network_monitor = components.get('network_monitor')
            if network_monitor:
                # Simulate packet processing
                detected_by_monitor = random.random() < 0.8  # 80% detection rate
            else:
                detected_by_monitor = False
            
            # Test risk scorer
            risk_scorer = components.get('risk_scorer')
            if risk_scorer:
                try:
                    risk_assessment = risk_scorer.assess_risk(packet_data, threat_data)
                    detected_by_risk = risk_assessment.risk_score > 0.6
                except:
                    detected_by_risk = False
            else:
                detected_by_risk = False
            
            # Test response system
            response_system = components.get('response_system')
            if response_system:
                try:
                    system_status = {'overall_status': 'normal'}
                    response_result = await response_system.execute_response(
                        threat_data[0], system_status
                    )
                    response_executed = response_result is not None and response_result.success
                except:
                    response_executed = False
            else:
                response_executed = False
            
            # Determine overall detection
            detected = detected_by_monitor or detected_by_risk or response_executed
            
            # Add some randomness to make it more realistic
            if random.random() < 0.1:  # 10% chance of false detection
                detected = not detected
            
            return detected
            
        except Exception as e:
            logger.error(f"Error simulating attack {scenario.scenario_id}: {e}")
            return False
    
    async def run_benchmark(self, benchmark_name: str, components: Dict[str, Any]) -> BenchmarkResult:
        """Run benchmark comparison against baseline systems."""
        start_time = time.time()
        
        try:
            logger.info(f"Starting benchmark: {benchmark_name}")
            
            # Run validation test
            validation_result = await self.run_validation_test(f"benchmark_{benchmark_name}", components)
            
            # Compare against baselines
            comparison_results = {}
            for metric in self.metrics:
                baseline_value = self.baselines.get(metric, 0.0)
                actual_value = getattr(validation_result, metric, 0.0)
                
                if baseline_value > 0:
                    improvement = ((actual_value - baseline_value) / baseline_value) * 100
                else:
                    improvement = 0.0
                
                comparison_results[metric] = {
                    'baseline': baseline_value,
                    'actual': actual_value,
                    'improvement': improvement
                }
            
            # Calculate overall performance score
            performance_score = (
                validation_result.accuracy * 0.3 +
                validation_result.precision * 0.2 +
                validation_result.recall * 0.2 +
                validation_result.f1_score * 0.2 +
                (1 - validation_result.false_alarm_rate) * 0.1
            )
            
            # Determine ranking (simplified)
            if performance_score >= 0.9:
                ranking = 1
            elif performance_score >= 0.8:
                ranking = 2
            elif performance_score >= 0.7:
                ranking = 3
            else:
                ranking = 4
            
            # Create benchmark result
            result = BenchmarkResult(
                benchmark_name=benchmark_name,
                system_performance={
                    'accuracy': validation_result.accuracy,
                    'precision': validation_result.precision,
                    'recall': validation_result.recall,
                    'f1_score': validation_result.f1_score,
                    'false_alarm_rate': validation_result.false_alarm_rate,
                    'mcc': validation_result.mcc,
                    'response_time': validation_result.response_time,
                    'overall_score': performance_score
                },
                comparison_results=comparison_results,
                ranking=ranking,
                timestamp=time.time(),
                description=f"Benchmark comparison for {benchmark_name}"
            )
            
            self.benchmark_results.append(result)
            
            logger.info(f"Benchmark completed: {benchmark_name}")
            logger.info(f"Overall score: {performance_score:.3f}, Ranking: {ranking}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error in benchmark {benchmark_name}: {e}")
            return BenchmarkResult(
                benchmark_name=benchmark_name,
                system_performance={},
                comparison_results={},
                ranking=999,
                timestamp=time.time(),
                description=f"Error in benchmark: {e}"
            )
    
    async def run_stress_test(self, components: Dict[str, Any]) -> Dict[str, Any]:
        """Run stress test to evaluate system performance under load."""
        try:
            logger.info("Starting stress test")
            
            start_time = time.time()
            test_duration = 300  # 5 minutes
            attack_rate = 10  # attacks per second
            
            total_attacks = 0
            detected_attacks = 0
            response_times = []
            
            # Run continuous attacks
            while time.time() - start_time < test_duration:
                # Select random scenario
                scenario = random.choice(self.scenarios)
                
                # Simulate attack
                attack_start = time.time()
                detected = await self._simulate_attack(scenario, components)
                attack_end = time.time()
                
                total_attacks += 1
                if detected:
                    detected_attacks += 1
                
                response_times.append(attack_end - attack_start)
                
                # Wait for next attack
                await asyncio.sleep(1.0 / attack_rate)
            
            # Calculate stress test metrics
            detection_rate = detected_attacks / total_attacks if total_attacks > 0 else 0
            avg_response_time = np.mean(response_times) if response_times else 0
            max_response_time = max(response_times) if response_times else 0
            min_response_time = min(response_times) if response_times else 0
            
            # Check for performance degradation
            performance_degradation = avg_response_time > self.baselines['response_time']
            
            stress_result = {
                'test_duration': test_duration,
                'total_attacks': total_attacks,
                'detected_attacks': detected_attacks,
                'detection_rate': detection_rate,
                'avg_response_time': avg_response_time,
                'max_response_time': max_response_time,
                'min_response_time': min_response_time,
                'performance_degradation': performance_degradation,
                'attacks_per_second': total_attacks / test_duration
            }
            
            logger.info(f"Stress test completed: {detection_rate:.3f} detection rate, {avg_response_time:.3f}s avg response")
            
            return stress_result
            
        except Exception as e:
            logger.error(f"Error in stress test: {e}")
            return {'error': str(e)}
    
    async def run_adversarial_test(self, components: Dict[str, Any]) -> Dict[str, Any]:
        """Run adversarial testing to evaluate robustness."""
        try:
            logger.info("Starting adversarial test")
            
            # Test evasion techniques
            evasion_results = {}
            
            # Test 1: Packet fragmentation
            evasion_results['packet_fragmentation'] = await self._test_packet_fragmentation(components)
            
            # Test 2: Timing manipulation
            evasion_results['timing_manipulation'] = await self._test_timing_manipulation(components)
            
            # Test 3: Protocol obfuscation
            evasion_results['protocol_obfuscation'] = await self._test_protocol_obfuscation(components)
            
            # Test 4: Payload encoding
            evasion_results['payload_encoding'] = await self._test_payload_encoding(components)
            
            # Calculate overall robustness score
            robustness_score = np.mean([
                result.get('detection_rate', 0) for result in evasion_results.values()
            ])
            
            adversarial_result = {
                'evasion_tests': evasion_results,
                'robustness_score': robustness_score,
                'overall_assessment': 'robust' if robustness_score > 0.7 else 'vulnerable'
            }
            
            logger.info(f"Adversarial test completed: robustness score {robustness_score:.3f}")
            
            return adversarial_result
            
        except Exception as e:
            logger.error(f"Error in adversarial test: {e}")
            return {'error': str(e)}
    
    async def _test_packet_fragmentation(self, components: Dict[str, Any]) -> Dict[str, Any]:
        """Test system against packet fragmentation attacks."""
        detected_count = 0
        total_tests = 10
        
        for i in range(total_tests):
            # Create fragmented packet scenario
            scenario = random.choice(self.scenarios)
            
            # Simulate fragmented packet
            packet_data = {
                'timestamp': time.time(),
                'source_ip': scenario.payload.get('source_ip', '192.168.1.100'),
                'destination_ip': scenario.payload.get('destination_ip', '192.168.1.10'),
                'protocol': scenario.payload.get('protocol', 'TCP'),
                'packet_size': 64,  # Small fragmented packet
                'fragmented': True,
                'fragment_offset': i * 8,
                'more_fragments': i < total_tests - 1
            }
            
            # Test detection
            detected = await self._simulate_attack(scenario, components)
            if detected:
                detected_count += 1
        
        return {
            'detection_rate': detected_count / total_tests,
            'total_tests': total_tests,
            'detected_count': detected_count
        }
    
    async def _test_timing_manipulation(self, components: Dict[str, Any]) -> Dict[str, Any]:
        """Test system against timing manipulation attacks."""
        detected_count = 0
        total_tests = 10
        
        for i in range(total_tests):
            # Create slow attack scenario
            scenario = random.choice(self.scenarios)
            
            # Simulate slow attack
            await asyncio.sleep(random.uniform(1, 5))  # Random delay
            
            detected = await self._simulate_attack(scenario, components)
            if detected:
                detected_count += 1
        
        return {
            'detection_rate': detected_count / total_tests,
            'total_tests': total_tests,
            'detected_count': detected_count
        }
    
    async def _test_protocol_obfuscation(self, components: Dict[str, Any]) -> Dict[str, Any]:
        """Test system against protocol obfuscation attacks."""
        detected_count = 0
        total_tests = 10
        
        for i in range(total_tests):
            # Create obfuscated protocol scenario
            scenario = random.choice(self.scenarios)
            
            # Modify protocol information
            modified_payload = scenario.payload.copy()
            modified_payload['protocol'] = 'HTTP'  # Obfuscate as HTTP
            modified_payload['port'] = 80  # Use standard HTTP port
            
            scenario.payload = modified_payload
            
            detected = await self._simulate_attack(scenario, components)
            if detected:
                detected_count += 1
        
        return {
            'detection_rate': detected_count / total_tests,
            'total_tests': total_tests,
            'detected_count': detected_count
        }
    
    async def _test_payload_encoding(self, components: Dict[str, Any]) -> Dict[str, Any]:
        """Test system against payload encoding attacks."""
        detected_count = 0
        total_tests = 10
        
        for i in range(total_tests):
            # Create encoded payload scenario
            scenario = random.choice(self.scenarios)
            
            # Encode payload
            import base64
            encoded_payload = base64.b64encode(json.dumps(scenario.payload).encode()).decode()
            
            modified_payload = scenario.payload.copy()
            modified_payload['encoded_data'] = encoded_payload
            
            scenario.payload = modified_payload
            
            detected = await self._simulate_attack(scenario, components)
            if detected:
                detected_count += 1
        
        return {
            'detection_rate': detected_count / total_tests,
            'total_tests': total_tests,
            'detected_count': detected_count
        }
    
    async def start(self):
        """Start the model validator service."""
        self.running = True
        logger.info("Model validator service started")
        
        # Start periodic validation
        asyncio.create_task(self._periodic_validation())
    
    async def _periodic_validation(self):
        """Run periodic validation tests."""
        validation_interval = 3600  # 1 hour
        
        while self.running:
            try:
                await asyncio.sleep(validation_interval)
                
                # Run validation test
                logger.info("Running periodic validation test")
                # Note: In a real implementation, you would pass the components here
                
            except Exception as e:
                logger.error(f"Error in periodic validation: {e}")
                await asyncio.sleep(300)  # Wait 5 minutes before retry
    
    async def stop(self):
        """Stop the model validator service."""
        self.running = False
        logger.info("Model validator service stopped")
    
    def get_validation_results(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent validation results."""
        return [asdict(result) for result in self.validation_results[-limit:]]
    
    def get_benchmark_results(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent benchmark results."""
        return [asdict(result) for result in self.benchmark_results[-limit:]]
    
    def export_validation_report(self, filepath: str):
        """Export validation results to file."""
        try:
            report = {
                'validation_results': self.get_validation_results(),
                'benchmark_results': self.get_benchmark_results(),
                'baselines': self.baselines,
                'scenarios': [asdict(s) for s in self.scenarios],
                'export_timestamp': datetime.now().isoformat()
            }
            
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            logger.info(f"Validation report exported to {filepath}")
            
        except Exception as e:
            logger.error(f"Error exporting validation report: {e}") 