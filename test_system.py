#!/usr/bin/env python3
"""
Comprehensive Test Script for ICS Cybersecurity System
This script handles all steps for testing the system:
1. Environment validation
2. System initialization
3. Component testing
4. API testing
5. Dashboard testing
6. Performance validation
7. Cleanup
"""
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.graph_analysis.attack_graph import Node, Edge

import asyncio
import sys
import os
import time
import signal
import subprocess
import requests
import json
import threading
from pathlib import Path
from typing import Dict, List, Any
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('test_run.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class ICSTestRunner:
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.test_results = {}
        self.system_process = None
        self.api_base_url = "http://localhost:8000"
        self.dashboard_url = "http://localhost:8050"
        self.api_key = "test-api-key-123"
        
    def log_test(self, test_name: str, success: bool, message: str = ""):
        """Log test results"""
        status = "✅ PASS" if success else "❌ FAIL"
        logger.info(f"{status} {test_name}: {message}")
        self.test_results[test_name] = {"success": success, "message": message}
        
    def test_environment(self) -> bool:
        """Test 1: Environment and Dependencies"""
        logger.info("=" * 60)
        logger.info("TEST 1: Environment and Dependencies")
        logger.info("=" * 60)
        
        try:
            # Check Python version
            python_version = sys.version_info
            if python_version.major == 3 and python_version.minor >= 8:
                self.log_test("Python Version", True, f"Python {python_version.major}.{python_version.minor}.{python_version.micro}")
            else:
                self.log_test("Python Version", False, f"Python {python_version.major}.{python_version.minor}.{python_version.micro} (requires 3.8+)")
                return False
            
            # Check required files
            required_files = [
                "main.py",
                "requirements.txt",
                "config/settings.py",
                "config/settings.yaml",
                "src/data_collection/network_monitor.py",
                "src/graph_analysis/attack_graph.py",
                "src/risk_assessment/ml_risk_scorer.py",
                "src/threat_mitigation/response_system.py",
                "src/dashboard/app.py",
                "src/api/main.py",
                "src/validation/model_validator.py",
                "scripts/init_database.py",
                "tests/test_system.py"
            ]
            
            for file_path in required_files:
                if (self.base_dir / file_path).exists():
                    self.log_test(f"File Check: {file_path}", True)
                else:
                    self.log_test(f"File Check: {file_path}", False, f"Missing: {file_path}")
                    return False
            
            # Check virtual environment
            if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
                self.log_test("Virtual Environment", True, "Virtual environment detected")
            else:
                self.log_test("Virtual Environment", False, "No virtual environment detected")
                logger.warning("⚠️  It's recommended to use a virtual environment")
            
            # Test imports
            try:
                import fastapi
                import dash
                import networkx
                import sklearn
                import pandas
                import numpy
                import yaml
                import pydantic
                import loguru
                import asyncio
                import aiohttp
                self.log_test("Core Dependencies", True, "All core dependencies imported successfully")
            except ImportError as e:
                self.log_test("Core Dependencies", False, f"Import error: {e}")
                return False
            
            return True
            
        except Exception as e:
            self.log_test("Environment Test", False, f"Unexpected error: {e}")
            return False
    
    def test_configuration(self) -> bool:
        """Test 2: Configuration Loading"""
        logger.info("=" * 60)
        logger.info("TEST 2: Configuration Loading")
        logger.info("=" * 60)
        
        try:
            # Test configuration loading
            sys.path.insert(0, str(self.base_dir))
            from config.settings import load_config
            
            config = load_config()
            
            # Check required config sections
            required_sections = ['network', 'graph', 'ml', 'mitigation', 'api', 'dashboard', 'validation']
            for section in required_sections:
                if section in config:
                    self.log_test(f"Config Section: {section}", True)
                else:
                    self.log_test(f"Config Section: {section}", False, f"Missing section: {section}")
                    return False
            
            # Test specific config values
            if config['api']['port'] == 8000:
                self.log_test("API Port Config", True, f"Port: {config['api']['port']}")
            else:
                self.log_test("API Port Config", False, f"Unexpected port: {config['api']['port']}")
            
            if config['dashboard']['port'] == 8050:
                self.log_test("Dashboard Port Config", True, f"Port: {config['dashboard']['port']}")
            else:
                self.log_test("Dashboard Port Config", False, f"Unexpected port: {config['dashboard']['port']}")
            
            return True
            
        except Exception as e:
            self.log_test("Configuration Test", False, f"Error: {e}")
            return False
    
    def test_initialization(self) -> bool:
        """Test 3: System Initialization"""
        logger.info("=" * 60)
        logger.info("TEST 3: System Initialization")
        logger.info("=" * 60)
        
        try:
            # Run initialization script
            init_script = self.base_dir / "scripts" / "init_database.py"
            if init_script.exists():
                result = subprocess.run([sys.executable, str(init_script)], 
                                      capture_output=True, text=True, cwd=self.base_dir)
                
                if result.returncode == 0:
                    self.log_test("Database Initialization", True, "Initialization script completed")
                else:
                    self.log_test("Database Initialization", False, f"Script failed: {result.stderr}")
                    return False
            else:
                self.log_test("Database Initialization", False, "Initialization script not found")
                return False
            
            # Check if directories were created
            required_dirs = ['logs', 'models', 'exports', 'data']
            for dir_name in required_dirs:
                dir_path = self.base_dir / dir_name
                if dir_path.exists():
                    self.log_test(f"Directory Creation: {dir_name}", True)
                else:
                    self.log_test(f"Directory Creation: {dir_name}", False, f"Directory not created: {dir_name}")
            
            return True
            
        except Exception as e:
            self.log_test("Initialization Test", False, f"Error: {e}")
            return False
    
    def test_components(self) -> bool:
        """Test 4: Individual Component Testing"""
        logger.info("=" * 60)
        logger.info("TEST 4: Individual Component Testing")
        logger.info("=" * 60)
        
        try:
            # Test network monitor
            from src.data_collection.network_monitor import NetworkMonitor
            from config.settings import load_config
            
            config = load_config()
            monitor = NetworkMonitor(config['network'])
            
            # Test packet analysis
            packet_data = {
                'timestamp': 1234567890,
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
            
            threat = monitor._analyze_packet(monitor._extract_packet_data(packet_data))
            self.log_test("Network Monitor - Packet Analysis", True, f"Threat detected: {threat is not None}")
            
            # Test attack graph
            from src.graph_analysis.attack_graph import AttackGraphAnalyzer
            
            graph_analyzer = AttackGraphAnalyzer(config['graph'])
            nodes = graph_analyzer.get_nodes()
            edges = graph_analyzer.get_edges()
            
            self.log_test("Attack Graph - Node Count", True, f"Nodes: {len(nodes)}")
            self.log_test("Attack Graph - Edge Count", True, f"Edges: {len(edges)}")
            
            # Test ML risk scorer
            from src.risk_assessment.ml_risk_scorer import MLRiskScorer
            
            risk_scorer = MLRiskScorer(config['ml'])
            risk_score = risk_scorer.calculate_risk_score({
                'source_ip': '192.168.1.100',
                'threat_type': 'port_scan',
                'severity': 'medium'
            })
            
            self.log_test("ML Risk Scorer", True, f"Risk score calculated: {risk_score}")
            
            # Test threat response
            from src.threat_mitigation.response_system import ThreatResponseSystem
            
            response_system = ThreatResponseSystem(config['mitigation'])
            response = response_system.get_response_strategy('port_scan', 'medium')
            
            self.log_test("Threat Response System", True, f"Response strategy: {response['action']}")
            
            return True
            
        except Exception as e:
            self.log_test("Component Test", False, f"Error: {e}")
            return False
    
    def start_system(self) -> bool:
        """Start the main system"""
        try:
            logger.info("Starting ICS Cybersecurity System...")
            self.system_process = subprocess.Popen(
                [sys.executable, "main.py"],
                cwd=self.base_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait for system to start
            time.sleep(10)
            
            if self.system_process.poll() is None:
                self.log_test("System Startup", True, "System process started successfully")
                return True
            else:
                stdout, stderr = self.system_process.communicate()
                self.log_test("System Startup", False, f"System failed to start: {stderr.decode()}")
                return False
                
        except Exception as e:
            self.log_test("System Startup", False, f"Error: {e}")
            return False
    
    def test_api(self) -> bool:
        """Test 5: API Testing"""
        logger.info("=" * 60)
        logger.info("TEST 5: API Testing")
        logger.info("=" * 60)
        
        try:
            # Test API health endpoint
            try:
                response = requests.get(f"{self.api_base_url}/health", timeout=5)
                if response.status_code == 200:
                    self.log_test("API Health Check", True, "Health endpoint responding")
                else:
                    self.log_test("API Health Check", False, f"Status code: {response.status_code}")
                    return False
            except requests.exceptions.RequestException as e:
                self.log_test("API Health Check", False, f"Connection error: {e}")
                return False
            
            # Test API with authentication
            headers = {"Authorization": f"Bearer {self.api_key}"}
            
            # Test root endpoint
            response = requests.get(f"{self.api_base_url}/", headers=headers, timeout=5)
            if response.status_code == 200:
                self.log_test("API Root Endpoint", True, "Root endpoint accessible")
            else:
                self.log_test("API Root Endpoint", False, f"Status code: {response.status_code}")
            
            # Test threats endpoint
            response = requests.get(f"{self.api_base_url}/threats?limit=5", headers=headers, timeout=5)
            if response.status_code == 200:
                threats = response.json()
                self.log_test("API Threats Endpoint", True, f"Retrieved {len(threats)} threats")
            else:
                self.log_test("API Threats Endpoint", False, f"Status code: {response.status_code}")
            
            # Test threat creation
            threat_data = {
                'source_ip': '192.168.1.200',
                'destination_ip': '192.168.1.10',
                'threat_type': 'port_scan',
                'severity': 'medium',
                'confidence': 0.8,
                'description': 'Test port scan from test script',
                'mitre_technique': 'T1595.001'
            }
            
            response = requests.post(
                f"{self.api_base_url}/threats",
                headers={**headers, "Content-Type": "application/json"},
                json=threat_data,
                timeout=5
            )
            
            if response.status_code == 201:
                self.log_test("API Threat Creation", True, "Threat created successfully")
            else:
                self.log_test("API Threat Creation", False, f"Status code: {response.status_code}")
            
            # Test risk assessment endpoint
            response = requests.get(f"{self.api_base_url}/risk-assessment", headers=headers, timeout=5)
            if response.status_code == 200:
                risk_data = response.json()
                self.log_test("API Risk Assessment", True, f"Risk score: {risk_data.get('overall_risk', 'N/A')}")
            else:
                self.log_test("API Risk Assessment", False, f"Status code: {response.status_code}")
            
            return True
            
        except Exception as e:
            self.log_test("API Test", False, f"Error: {e}")
            return False
    
    def test_dashboard(self) -> bool:
        """Test 6: Dashboard Testing"""
        logger.info("=" * 60)
        logger.info("TEST 6: Dashboard Testing")
        logger.info("=" * 60)
        
        try:
            # Test dashboard accessibility
            response = requests.get(self.dashboard_url, timeout=5)
            if response.status_code == 200:
                self.log_test("Dashboard Accessibility", True, "Dashboard responding")
            else:
                self.log_test("Dashboard Accessibility", False, f"Status code: {response.status_code}")
                return False
            
            # Check if dashboard contains expected content
            if "ICS Cybersecurity Dashboard" in response.text:
                self.log_test("Dashboard Content", True, "Dashboard title found")
            else:
                self.log_test("Dashboard Content", False, "Dashboard title not found")
            
            return True
            
        except requests.exceptions.RequestException as e:
            self.log_test("Dashboard Test", False, f"Connection error: {e}")
            return False
        except Exception as e:
            self.log_test("Dashboard Test", False, f"Error: {e}")
            return False
    
    def test_performance(self) -> bool:
        """Test 7: Performance and Validation Testing"""
        logger.info("=" * 60)
        logger.info("TEST 7: Performance and Validation Testing")
        logger.info("=" * 60)
        
        try:
            # Test model validation
            from src.validation.model_validator import ModelValidator
            from config.settings import load_config
            
            config = load_config()
            validator = ModelValidator(config['validation'])
            
            # Test scenario simulation
            if validator.scenarios:
                scenario = validator.scenarios[0]
                components = {}
                detected = asyncio.run(validator._simulate_attack(scenario, components))
                self.log_test("Attack Simulation", True, f"Scenario '{scenario.name}' simulated, detected: {detected}")
            else:
                self.log_test("Attack Simulation", False, "No scenarios available")
            
            # Test performance metrics
            start_time = time.time()
            
            # Simulate multiple API calls
            headers = {"Authorization": f"Bearer {self.api_key}"}
            for i in range(5):
                response = requests.get(f"{self.api_base_url}/threats?limit=1", headers=headers, timeout=5)
                if response.status_code != 200:
                    self.log_test("API Performance", False, f"API call {i+1} failed")
                    return False
            
            end_time = time.time()
            avg_response_time = (end_time - start_time) / 5
            
            if avg_response_time < 2.0:  # Less than 2 seconds average
                self.log_test("API Performance", True, f"Average response time: {avg_response_time:.2f}s")
            else:
                self.log_test("API Performance", False, f"Slow response time: {avg_response_time:.2f}s")
            
            return True
            
        except Exception as e:
            self.log_test("Performance Test", False, f"Error: {e}")
            return False
    
    def cleanup(self):
        """Cleanup resources"""
        logger.info("=" * 60)
        logger.info("CLEANUP: Stopping Services")
        logger.info("=" * 60)
        
        try:
            # Stop the main system process
            if self.system_process and self.system_process.poll() is None:
                self.system_process.terminate()
                try:
                    self.system_process.wait(timeout=10)
                    self.log_test("System Shutdown", True, "System stopped gracefully")
                except subprocess.TimeoutExpired:
                    self.system_process.kill()
                    self.log_test("System Shutdown", False, "System force killed")
            
            # Additional cleanup if needed
            logger.info("Cleanup completed")
            
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
    
    def print_summary(self):
        """Print test summary"""
        logger.info("=" * 60)
        logger.info("TEST SUMMARY")
        logger.info("=" * 60)
        
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results.values() if result["success"])
        failed_tests = total_tests - passed_tests
        
        logger.info(f"Total Tests: {total_tests}")
        logger.info(f"Passed: {passed_tests}")
        logger.info(f"Failed: {failed_tests}")
        logger.info(f"Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        if failed_tests > 0:
            logger.info("\nFailed Tests:")
            for test_name, result in self.test_results.items():
                if not result["success"]:
                    logger.info(f"  ❌ {test_name}: {result['message']}")
        
        if passed_tests == total_tests:
            logger.info("\n🎉 ALL TESTS PASSED! The ICS Cybersecurity System is working correctly.")
        else:
            logger.info(f"\n⚠️  {failed_tests} test(s) failed. Please check the logs for details.")
    
    def run_all_tests(self):
        """Run all tests in sequence"""
        logger.info("🚀 Starting ICS Cybersecurity System Test Suite")
        logger.info(f"Test started at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        try:
            # Test 1: Environment
            if not self.test_environment():
                logger.error("Environment test failed. Stopping tests.")
                return False
            
            # Test 2: Configuration
            if not self.test_configuration():
                logger.error("Configuration test failed. Stopping tests.")
                return False
            
            # Test 3: Initialization
            if not self.test_initialization():
                logger.error("Initialization test failed. Stopping tests.")
                return False
            
            # Test 4: Components
            if not self.test_components():
                logger.error("Component test failed. Stopping tests.")
                return False
            
            # Test 5: Start System
            if not self.start_system():
                logger.error("System startup failed. Stopping tests.")
                return False
            
            # Wait a bit for system to fully start
            time.sleep(5)
            
            # Test 6: API
            if not self.test_api():
                logger.warning("API test failed, but continuing...")
            
            # Test 7: Dashboard
            if not self.test_dashboard():
                logger.warning("Dashboard test failed, but continuing...")
            
            # Test 8: Performance
            if not self.test_performance():
                logger.warning("Performance test failed, but continuing...")
            
            return True
            
        except KeyboardInterrupt:
            logger.info("Test interrupted by user")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during testing: {e}")
            return False
        finally:
            self.cleanup()
            self.print_summary()

def main():
    """Main function"""
    # Set up signal handler for graceful shutdown
    def signal_handler(signum, frame):
        logger.info("Received interrupt signal. Shutting down...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Create and run test suite
    test_runner = ICSTestRunner()
    success = test_runner.run_all_tests()
    
    if success:
        logger.info("✅ Test suite completed successfully!")
        sys.exit(0)
    else:
        logger.error("❌ Test suite failed!")
        sys.exit(1)

if __name__ == "__main__":
    main() 