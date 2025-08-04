#!/usr/bin/env python3
"""
Simple API Test Script for ICS Cybersecurity System
Tests the API endpoints to ensure they're working correctly.
"""

import requests
import json
import time
from typing import Dict, Any

class APITester:
    def __init__(self, base_url: str = "http://localhost:8000", api_key: str = "test-api-key-123"):
        self.base_url = base_url
        self.api_key = api_key
        self.headers = {"Authorization": f"Bearer {api_key}"}
    
    def test_endpoint(self, endpoint: str, method: str = "GET", data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Test an API endpoint."""
        url = f"{self.base_url}{endpoint}"
        
        try:
            if method == "GET":
                response = requests.get(url, headers=self.headers, timeout=10)
            elif method == "POST":
                response = requests.post(url, headers=self.headers, json=data, timeout=10)
            else:
                return {"success": False, "error": f"Unsupported method: {method}"}
            
            if response.status_code == 200 or response.status_code == 201:
                return {
                    "success": True,
                    "status_code": response.status_code,
                    "data": response.json()
                }
            else:
                return {
                    "success": False,
                    "status_code": response.status_code,
                    "error": response.text
                }
                
        except requests.exceptions.ConnectionError:
            return {"success": False, "error": "Connection failed - API server not running"}
        except requests.exceptions.Timeout:
            return {"success": False, "error": "Request timeout"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def run_tests(self):
        """Run all API tests."""
        print("=" * 60)
        print("ICS Cybersecurity System - API Test Suite")
        print("=" * 60)
        
        tests = [
            ("Health Check", "/health", "GET"),
            ("Root Endpoint", "/", "GET"),
            ("System Status", "/system/status", "GET"),
            ("Get Threats", "/threats?limit=5", "GET"),
            ("Get Risk Scores", "/risk/scores?limit=5", "GET"),
            ("Get Response History", "/response/history?limit=5", "GET"),
            ("Get Attack Graph", "/graph", "GET"),
        ]
        
        results = []
        
        for test_name, endpoint, method in tests:
            print(f"\nTesting: {test_name}")
            print(f"Endpoint: {method} {endpoint}")
            
            result = self.test_endpoint(endpoint, method)
            
            if result["success"]:
                print(f"✅ PASS - Status: {result['status_code']}")
                if "data" in result and isinstance(result["data"], dict):
                    # Show a summary of the response
                    if "statistics" in result["data"]:
                        stats = result["data"]["statistics"]
                        print(f"   Statistics: {stats}")
                    elif "message" in result["data"]:
                        print(f"   Message: {result['data']['message']}")
                    elif len(result["data"]) <= 3:
                        print(f"   Data: {result['data']}")
                    else:
                        print(f"   Data length: {len(result['data'])} items")
            else:
                print(f"❌ FAIL - {result['error']}")
            
            results.append((test_name, result))
        
        # Test creating a new threat
        print(f"\nTesting: Create New Threat")
        print(f"Endpoint: POST /threats")
        
        new_threat = {
            "source_ip": "192.168.1.250",
            "destination_ip": "192.168.1.15",
            "threat_type": "ddos_attack",
            "severity": "critical",
            "confidence": 0.85,
            "description": "Test DDoS attack from API test"
        }
        
        result = self.test_endpoint("/threats", "POST", new_threat)
        
        if result["success"]:
            print(f"✅ PASS - Status: {result['status_code']}")
            if "data" in result and "threat" in result["data"]:
                threat = result["data"]["threat"]
                print(f"   Created threat ID: {threat.get('id', 'N/A')}")
        else:
            print(f"❌ FAIL - {result['error']}")
        
        results.append(("Create Threat", result))
        
        # Summary
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        
        passed = sum(1 for _, result in results if result["success"])
        total = len(results)
        
        print(f"Total Tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {total - passed}")
        print(f"Success Rate: {(passed/total)*100:.1f}%")
        
        if passed == total:
            print("\n🎉 ALL TESTS PASSED! API is working correctly.")
        else:
            print(f"\n⚠️  {total - passed} test(s) failed.")
            print("\nFailed tests:")
            for test_name, result in results:
                if not result["success"]:
                    print(f"  ❌ {test_name}: {result['error']}")
        
        return passed == total

def main():
    """Main function."""
    print("🚀 Starting ICS Cybersecurity System API Tests...")
    print("Make sure the API server is running: python simple_api_server.py")
    print("-" * 50)
    
    # Wait a moment for user to start server if needed
    time.sleep(2)
    
    tester = APITester()
    success = tester.run_tests()
    
    if success:
        print("\n✅ API testing completed successfully!")
        print("\nYou can now:")
        print("1. Access the API documentation at: http://localhost:8000/docs")
        print("2. Use the API with tools like Postman or curl")
        print("3. Integrate with other systems")
    else:
        print("\n❌ API testing failed!")
        print("\nTroubleshooting:")
        print("1. Make sure the API server is running: python simple_api_server.py")
        print("2. Check if port 8000 is available")
        print("3. Verify the API key is correct: test-api-key-123")

if __name__ == "__main__":
    main() 