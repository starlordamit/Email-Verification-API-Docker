#!/usr/bin/env python3
"""
Comprehensive Email Verification API Test Suite
Tests all endpoints and functionality of the production-ready API
"""

import requests
import json
import time
import sys
from typing import Dict, Any

# API Configuration
BASE_URL = "http://localhost:8080"
TIMEOUT = 10

def test_endpoint(method: str, endpoint: str, data: Dict[Any, Any] = None, description: str = "") -> bool:
    """Test a single API endpoint"""
    url = f"{BASE_URL}{endpoint}"
    
    try:
        print(f"\n🧪 {description}")
        print(f"   {method} {endpoint}")
        
        if method == "GET":
            response = requests.get(url, timeout=TIMEOUT)
        elif method == "POST":
            response = requests.post(url, json=data, timeout=TIMEOUT)
        else:
            response = requests.request(method, url, json=data, timeout=TIMEOUT)
        
        print(f"   Status: {response.status_code}")
        
        try:
            result = response.json()
            print(f"   Response: {json.dumps(result, indent=2)}")
        except:
            print(f"   Response: {response.text[:200]}...")
        
        return 200 <= response.status_code < 300
        
    except requests.exceptions.ConnectionError:
        print(f"   ❌ Connection failed - API server not running")
        return False
    except requests.exceptions.Timeout:
        print(f"   ⏰ Request timeout")
        return False
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

def main():
    """Run comprehensive API tests"""
    print("🚀 Email Verification API v2.0 - Comprehensive Test Suite")
    print("=" * 60)
    
    # Track test results
    tests = []
    
    # Test 1: Health Check
    tests.append(test_endpoint(
        "GET", "/health",
        description="Basic Health Check"
    ))
    
    # Test 2: Deep Health Check
    tests.append(test_endpoint(
        "GET", "/health/deep",
        description="Deep Health Check (with system monitoring)"
    ))
    
    # Test 3: API Documentation
    tests.append(test_endpoint(
        "GET", "/",
        description="API Documentation Root"
    ))
    
    # Test 4: Swagger Documentation
    tests.append(test_endpoint(
        "GET", "/api/docs/",
        description="Swagger API Documentation"
    ))
    
    # Test 5: Single Email Verification - Valid Email
    tests.append(test_endpoint(
        "POST", "/api/v2/verify",
        data={"email": "test@example.com"},
        description="Single Email Verification - Valid Format"
    ))
    
    # Test 6: Single Email Verification - Invalid Email
    tests.append(test_endpoint(
        "POST", "/api/v2/verify",
        data={"email": "invalid-email"},
        description="Single Email Verification - Invalid Format"
    ))
    
    # Test 7: Single Email Verification - Real Domain
    tests.append(test_endpoint(
        "POST", "/api/v2/verify",
        data={"email": "test@gmail.com"},
        description="Single Email Verification - Real Domain"
    ))
    
    # Test 8: Bulk Email Verification
    tests.append(test_endpoint(
        "POST", "/api/v2/bulk-verify",
        data={
            "emails": [
                "test@example.com",
                "invalid-email",
                "user@gmail.com",
                "admin@github.com"
            ]
        },
        description="Bulk Email Verification (4 emails)"
    ))
    
    # Test 9: Prometheus Metrics
    tests.append(test_endpoint(
        "GET", "/metrics",
        description="Prometheus Metrics Endpoint"
    ))
    
    # Test 10: System Stats
    tests.append(test_endpoint(
        "GET", "/stats",
        description="System Statistics"
    ))
    
    # Test 11: Error Handling - Missing Data
    tests.append(test_endpoint(
        "POST", "/api/v2/verify",
        data={},
        description="Error Handling - Missing Email Field"
    ))
    
    # Test 12: Error Handling - Invalid JSON
    try:
        print(f"\n🧪 Error Handling - Invalid JSON")
        print(f"   POST /api/v2/verify")
        response = requests.post(f"{BASE_URL}/api/v2/verify", data="invalid json", timeout=TIMEOUT)
        print(f"   Status: {response.status_code}")
        tests.append(400 <= response.status_code < 500)
    except Exception as e:
        print(f"   ❌ Error: {e}")
        tests.append(False)
    
    # Results Summary
    print("\n" + "=" * 60)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 60)
    
    passed = sum(tests)
    total = len(tests)
    
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {total - passed}")
    print(f"📈 Success Rate: {(passed/total)*100:.1f}%")
    
    if passed == total:
        print("🎉 ALL TESTS PASSED! API is fully functional.")
        return 0
    else:
        print("⚠️  Some tests failed. Check the API server logs.")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 