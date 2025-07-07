#!/usr/bin/env python3
"""
Quick Test Script for Email Verification API
Run this to verify the API is working correctly
"""

import requests
import json
import time

API_URL = "http://localhost:5004"

def test_api():
    """Quick test of all major API functions"""
    print("🚀 Email Verification API - Quick Test")
    print("=" * 50)
    
    # Test 1: Health Check
    print("\n1️⃣ Testing Health Check...")
    try:
        response = requests.get(f"{API_URL}/health", timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Health: {data.get('status')}")
            print(f"   Version: {data.get('version')}")
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Cannot connect to API: {e}")
        print("💡 Make sure the API is running: python app.py")
        return False
    
    # Test 2: Single Email Verification
    print("\n2️⃣ Testing Single Email Verification...")
    test_email = "test@gmail.com"
    
    try:
        response = requests.post(
            f"{API_URL}/api/v2/verify",
            json={"email": test_email},
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            result = data.get('result', {})
            
            print(f"✅ Email: {test_email}")
            print(f"   Valid: {result.get('is_valid')}")
            print(f"   Provider: {result.get('provider')}")
            print(f"   Confidence: {result.get('confidence_score', 0):.2f}")
        else:
            print(f"❌ Single verification failed: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Single verification error: {e}")
        return False
    
    # Test 3: Bulk Verification
    print("\n3️⃣ Testing Bulk Email Verification...")
    test_emails = ["user@gmail.com", "admin@yahoo.com"]
    
    try:
        response = requests.post(
            f"{API_URL}/api/v2/bulk-verify",
            json={"emails": test_emails},
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            summary = data.get('summary', {})
            
            print(f"✅ Bulk verification:")
            print(f"   Processed: {summary.get('total_processed', 0)}")
            print(f"   Valid: {summary.get('valid_emails', 0)}")
            print(f"   Success Rate: {summary.get('success_rate', '0%')}")
        else:
            print(f"❌ Bulk verification failed: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Bulk verification error: {e}")
        return False
    
    # Test 4: API Documentation
    print("\n4️⃣ Testing API Documentation...")
    try:
        response = requests.get(f"{API_URL}/", timeout=10)
        if response.status_code == 200:
            print("✅ API documentation accessible")
        else:
            print(f"⚠️ Documentation returned: {response.status_code}")
    except Exception as e:
        print(f"⚠️ Documentation test failed: {e}")
    
    print("\n🎉 All tests completed successfully!")
    print("\n📚 Next Steps:")
    print(f"   • API Documentation: {API_URL}/")
    print(f"   • Interactive Docs: {API_URL}/api/docs/")
    print(f"   • Health Check: {API_URL}/health")
    print("   • Run examples: python examples/basic_usage.py")
    
    return True

if __name__ == "__main__":
    test_api() 