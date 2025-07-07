#!/usr/bin/env python3
"""
Email Verification API - Basic Usage Examples
Demonstrates common usage patterns for the production API
"""

import requests
import json
import time
from typing import List, Dict, Any

# Configuration
API_BASE_URL = "http://localhost:5004"
API_TIMEOUT = 30

class EmailVerificationClient:
    """Simple client for Email Verification API"""
    
    def __init__(self, base_url: str = API_BASE_URL, api_key: str = None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({'X-API-Key': api_key})
        
    def verify_email(self, email: str) -> Dict[str, Any]:
        """Verify a single email address"""
        url = f"{self.base_url}/api/v2/verify"
        data = {"email": email}
        
        try:
            response = self.session.post(url, json=data, timeout=API_TIMEOUT)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e)}
    
    def bulk_verify(self, emails: List[str]) -> Dict[str, Any]:
        """Verify multiple emails in a single request"""
        url = f"{self.base_url}/api/v2/bulk-verify"
        data = {"emails": emails}
        
        try:
            response = self.session.post(url, json=data, timeout=API_TIMEOUT)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e)}
    
    def health_check(self) -> Dict[str, Any]:
        """Check API health"""
        url = f"{self.base_url}/health"
        
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e)}

def print_verification_result(email: str, result: Dict[str, Any]):
    """Pretty print verification results"""
    print(f"\n📧 Email: {email}")
    print("-" * 50)
    
    if not result.get('success'):
        print(f"❌ Error: {result.get('error', 'Unknown error')}")
        return
    
    data = result.get('result', {})
    
    # Status indicators
    valid = "✅" if data.get('is_valid') else "❌"
    deliverable = "✅" if data.get('is_deliverable') else "❌"
    disposable = "⚠️" if data.get('is_disposable') else "✅"
    role_account = "⚠️" if data.get('is_role_account') else "✅"
    
    print(f"   Format Valid: {valid}")
    print(f"   Deliverable:  {deliverable}")
    print(f"   Not Disposable: {disposable}")
    print(f"   Not Role Account: {role_account}")
    print(f"   Confidence: {data.get('confidence_score', 0):.2f}")
    print(f"   Provider: {data.get('provider', 'Unknown')}")
    
    # Domain info
    domain_info = data.get('domain_info', {})
    if domain_info:
        print(f"   Domain: {domain_info.get('domain', 'Unknown')}")
        print(f"   Has MX: {'✅' if domain_info.get('has_mx') else '❌'}")
    
    # Errors
    errors = data.get('errors', [])
    if errors:
        print(f"   Warnings: {', '.join(errors)}")

def example_1_single_verification():
    """Example 1: Single email verification"""
    print("\n🔍 Example 1: Single Email Verification")
    print("=" * 60)
    
    client = EmailVerificationClient()
    
    # Test different types of emails
    test_emails = [
        "user@gmail.com",           # Valid email
        "admin@yahoo.com",          # Role account  
        "test@10minutemail.com",    # Disposable
        "invalid-email",            # Invalid format
        "fake@nonexistentdomain123.com"  # Non-existent domain
    ]
    
    for email in test_emails:
        result = client.verify_email(email)
        print_verification_result(email, result)
        time.sleep(0.5)  # Be nice to the API

def example_2_bulk_verification():
    """Example 2: Bulk email verification"""
    print("\n📊 Example 2: Bulk Email Verification")
    print("=" * 60)
    
    client = EmailVerificationClient()
    
    # Bulk verification
    emails = [
        "support@github.com",
        "user@outlook.com", 
        "test@guerrillamail.com",
        "valid@protonmail.com",
        "fake@fakefakefake.com"
    ]
    
    print(f"Verifying {len(emails)} emails in bulk...")
    result = client.bulk_verify(emails)
    
    if result.get('success'):
        summary = result.get('summary', {})
        print(f"\n📈 Bulk Verification Summary:")
        print(f"   Total Processed: {summary.get('total_processed', 0)}")
        print(f"   Valid Emails: {summary.get('valid_emails', 0)}")
        print(f"   Deliverable: {summary.get('deliverable_emails', 0)}")
        print(f"   Success Rate: {summary.get('success_rate', '0%')}")
        print(f"   Processing Time: {result.get('processing_time', 'Unknown')}")
        
        # Show individual results
        print(f"\n📋 Individual Results:")
        for item in result.get('results', []):
            email = item.get('email')
            data = item.get('result', {})
            
            status = "✅" if data.get('is_valid') else "❌"
            confidence = data.get('confidence_score', 0)
            provider = data.get('provider', 'Unknown')
            
            print(f"   {status} {email:<30} | {confidence:.2f} | {provider}")
    else:
        print(f"❌ Bulk verification failed: {result.get('error')}")

def example_3_filtering_and_sorting():
    """Example 3: Filter and sort results"""
    print("\n🔍 Example 3: Filtering and Analysis")
    print("=" * 60)
    
    client = EmailVerificationClient()
    
    # Email list to analyze
    email_list = [
        "ceo@company.com",
        "user1@gmail.com",
        "admin@tempmail.com", 
        "marketing@outlook.com",
        "test@protonmail.com",
        "support@yahoo.com",
        "user2@guerrillamail.com",
        "sales@company.com"
    ]
    
    print(f"Analyzing {len(email_list)} emails...")
    
    # Verify all emails
    results = []
    for email in email_list:
        result = client.verify_email(email)
        if result.get('success'):
            results.append({
                'email': email,
                'data': result['result']
            })
        time.sleep(0.2)
    
    # Filter by criteria
    valid_emails = [r for r in results if r['data'].get('is_valid')]
    deliverable_emails = [r for r in results if r['data'].get('is_deliverable')]
    role_accounts = [r for r in results if r['data'].get('is_role_account')]
    disposable_emails = [r for r in results if r['data'].get('is_disposable')]
    high_confidence = [r for r in results if r['data'].get('confidence_score', 0) >= 0.8]
    
    print(f"\n📊 Analysis Results:")
    print(f"   Total Emails: {len(email_list)}")
    print(f"   Valid Format: {len(valid_emails)}")
    print(f"   Deliverable: {len(deliverable_emails)}")
    print(f"   Role Accounts: {len(role_accounts)}")
    print(f"   Disposable: {len(disposable_emails)}")
    print(f"   High Confidence (≥0.8): {len(high_confidence)}")
    
    # Show best emails (high confidence, not role/disposable)
    best_emails = [
        r for r in results 
        if r['data'].get('confidence_score', 0) >= 0.7
        and not r['data'].get('is_role_account')
        and not r['data'].get('is_disposable')
        and r['data'].get('is_valid')
    ]
    
    print(f"\n✨ Recommended Emails ({len(best_emails)}):")
    for result in sorted(best_emails, key=lambda x: x['data']['confidence_score'], reverse=True):
        email = result['email']
        confidence = result['data']['confidence_score']
        provider = result['data'].get('provider', 'Unknown')
        print(f"   ✅ {email:<25} | {confidence:.2f} | {provider}")

def example_4_health_monitoring():
    """Example 4: Health check and monitoring"""
    print("\n🏥 Example 4: Health Monitoring")
    print("=" * 60)
    
    client = EmailVerificationClient()
    
    # Basic health check
    health = client.health_check()
    
    if health.get('status') == 'healthy':
        print("✅ API is healthy")
        print(f"   Version: {health.get('version', 'Unknown')}")
        print(f"   Timestamp: {health.get('timestamp', 'Unknown')}")
        
        services = health.get('services', {})
        print(f"\n🔧 Service Status:")
        for service, status in services.items():
            icon = "✅" if status in ['online', 'running'] else "⚠️"
            print(f"   {icon} {service}: {status}")
    else:
        print("❌ API is not healthy")
        print(f"   Error: {health.get('error', 'Unknown')}")

def main():
    """Run all examples"""
    print("🚀 Email Verification API - Usage Examples")
    print("=" * 60)
    
    try:
        # Check if API is running
        client = EmailVerificationClient()
        health = client.health_check()
        
        if health.get('status') != 'healthy':
            print("❌ API is not running. Please start the API first:")
            print("   python app.py")
            return
        
        print("✅ API is running and healthy!")
        
        # Run examples
        example_1_single_verification()
        example_2_bulk_verification()  
        example_3_filtering_and_sorting()
        example_4_health_monitoring()
        
        print("\n🎉 All examples completed successfully!")
        print("\n💡 Tips:")
        print("   - Use bulk verification for better performance")
        print("   - Check confidence scores for quality filtering")
        print("   - Monitor role accounts and disposable emails")
        print("   - Add Redis for 4x performance improvement")
        
    except KeyboardInterrupt:
        print("\n⚠️ Examples interrupted by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")

if __name__ == "__main__":
    main() 