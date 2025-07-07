#!/usr/bin/env python3
"""
Demo script to showcase the new user information extraction feature
This runs independently to demonstrate the functionality
"""

from user_info import user_info_extractor
import json

def demo_user_info_extraction():
    """Demonstrate user information extraction with sample emails"""
    
    print("🚀 User Information Extraction Demo")
    print("="*50)
    print("This demonstrates the new feature that extracts:")
    print("• Names from email patterns")
    print("• Profile pictures via Gravatar")
    print("• Professional vs personal email detection")
    print("• Social media profile suggestions")
    print("• Domain type classification")
    print()
    
    # Test emails with different patterns
    test_emails = [
        "john.doe@gmail.com",
        "sarah.wilson@company.com",
        "mike_johnson@hotmail.com",
        "info@example.org",
        "JohnSmith@protonmail.com",
        "alice.cooper@yahoo.com"
    ]
    
    for i, email in enumerate(test_emails, 1):
        print(f"{i}. Testing: {email}")
        print("-" * 40)
        
        try:
            # Extract user information
            user_info = user_info_extractor.extract_user_info(email)
            
            # Display results
            extracted = user_info.get('extracted_info', {})
            
            # Names
            names = extracted.get('names', {})
            if names.get('first_name'):
                print(f"   👤 Name: {names.get('full_name', names['first_name'])}")
                print(f"   🔧 Extraction: {names.get('extraction_method', 'unknown')}")
            else:
                print(f"   👤 Name: Not extracted")
            
            # Profile Picture
            profile_pic = extracted.get('profile_picture', {})
            if profile_pic.get('has_gravatar'):
                print(f"   🖼️  Gravatar: Available ✅")
                print(f"   🔗 Avatar: {profile_pic['avatar_url']}")
            else:
                print(f"   🖼️  Gravatar: Not found ❌")
            
            # Professional Info
            prof_info = extracted.get('professional_info', {})
            print(f"   💼 Type: {prof_info.get('email_type', 'unknown').title()}")
            if prof_info.get('role_indicators'):
                print(f"   🏷️  Role: {', '.join(prof_info['role_indicators'])}")
            
            # Domain Info
            domain_info = extracted.get('domain_info', {})
            if domain_info.get('platform'):
                print(f"   🌐 Platform: {domain_info['platform']} ({domain_info.get('type', 'unknown')})")
            
            # Social Profiles
            social_info = extracted.get('social_profiles', {})
            potential_profiles = social_info.get('potential_profiles', [])
            if potential_profiles:
                print(f"   📱 Potential Profiles:")
                for profile in potential_profiles[:3]:  # Show first 3
                    print(f"      - {profile['platform']}: {profile['url']}")
            
            print(f"   📊 Confidence: {user_info.get('confidence_score', 0.0)}")
            
        except Exception as e:
            print(f"   ❌ Error: {e}")
        
        print()
    
    print("="*50)
    print("✨ Feature Summary:")
    print("• Name extraction works with patterns like firstname.lastname@domain.com")
    print("• Gravatar integration provides profile pictures when available")
    print("• Professional email detection identifies corporate vs personal emails")
    print("• Social profile suggestions help find associated accounts")
    print("• Confidence scoring indicates reliability of extracted information")
    print("• All extraction is done efficiently with minimal API calls")

def demo_json_output():
    """Show complete JSON structure for integration"""
    print("\n" + "="*50)
    print("📋 Complete JSON Structure Example")
    print("="*50)
    
    email = "alice.cooper@gmail.com"
    user_info = user_info_extractor.extract_user_info(email)
    
    print("Sample API Response Structure:")
    print(json.dumps(user_info, indent=2))

if __name__ == "__main__":
    demo_user_info_extraction()
    demo_json_output() 