"""
User Information Extractor for Email Verification API
Extracts profile information, names, and social profiles from email addresses
"""

import hashlib
import re
import requests
import logging
from typing import Dict, Any, Optional, List
from urllib.parse import quote
import json

logger = logging.getLogger(__name__)

class UserInfoExtractor:
    """Extract user information from email addresses"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Email-Verification-API/2.0 (Professional Email Validator)'
        })
        
        # Common name patterns in emails
        self.name_patterns = [
            r'^([a-zA-Z]+)\.([a-zA-Z]+)@',           # firstname.lastname@
            r'^([a-zA-Z]+)_([a-zA-Z]+)@',           # firstname_lastname@
            r'^([a-zA-Z]+)-([a-zA-Z]+)@',           # firstname-lastname@
            r'^([a-zA-Z]+)([a-zA-Z]+)\d*@',         # firstnamelastname@
            r'^([a-zA-Z]{2,})@',                    # just firstname@
        ]
        
        # Social media domain mappings
        self.social_domains = {
            'gmail.com': {'platform': 'Google', 'type': 'email'},
            'yahoo.com': {'platform': 'Yahoo', 'type': 'email'},
            'outlook.com': {'platform': 'Microsoft', 'type': 'email'},
            'hotmail.com': {'platform': 'Microsoft', 'type': 'email'},
            'icloud.com': {'platform': 'Apple', 'type': 'email'},
            'protonmail.com': {'platform': 'ProtonMail', 'type': 'privacy'},
            'tutanota.com': {'platform': 'Tutanota', 'type': 'privacy'},
        }
        
        # Professional email indicators
        self.professional_indicators = [
            'admin', 'info', 'contact', 'support', 'sales', 'marketing',
            'hr', 'team', 'office', 'hello', 'mail', 'noreply', 'no-reply'
        ]

    def extract_user_info(self, email: str) -> Dict[str, Any]:
        """
        Extract comprehensive user information from email address
        
        Args:
            email: Email address to analyze
            
        Returns:
            Dictionary containing user information
        """
        try:
            email = email.lower().strip()
            local_part, domain = email.split('@')
            
            user_info = {
                'email': email,
                'extracted_info': {
                    'names': self._extract_names(local_part),
                    'profile_picture': self._get_gravatar_info(email),
                    'social_profiles': self._detect_social_profiles(email, domain),
                    'professional_info': self._analyze_professional_email(local_part, domain),
                    'domain_info': self._analyze_domain_info(domain)
                },
                'confidence_score': 0.0,
                'extraction_methods': []
            }
            
            # Calculate confidence score
            user_info['confidence_score'] = self._calculate_confidence(user_info)
            
            return user_info
            
        except Exception as e:
            logger.error(f"Error extracting user info for {email}: {e}")
            return {
                'email': email,
                'extracted_info': {},
                'confidence_score': 0.0,
                'extraction_methods': [],
                'error': str(e)
            }

    def _extract_names(self, local_part: str) -> Dict[str, Any]:
        """Extract potential names from email local part"""
        names = {
            'first_name': None,
            'last_name': None,
            'full_name': None,
            'username': local_part,
            'extraction_method': None
        }
        
        # Skip if looks like a professional/system email
        if any(indicator in local_part for indicator in self.professional_indicators):
            names['extraction_method'] = 'professional_email_skipped'
            return names
        
        # Try different name patterns
        for i, pattern in enumerate(self.name_patterns):
            match = re.match(pattern, local_part + '@')
            if match:
                groups = match.groups()
                if len(groups) >= 2:
                    # Two parts found (firstname.lastname pattern)
                    names['first_name'] = groups[0].title()
                    names['last_name'] = groups[1].title()
                    names['full_name'] = f"{names['first_name']} {names['last_name']}"
                    names['extraction_method'] = f'pattern_{i}_two_parts'
                    break
                elif len(groups) == 1 and len(groups[0]) > 2:
                    # Single name found
                    names['first_name'] = groups[0].title()
                    names['full_name'] = names['first_name']
                    names['extraction_method'] = f'pattern_{i}_single_part'
                    break
        
        # If no pattern matched, try to split camelCase or extract first word
        if not names['first_name']:
            names.update(self._extract_from_camelcase(local_part))
        
        return names

    def _extract_from_camelcase(self, local_part: str) -> Dict[str, str]:
        """Extract names from camelCase or other formats"""
        # Try camelCase detection
        camel_match = re.findall(r'[A-Z][a-z]+', local_part)
        if len(camel_match) >= 2:
            return {
                'first_name': camel_match[0],
                'last_name': camel_match[1],
                'full_name': ' '.join(camel_match[:2]),
                'extraction_method': 'camelcase'
            }
        elif len(camel_match) == 1:
            return {
                'first_name': camel_match[0],
                'full_name': camel_match[0],
                'extraction_method': 'camelcase_single'
            }
        
        # Try extracting first meaningful word
        clean_part = re.sub(r'[^a-zA-Z]', '', local_part)
        if len(clean_part) > 2:
            return {
                'first_name': clean_part[:1].upper() + clean_part[1:].lower(),
                'full_name': clean_part[:1].upper() + clean_part[1:].lower(),
                'extraction_method': 'first_word'
            }
        
        return {'extraction_method': 'no_pattern_found'}

    def _get_gravatar_info(self, email: str) -> Dict[str, Any]:
        """Get Gravatar profile information"""
        try:
            # Create MD5 hash of email for Gravatar
            email_hash = hashlib.md5(email.encode('utf-8')).hexdigest()
            
            gravatar_info = {
                'gravatar_hash': email_hash,
                'avatar_url': f"https://www.gravatar.com/avatar/{email_hash}?s=200&d=404",
                'profile_url': f"https://www.gravatar.com/{email_hash}",
                'has_gravatar': False,
                'profile_data': None
            }
            
            # Check if Gravatar exists (without downloading full image)
            try:
                response = self.session.head(
                    f"https://www.gravatar.com/avatar/{email_hash}?d=404",
                    timeout=3
                )
                if response.status_code == 200:
                    gravatar_info['has_gravatar'] = True
                    gravatar_info['avatar_url'] = f"https://www.gravatar.com/avatar/{email_hash}?s=200"
                    
                    # Try to get profile data
                    try:
                        profile_response = self.session.get(
                            f"https://www.gravatar.com/{email_hash}.json",
                            timeout=3
                        )
                        if profile_response.status_code == 200:
                            profile_data = profile_response.json()
                            gravatar_info['profile_data'] = self._parse_gravatar_profile(profile_data)
                    except:
                        pass  # Profile data is optional
                        
            except requests.exceptions.RequestException:
                pass  # Gravatar check failed, but that's ok
            
            return gravatar_info
            
        except Exception as e:
            logger.error(f"Error getting Gravatar info: {e}")
            return {'error': str(e)}

    def _parse_gravatar_profile(self, profile_data: Dict) -> Dict[str, Any]:
        """Parse Gravatar profile data"""
        try:
            entry = profile_data.get('entry', [{}])[0]
            
            parsed = {
                'display_name': entry.get('displayName'),
                'real_name': entry.get('name', {}).get('formatted'),
                'location': entry.get('currentLocation'),
                'bio': entry.get('aboutMe'),
                'urls': [],
                'social_accounts': []
            }
            
            # Extract URLs and social accounts
            for url_entry in entry.get('urls', []):
                url_info = {
                    'title': url_entry.get('title'),
                    'url': url_entry.get('value')
                }
                parsed['urls'].append(url_info)
                
                # Try to identify social platforms
                if url_info['url']:
                    platform = self._identify_social_platform(url_info['url'])
                    if platform:
                        parsed['social_accounts'].append({
                            'platform': platform,
                            'url': url_info['url'],
                            'title': url_info['title']
                        })
            
            return parsed
            
        except Exception as e:
            logger.error(f"Error parsing Gravatar profile: {e}")
            return {}

    def _identify_social_platform(self, url: str) -> Optional[str]:
        """Identify social media platform from URL"""
        social_patterns = {
            'twitter.com': 'Twitter',
            'x.com': 'Twitter/X',
            'linkedin.com': 'LinkedIn',
            'github.com': 'GitHub',
            'facebook.com': 'Facebook',
            'instagram.com': 'Instagram',
            'youtube.com': 'YouTube',
            'medium.com': 'Medium',
            'dev.to': 'Dev.to',
            'stackoverflow.com': 'Stack Overflow'
        }
        
        for domain, platform in social_patterns.items():
            if domain in url.lower():
                return platform
        return None

    def _detect_social_profiles(self, email: str, domain: str) -> Dict[str, Any]:
        """Detect potential social media profiles"""
        local_part = email.split('@')[0]
        
        social_info = {
            'potential_profiles': [],
            'domain_type': self.social_domains.get(domain, {'platform': 'Unknown', 'type': 'personal'}),
            'suggested_searches': []
        }
        
        # Generate potential social media profile URLs
        platforms = {
            'GitHub': f"https://github.com/{local_part}",
            'Twitter': f"https://twitter.com/{local_part}",
            'LinkedIn': f"https://linkedin.com/in/{local_part}",
            'Instagram': f"https://instagram.com/{local_part}",
            'Medium': f"https://medium.com/@{local_part}"
        }
        
        for platform, url in platforms.items():
            social_info['potential_profiles'].append({
                'platform': platform,
                'url': url,
                'confidence': 'low',  # These are just guesses
                'note': 'Potential profile - not verified'
            })
        
        return social_info

    def _analyze_professional_email(self, local_part: str, domain: str) -> Dict[str, Any]:
        """Analyze if this looks like a professional email"""
        professional_info = {
            'is_professional': False,
            'role_indicators': [],
            'company_domain': domain,
            'email_type': 'personal'
        }
        
        # Check for professional indicators
        for indicator in self.professional_indicators:
            if indicator in local_part:
                professional_info['role_indicators'].append(indicator)
        
        # Determine email type
        if professional_info['role_indicators']:
            professional_info['is_professional'] = True
            professional_info['email_type'] = 'role_based'
        elif domain not in ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com']:
            professional_info['is_professional'] = True
            professional_info['email_type'] = 'corporate'
        
        return professional_info

    def _analyze_domain_info(self, domain: str) -> Dict[str, Any]:
        """Analyze domain information"""
        domain_info = {
            'domain': domain,
            'type': 'unknown',
            'platform': None,
            'reputation': 'unknown'
        }
        
        # Categorize domain
        if domain in self.social_domains:
            domain_info.update(self.social_domains[domain])
        elif domain.endswith('.edu'):
            domain_info['type'] = 'educational'
            domain_info['platform'] = 'Educational Institution'
        elif domain.endswith('.gov'):
            domain_info['type'] = 'government'
            domain_info['platform'] = 'Government'
        elif domain.endswith('.org'):
            domain_info['type'] = 'organization'
            domain_info['platform'] = 'Non-profit/Organization'
        else:
            domain_info['type'] = 'corporate'
        
        return domain_info

    def _calculate_confidence(self, user_info: Dict[str, Any]) -> float:
        """Calculate confidence score for extracted information"""
        score = 0.0
        max_score = 0.0
        
        # Name extraction confidence
        names = user_info['extracted_info'].get('names', {})
        if names.get('first_name'):
            if names.get('last_name'):
                score += 0.3  # Full name found
            else:
                score += 0.15  # Only first name
        max_score += 0.3
        
        # Gravatar confidence
        gravatar = user_info['extracted_info'].get('profile_picture', {})
        if gravatar.get('has_gravatar'):
            score += 0.4
            if gravatar.get('profile_data'):
                score += 0.2
        max_score += 0.6
        
        # Professional email detection
        prof_info = user_info['extracted_info'].get('professional_info', {})
        if prof_info.get('is_professional') is not None:
            score += 0.1
        max_score += 0.1
        
        return round(score / max_score if max_score > 0 else 0.0, 2)

# Global instance
user_info_extractor = UserInfoExtractor() 