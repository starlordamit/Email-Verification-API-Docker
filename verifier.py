
import re
import socket
import time
import dns.resolver
import smtplib
import hashlib
import whois
from datetime import datetime
from config import Config


class EmailVerifier:
    def __init__(self, from_email="verify@example.com"):
        self.from_email = from_email  # Used for SMTP verification

    def verify_email(self, email_address):
        start_time = time.time()
        result = {
            "email_address": email_address,
            "gravatar_url": self._get_gravatar_url(email_address),
            "account": self._extract_account(email_address),
            "domain_details": {},
            "validation_details": {
                "format_valid": False,
                "mx_found": False,
                "smtp_check": False,
                "catch_all": False,
                "role": False,
                "disposable": False,
                "free": False,
                "tagged": False,
                "mailbox_full": False,
                "mailbox_disabled": False,
                "no_reply": False
            },
            "selected_mx_record": None,
            "service_provider": None,
            "character_stats": self._get_character_stats(email_address),
            "ip_details": None,
            "time_taken_to_verify": None,
            "reason": None,
            "status": None,
            "score": 0
        }

        # Validate email format
        if not self._validate_email_format(email_address):
            result["reason"] = "invalid_format"
            result["status"] = "invalid"
            result["time_taken_to_verify"] = f"{time.time() - start_time:.2f}"
            return self._format_response(result)

        result["validation_details"]["format_valid"] = True

        # Extract domain details
        domain = email_address.split('@')[-1]
        domain_details = self._get_domain_details(domain)
        result["domain_details"] = domain_details

        # Check MX records
        mx_records = self._check_mx_records(domain)
        if not mx_records:
            result["reason"] = "no_mx_records"
            result["status"] = "undeliverable"
            result["time_taken_to_verify"] = f"{time.time() - start_time:.2f}"
            return self._format_response(result)

        result["validation_details"]["mx_found"] = True
        result["selected_mx_record"] = mx_records[0]
        result["service_provider"] = self._identify_service_provider(mx_records[0])

        # Perform SMTP verification (mailbox check)
        smtp_check_result = self._check_smtp_mailbox(email_address, mx_records)
        result["validation_details"]["smtp_check"] = smtp_check_result["exists"]
        result["validation_details"]["mailbox_disabled"] = smtp_check_result.get("disabled", False)
        result["validation_details"]["mailbox_full"] = smtp_check_result.get("full", False)

        # Additional validations
        result["validation_details"]["role"] = self._is_role_account(email_address)
        result["validation_details"]["disposable"] = self._is_disposable_domain(domain)
        result["validation_details"]["free"] = self._is_free_email_provider(domain)

        # Determine final status
        if result["validation_details"]["format_valid"] and result["validation_details"]["mx_found"]:
            if result["validation_details"]["smtp_check"]:
                result["status"] = "deliverable"
                result["reason"] = "deliverable"
            else:
                result["status"] = "risky"
                result["reason"] = "mailbox_not_found"
            result["score"] = self._calculate_score(result)
        else:
            result["status"] = "undeliverable"

        result["time_taken_to_verify"] = f"{time.time() - start_time:.2f}"

        return self._format_response(result)

    def _check_smtp_mailbox(self, email, mx_records, timeout=10):
        """Check if the mailbox exists via SMTP"""
        result = {"exists": False, "disabled": False, "full": False}

        for mx in mx_records:
            try:
                # Connect to the SMTP server
                with smtplib.SMTP(timeout=timeout) as smtp:
                    smtp.set_debuglevel(0)  # Disable debug output
                    smtp.connect(mx)

                    # Send SMTP commands
                    smtp.ehlo_or_helo_if_needed()
                    smtp.mail(self.from_email)
                    code, response = smtp.rcpt(email)

                    # Decode response if it's in bytes
                    if isinstance(response, bytes):
                        response = response.decode('utf-8', errors='ignore')

                    # Check response codes
                    if code == 250:  # Mailbox exists
                        result["exists"] = True
                        break
                    elif code == 552:  # Mailbox full
                        result["exists"] = True
                        result["full"] = True
                        break
                    elif code in [550, 551]:  # Mailbox does not exist or disabled
                        result["exists"] = False
                        if "disabled" in response.lower():
                            result["disabled"] = True
                        break
            except (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError, smtplib.SMTPResponseException, socket.timeout, socket.gaierror):
                continue

        return result
    def _format_response(self, verification_result):
        return {
            "success": True,
            "message": "The results have been successfully retrieved from our task scheduler service.",
            "verification_result": verification_result
        }

    def _validate_email_format(self, email):
        """Validate email format using regex"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def _extract_account(self, email):
        """Extract the account part of the email"""
        return email.split('@')[0]

    def _get_gravatar_url(self, email):
        """Generate Gravatar URL"""
        email_hash = hashlib.md5(email.lower().encode('utf-8')).hexdigest()
        return f"https://www.gravatar.com/avatar/{email_hash}"

    def _get_domain_details(self, domain):
        """Get domain details including age"""
        try:
            domain_info = whois.whois(domain)
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            domain_age = (datetime.now() - creation_date).days if creation_date else None
            
            return {
                "domain": domain,
                "domain_age": domain_age,
                "did_you_mean": None
            }
        except Exception:
            return {
                "domain": domain,
                "domain_age": None,
                "did_you_mean": None
            }

    def _check_mx_records(self, domain):
        """Check MX records for the domain"""
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            return [str(mx.exchange).rstrip('.') for mx in mx_records]
        except Exception:
            return None

    def _identify_service_provider(self, mx_record):
        """Identify email service provider from MX record"""
        mx_lower = mx_record.lower()
        if 'google' in mx_lower or 'gmail' in mx_lower:
            return "Gmail"
        elif 'outlook' in mx_lower or 'microsoft' in mx_lower:
            return "Microsoft Outlook"
        elif 'yahoo' in mx_lower:
            return "Yahoo"
        elif 'amazonaws' in mx_lower:
            return "Amazon SES"
        elif 'mail.protection.outlook' in mx_lower:
            return "Office 365"
        else:
            return "Custom"

    def _get_character_stats(self, email):
        """Get character statistics for the email"""
        account_part = email.split('@')[0]
        alpha = sum(1 for c in account_part if c.isalpha())
        numeric = sum(1 for c in account_part if c.isdigit())
        symbols = len(account_part) - alpha - numeric
        
        return {
            "alphabetical_characters": alpha,
            "numerical_characters": numeric,
            "unicode_symbols": symbols
        }

    def _is_role_account(self, email):
        """Check if this is a role-based email address"""
        role_accounts = ['admin', 'contact', 'support', 'help', 'info', 'sales', 
                         'service', 'feedback', 'webmaster', 'postmaster']
        account = email.split('@')[0].lower()
        return any(role in account for role in role_accounts)

    def _is_disposable_domain(self, domain):
        """Check if this is a disposable email domain"""
        disposable_domains = ['mailinator.com', 'tempmail.com', '10minutemail.com']
        return domain.lower() in disposable_domains

    def _is_free_email_provider(self, domain):
        """Check if this is a free email provider"""
        free_domains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 
                        'protonmail.com', 'icloud.com']
        return domain.lower() in free_domains

    def _calculate_score(self, result):
        """Calculate a deliverability score based on verification results"""
        score = 0
        
        if result["validation_details"]["format_valid"]:
            score += 20
        if result["validation_details"]["mx_found"]:
            score += 20
        if result["validation_details"]["smtp_check"]:
            score += 30
        if not result["validation_details"]["disposable"]:
            score += 10
        if not result["validation_details"]["role"]:
            score += 10
        if not result["validation_details"]["free"]:
            score += 10
            
        return min(score, 100)
