# email_providers.py
import re
import dns.resolver

# Database of common email providers and their settings
EMAIL_PROVIDERS = {
    "gmail.com": {
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 587,
        "smtp_ssl": False,
        "smtp_tls": True,
        "imap_host": "imap.gmail.com",
        "imap_port": 993,
        "imap_ssl": True,
    },
    "outlook.com": {
        "smtp_host": "smtp-mail.outlook.com",
        "smtp_port": 587,
        "smtp_ssl": False,
        "smtp_tls": True,
        "imap_host": "outlook.office365.com",
        "imap_port": 993,
        "imap_ssl": True,
    },
    "yahoo.com": {
        "smtp_host": "smtp.mail.yahoo.com",
        "smtp_port": 587,
        "smtp_ssl": False,
        "smtp_tls": True,
        "imap_host": "imap.mail.yahoo.com",
        "imap_port": 993,
        "imap_ssl": True,
    },
    "aol.com": {
        "smtp_host": "smtp.aol.com",
        "smtp_port": 587,
        "smtp_ssl": False,
        "smtp_tls": True,
        "imap_host": "imap.aol.com",
        "imap_port": 993,
        "imap_ssl": True,
    },
    "icloud.com": {
        "smtp_host": "smtp.mail.me.com",
        "smtp_port": 587,
        "smtp_ssl": False,
        "smtp_tls": True,
        "imap_host": "imap.mail.me.com",
        "imap_port": 993,
        "imap_ssl": True,
    },
    "hotmail.com": {
        "smtp_host": "smtp-mail.outlook.com",
        "smtp_port": 587,
        "smtp_ssl": False,
        "smtp_tls": True,
        "imap_host": "outlook.office365.com",
        "imap_port": 993,
        "imap_ssl": True,
    },
    "live.com": {
        "smtp_host": "smtp-mail.outlook.com",
        "smtp_port": 587,
        "smtp_ssl": False,
        "smtp_tls": True,
        "imap_host": "outlook.office365.com",
        "imap_port": 993,
        "imap_ssl": True,
    },
    "office365.com": {
        "smtp_host": "smtp.office365.com",
        "smtp_port": 587,
        "smtp_ssl": False,
        "smtp_tls": True,
        "imap_host": "outlook.office365.com",
        "imap_port": 993,
        "imap_ssl": True,
    },
    "protonmail.com": {
        "smtp_host": "mail.protonmail.com",
        "smtp_port": 587,
        "smtp_ssl": False,
        "smtp_tls": True,
        "imap_host": "mail.protonmail.com",
        "imap_port": 993,
        "imap_ssl": True,
    },
    "zoho.com": {
        "smtp_host": "smtp.zoho.com",
        "smtp_port": 587,
        "smtp_ssl": False,
        "smtp_tls": True,
        "imap_host": "imap.zoho.com",
        "imap_port": 993,
        "imap_ssl": True,
    },
    # Add more providers as needed
}

def extract_domain(email):
    """Extract domain from email address"""
    pattern = r'@([\w\.-]+)'
    match = re.search(pattern, email)
    if match:
        return match.group(1).lower()
    return None

def get_email_settings(email):
    """Get email settings based on domain"""
    domain = extract_domain(email)
    if not domain:
        return None
    
    # Check if domain is in our known providers
    if domain in EMAIL_PROVIDERS:
        return EMAIL_PROVIDERS[domain]
    
    # For custom domains, try to discover settings
    return discover_custom_domain_settings(domain)

def discover_custom_domain_settings(domain):
    """Try to discover email settings for custom domains"""
    settings = {
        "smtp_host": f"smtp.{domain}",
        "smtp_port": 587,
        "smtp_ssl": False,
        "smtp_tls": True,
        "imap_host": f"imap.{domain}",
        "imap_port": 993,
        "imap_ssl": True,
    }
    
    # Try to discover actual settings via DNS
    try:
        # Check for common mail server configurations
        mx_records = dns.resolver.resolve(domain, 'MX')
        for mx in mx_records:
            mx_host = str(mx.exchange).rstrip('.')
            
            # Check if it's a known provider's MX
            if "google" in mx_host:
                settings.update({
                    "smtp_host": "smtp.gmail.com",
                    "imap_host": "imap.gmail.com"
                })
                break
            elif "outlook" in mx_host or "office365" in mx_host:
                settings.update({
                    "smtp_host": "smtp.office365.com",
                    "imap_host": "outlook.office365.com"
                })
                break
    except:
        # If DNS lookup fails, fall back to default assumptions
        pass
    
    return settings
