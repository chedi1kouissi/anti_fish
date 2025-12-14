import whois
import datetime
from typing import Dict, Any

def whois_lookup(domain: str) -> Dict[str, Any]:
    """
    Performs a WHOIS lookup for the given domain.
    Returns:
        Domain creation date
        Age in days
        Registrar
        Privacy protection flag
    """
    try:
        w = whois.whois(domain)
        
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        age_days = -1
        if creation_date:
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=datetime.timezone.utc)
            else:
                creation_date = creation_date.astimezone(datetime.timezone.utc)
            
            now = datetime.datetime.now(datetime.timezone.utc)
            age_days = (now - creation_date).days
            
        privacy_found = False
        if w.text:
            privacy_keywords = ['privacy', 'redacted', 'protected', 'proxy', 'guard']
            privacy_found = any(keyword in w.text.lower() for keyword in privacy_keywords)

        return {
            "domain": domain,
            "creation_date": str(creation_date) if creation_date else None,
            "age_days": age_days,
            "registrar": w.registrar,
            "privacy_protection": privacy_found,
            "raw_whois": str(w) # minimal raw info
        }
    except Exception as e:
        return {
            "domain": domain,
            "error": str(e)
        }
