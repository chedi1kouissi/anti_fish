import dns.resolver
from typing import List, Dict, Any

def get_dns_records(domain: str) -> Dict[str, Any]:
    """
    Retrieves basic DNS records for a domain.
    """
    records = {}
    try:
        for rtype in ['A', 'MX', 'NS', 'TXT']:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                records[rtype] = []
        return records
    except Exception as e:
        return {"error": str(e)}
