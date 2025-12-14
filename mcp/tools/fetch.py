import httpx
from bs4 import BeautifulSoup
from typing import Dict, Any
import re

def fetch_url(url: str) -> Dict[str, Any]:
    """
    Fetches the URL and returns details.
    Returns:
        Final URL
        Redirect chain
        Response headers
        HTML content (truncated)
    """
    try:
        with httpx.Client(follow_redirects=True, timeout=10.0) as client:
            response = client.get(url)
            
            # Truncate HTML to avoid token limits
            html_content = response.text[:10000] 
            
            redirect_chain = [str(r.url) for r in response.history]
            
            return {
                "final_url": str(response.url),
                "redirect_chain": redirect_chain,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "html_content": html_content
            }
    except Exception as e:
        return {
            "url": url,
            "error": str(e)
        }

def extract_page_signals(url: str, html_content: str = None) -> Dict[str, Any]:
    """
    Analyzes the page content for suspicious signals.
    Returns:
        Login form detected (bool)
        Password field detected (bool)
        Brand keywords found
        Suspicious patterns
    """
    if not html_content:
        # If HTML not provided, fetch it (optional, but usually passed from fetch_url result)
        fetch_result = fetch_url(url)
        if "error" in fetch_result:
            return {"error": fetch_result["error"]}
        html_content = fetch_result.get("html_content", "")

    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Login form detection
    login_form = False
    password_field = False
    
    forms = soup.find_all('form')
    for form in forms:
        if form.find('input', {'type': 'password'}):
            password_field = True
            login_form = True # Strong signal
            break
        
        # Check for keywords in form action or inputs
        text = form.get_text().lower()
        if 'login' in text or 'sign in' in text:
            login_form = True

    # Brand keywords (simple check)
    brand_keywords = []
    common_brands = ['paypal', 'google', 'microsoft', 'apple', 'facebook', 'instagram', 'netflix', 'amazon', 'bank', 'chase', 'wells fargo']
    text_content = soup.get_text().lower()
    for brand in common_brands:
        if brand in text_content:
            brand_keywords.append(brand)

    # Suspicious patterns
    suspicious_patterns = []
    if "ngrok" in url:
        suspicious_patterns.append("ngrok_tunnel")
    if "@" in url: # Basic check, though fetch_url handles parsing
        suspicious_patterns.append("url_has_at_symbol")

    analysis_note = ""
    if not forms:
        analysis_note = "No HTML forms detected on page"
        
    return {
        "login_form_detected": login_form,
        "password_field_detected": password_field,
        "brand_keywords_found": brand_keywords,
        "suspicious_patterns": suspicious_patterns,
        "analysis_note": analysis_note
    }
