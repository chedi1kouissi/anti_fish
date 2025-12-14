import os
import google.generativeai as genai
from schemas.message_artifact import MessageArtifact
from dotenv import load_dotenv
import json
import httpx
from typing import Dict, Any, List
from urllib.parse import urlparse

load_dotenv()

class LinkAnalyzerAgent:
    def __init__(self, mcp_url="http://localhost:5000"):
        genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
        self.model = genai.GenerativeModel('gemini-2.5-pro')
        self.mcp_url = mcp_url

    def _call_mcp(self, endpoint: str, payload: Dict) -> Dict:
        try:
            response = httpx.post(f"{self.mcp_url}/mcp/{endpoint}", json=payload, timeout=30.0)
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def analyze(self, urls: List[str]) -> List[Dict[str, Any]]:
        """
        Analyzes a list of URLs using MCP tools and Gemini reasoning.
        """
        findings = []
        
        for url in urls:
            # 1. Fetch URL
            fetch_result = self._call_mcp("fetch", {"url": url})
            
            # 2. Extract Signals
            signals_result = self._call_mcp("signals", {
                "url": url, 
                "html_content": fetch_result.get("html_content", "")
            })
            
            # 3. Whois Lookup (on domain)
            domain = urlparse(url).netloc
            whois_result = self._call_mcp("whois", {"domain": domain})
            
            # 4. Gemini Analysis of Technical Evidence
            prompt = f"""
            You are a Link Analyzer Agent. Interpret the following technical evidence for a specific URL.
            
            URL: {url}
            
            Fetch Result:
            {json.dumps(fetch_result, default=str)}
            
            Page Signals:
            {json.dumps(signals_result, default=str)}
            
            Whois Result:
            {json.dumps(whois_result, default=str)}
            
            Task:
            Determine if this link is malicious, suspicious, or safe based on the evidence.
            Look for:
            - Mismatched domains (e.g. paypal-login.com)
            - Young domains (< 30 days)
            - Credential harvesting forms
            - Redirection chains to suspicious sites
            
            Output JSON Schema:
            {{
                "url": "{url}",
                "risk_level": "high/medium/low/safe",
                "evidence": ["list", "of", "key", "findings"],
                "is_credential_harvesting": bool,
                "domain_age_warning": bool
            }}
            """
            
            try:
                response = self.model.generate_content(prompt)
                text = response.text.replace("```json", "").replace("```", "").strip()
                analysis = json.loads(text)
                findings.append(analysis)
            except Exception as e:
                findings.append({
                    "url": url,
                    "error": str(e),
                    "raw_evidence": {
                        "fetch": fetch_result,
                        "signals": signals_result,
                        "whois": whois_result
                    }
                })
                
        return findings
