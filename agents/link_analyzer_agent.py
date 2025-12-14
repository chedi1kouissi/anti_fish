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
            You are a Link Analyzer Agent. Extract factual observations from the provided technical evidence for a specific URL.

            URL: {url}

            Fetch Result:
            {json.dumps(fetch_result, default=str)}

            Page Signals:
            {json.dumps(signals_result, default=str)}

            Whois Result:
            {json.dumps(whois_result, default=str)}

            Task:
            Analyze the evidence and populate the "facts" object in the output using ONLY verifiable data from the inputs.
            
            IMPORTANT HANDLING OF ERRORS:
            - If any input (Fetch, Signals, Whois) contains an "error" field, do NOT fail.
            - Instead, add the error message to "technical_errors" in the output.
            - Extract as much valid data as possible from the non-failed inputs.
            - For example, if Whois fails but Fetch succeeds, still report the redirect chain and page signals.

            Do NOT make ANY judgments about risk (safe/malicious).
            Do NOT use words like "suspicious", "phishing", or "safe".
            Do NOT assign a risk score.

            Output JSON Schema:
            {{
                "agent": "LinkAnalyzerAgent",
                "url": "{url}",
                "facts": {{
                    "domain_age_days": int | null,
                    "registrar": "string | null",
                    "privacy_protection": bool | null,
                    "redirect_chain": ["url1", "url2"],
                    "redirect_count": int,
                    "login_form_detected": bool,
                    "password_field_detected": bool,
                    "brand_keywords_found": ["list", "of", "brands", "found"],
                    "reachability": "reachable" or "unreachable",
                    "technical_errors": ["list", "of", "errors"]
                }}
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
