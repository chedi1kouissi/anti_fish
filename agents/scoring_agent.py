import os
import google.generativeai as genai
from dotenv import load_dotenv
import json
from typing import Dict, Any, List

load_dotenv()

class ScoringAgent:
    def __init__(self):
        genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
        self.model = genai.GenerativeModel('gemini-2.5-pro')

    def calculate_score(self, indicators: Dict[str, Any], link_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculates the final risk score and classification.
        """
        prompt = f"""
        You are a Risk Scoring Agent. Calculate a scam risk score (0-100) based on the provided indicators and link analysis facts.

        Extractor Indicators:
        {json.dumps(indicators, indent=2)}

        Link Analysis Facts (Array of objects):
        {json.dumps(link_findings, indent=2)}

        Task:
        1. Analyze the "facts" for each link to determine its risk.
           - Young domain (< 30 days) -> High Risk
           - Mismatched domain (e.g. brand name in subdomain/path but not root) -> High Risk
           - Login form + Password field on non-official domain -> Critical Risk (Credential Harvesting)
           - Hidden/Redacted Whois -> Medium Risk factor
        2. Combine link risk with Extractor indicators (Urgency, Brand Mismatches).
        3. Assign a final score and severity.

        Scoring Rules:
        - 0-20: Safe / Low Risk
        - 21-50: Suspicious / Medium Risk
        - 51-80: High Risk
        - 81-100: Critical / Confirmed Scam

        Output JSON Schema:
        {{
            "risk_score": int,
            "severity_label": "Safe/Low/Medium/High/Critical",
            "scam_type": "Phishing/AdvanceFee/TechSupport/None/...",
            "top_reasons": ["reason 1", "reason 2", ...],
            "explanation": "Short summary of why this score was given."
        }}
        """
        
        try:
            response = self.model.generate_content(prompt)
            text = response.text.replace("```json", "").replace("```", "").strip()
            return json.loads(text)
        except Exception as e:
            return {"error": str(e)}
