import os
import google.generativeai as genai
from schemas.message_artifact import MessageArtifact
from dotenv import load_dotenv
import json
from typing import Dict, Any

load_dotenv()

class ExtractorAgent:
    def __init__(self):
        genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
        self.model = genai.GenerativeModel('gemini-2.5-flash')

    def analyze(self, artifact: MessageArtifact) -> Dict[str, Any]:
        """
        Analyzes the MessageArtifact for security indicators.
        """
        prompt = f"""
        You are a security extractor agent. Analyze the following message artifact for scam indicators.
        
        Message:
        {artifact.model_dump_json()}
        
        Task:
        Identify specific indicators of urgency, requested actions, brand impersonation, and sender mismatches.
        
        Output JSON Schema:
        {{
            "urgency_detected": bool,
            "urgency_type": "...", # e.g., "account_suspension", "limited_time_offer", "none"
            "requested_actions": ["login", "payment", "download", "reply", "otp", ...],
            "brand_impersonation": {{
                "detected": bool,
                "brand_name": "...",
                "evidence": "..."
            }},
            "sender_mismatch": {{
                "detected": bool,
                "explanation": "..."
            }},
            "language_tone": "..." # e.g., "threatening", "professional", "casual"
        }}
        
        Return ONLY valid JSON.
        """
        
        response = self.model.generate_content(prompt)
        try:
            text = response.text.replace("```json", "").replace("```", "").strip()
            return json.loads(text)
        except Exception as e:
            print(f"Error parsing Extractor response: {e}")
            return {"error": str(e)}
