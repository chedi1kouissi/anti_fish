import os
import google.generativeai as genai
from dotenv import load_dotenv
import json
from typing import Dict, Any

load_dotenv()

class ReportAgent:
    def __init__(self):
        genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
        self.model = genai.GenerativeModel('gemini-2.5-pro')

    def generate_report(self, 
                        message_artifact: Dict, 
                        risk_assessment: Dict, 
                        link_findings: list,
                        indicators: Dict) -> str:
        """
        Generates a human-readable markdown report.
        """
        prompt = f"""
        You are a Report Agent. Generate a clear, helpful, and explainable security report for a non-technical user.
        
        Input Data:
        - Message Sender: {message_artifact.get('sender')}
        - Subject: {message_artifact.get('subject')}
        - Risk Assessment: {json.dumps(risk_assessment, indent=2)}
        - Link Findings: {json.dumps(link_findings, indent=2)}
        - Indicators: {json.dumps(indicators, indent=2)}
        
        Structure:
        # 🚨 Scam Risk Analysis Report
        
        ## Summary
        [Risk Score] - [Severity Label]
        [Brief explanation]
        
        ## 🔍 Key Evidence
        - Bullet points of PROVEN facts (e.g., "Domain registered 2 days ago", "Login form on non-official site").
        
        ## 🛡️ What To Do Now
        - Specific advice based on the threat type.
        
        ## ⚠️ If You Already Clicked
        - Mitigation steps.
        
        Tone: Professional, calm, authoritative but helpful.
        Format: Markdown.
        """
        
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Error generating report: {e}"
