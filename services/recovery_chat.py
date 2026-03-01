import os
import uuid
import google.generativeai as genai
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv

load_dotenv()

class RecoveryChatService:
    def __init__(self):
        genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
        self.model = genai.GenerativeModel('gemini-2.5-pro')
        # In-memory session storage (not persistent)
        # Structure: session_id -> { "chat": ChatSession, "context": Dict }
        self._sessions: Dict[str, Any] = {}

    def start_session(self, case_context: Dict[str, Any]) -> str:
        """
        Initializes a new recovery chat session with specific case context.
        Returns: session_id
        """
        session_id = str(uuid.uuid4())
        
        system_prompt = self._build_system_prompt(case_context)
        
        # Initialize Gemini Chat
        chat_session = self.model.start_chat(history=[
            {"role": "user", "parts": [system_prompt]},
            {"role": "model", "parts": ["Understood. I am ready to assist with recovery based on these strict guidelines."]}
        ])
        
        self._sessions[session_id] = {
            "chat": chat_session,
            "context": case_context
        }
        
        return session_id

    def send_message(self, session_id: str, user_message: str) -> str:
        """
        Sends a user message to an active session.
        """
        if session_id not in self._sessions:
            raise ValueError("Session not found")
        
        session = self._sessions[session_id]
        
        # Safety Check: Refuse sensitive info
        # (This is a basic regex check, Gemini will also be prompted to refuse)
        if any(keyword in user_message.lower() for keyword in ["password", "credit card", "cvv", "social security"]):
             # We allow the word "password" in general ("how do I change my password?"), 
             # but we'll let the Model handle context.
             # This is just a placeholder for strict filtering if needed.
             pass

        try:
            response = session["chat"].send_message(user_message)
            return response.text
        except Exception as e:
            return f"I'm sorry, I encountered an error processing your request. Please try again. (Details: {str(e)})"

    def _build_system_prompt(self, context: Dict[str, Any]) -> str:
        """
        Constructs the strict system prompt.
        """
        details = f"""
        RISK SCORE: {context.get('risk_score', 'Unknown')}
        SEVERITY: {context.get('severity', 'Unknown')}
        SCAM TYPE: {context.get('scam_type', 'Unknown')}
        IMPERSONATED BRAND: {context.get('brand_impersonated', 'None')}
        
        OFFICIAL RECOVERY STEPS:
        {chr(10).join(f"- {step}" for step in context.get('recovery_steps', []))}
        """
        
        return f"""
        You are a Recovery Assistance AI.
        You are helping a user safely complete recovery steps after a confirmed scam.

        CASE CONTEXT:
        {details}

        YOUR ROLE:
        - Explain the official recovery steps listed above.
        - Clarify instructions if the user is confused.
        - Adapt advice to their device (mobile/desktop).
        - Reassure the user professionally.

        STRICT RULES (OFF-LIMITS):
        1. Do NOT ask for passwords, OTPs, credit card numbers, or personal secrets.
        2. Do NOT accept any sensitive data if offered (refuse it immediately).
        3. Do NOT suggest new recovery steps not listed above (unless it's generic safety like "run antivirus").
        4. Do NOT re-classify the scam or change the risk score.
        5. Do NOT execute tools or code.

        If the user asks "What should I do?", guide them through the OFFICIAL RECOVERY STEPS one by one.
        """
