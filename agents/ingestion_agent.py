import os
import google.generativeai as genai
from schemas.message_artifact import MessageArtifact
from dotenv import load_dotenv
import json

load_dotenv()

class IngestionAgent:
    def __init__(self):
        genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
        self.model = genai.GenerativeModel('gemini-2.5-flash')

    def process(self, raw_text: str, source_type: str = "email") -> MessageArtifact:
        """
        Ingests raw text and returns a structured MessageArtifact.
        """
        prompt = f"""
        You are an expert data ingestion agent.
        Your task is to parse the following raw text into a structured JSON object matching the MessageArtifact schema.
        
        Input Text:
        {raw_text}
        
        Source Type: {source_type}
        
        Output Schema (JSON):
        {{
            "source_type": "{source_type}",
            "sender": {{
                "display_name": "...",
                "email": "...",
                "phone": "..."
            }},
            "subject": "...",
            "body": {{
                "original_text": "...",
                "clean_text": "..." 
            }},
            "extracted_entities": {{
                "urls": ["..."],
                "emails": ["..."],
                "phones": ["..."]
            }},
            "metadata": {{
                "language": "...",
                "platform": "..."
            }}
        }}
        
        Instructions:
        1. Extract sender info if available.
        2. Clean the body text (remove HTML tags, signatures, noise).
        3. Extract all URLs, emails, and phone numbers into extracted_entities.
        4. Detect language.
        5. Return ONLY valid JSON.
        """
        
        response = self.model.generate_content(prompt)
        try:
            # Clean up potential markdown code blocks
            text = response.text.replace("```json", "").replace("```", "").strip()
            data = json.loads(text)
            return MessageArtifact(**data)
        except Exception as e:
            print(f"Error parsing Gemini response: {e}")
            # Fallback or re-raise
            raise e
