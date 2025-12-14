from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class SenderInfo(BaseModel):
    display_name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None

class ExtractedEntities(BaseModel):
    urls: List[str] = Field(default_factory=list)
    emails: List[str] = Field(default_factory=list)
    phones: List[str] = Field(default_factory=list)

class BodyContent(BaseModel):
    original_text: str
    clean_text: Optional[str] = None

class MessageArtifact(BaseModel):
    source_type: str = Field(..., description="email or social_dm")
    sender: SenderInfo
    subject: Optional[str] = None
    body: BodyContent
    extracted_entities: ExtractedEntities
    metadata: Dict[str, Any] = Field(default_factory=dict)
