import json
import uuid
import time
import os
import sys
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from flask import Flask, request, jsonify, Response, stream_with_context
from flask_cors import CORS

# Ensure we can import agents
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from agents.ingestion_agent import IngestionAgent
from agents.extractor_agent import ExtractorAgent
from agents.link_analyzer_agent import LinkAnalyzerAgent
from agents.scoring_agent import ScoringAgent
from agents.report_agent import ReportAgent

from schemas.message_artifact import MessageArtifact
from mcp.tools.whois import whois_lookup
from mcp.tools.fetch import fetch_url, extract_page_signals
from services.recovery_chat import RecoveryChatService

app = Flask(__name__)
# Allow CORS for Next.js dev server
CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})

# ============================================================================
# In-Memory Database (with JSON persistence)
# ============================================================================
ANALYSES_DB: Dict[str, Dict[str, Any]] = {}
EVENTS_DB: Dict[str, List[Dict[str, Any]]] = {}

# Persistence files
ANALYSES_LOG_FILE = "analyses_log.json"
EVENTS_LOG_FILE = "events_log.json"

# ============================================================================
# Persistence Helpers
# ============================================================================

def load_data():
    """Load analyses and events from JSON files on startup"""
    global ANALYSES_DB, EVENTS_DB
    
    # Load analyses
    if os.path.exists(ANALYSES_LOG_FILE):
        try:
            with open(ANALYSES_LOG_FILE, 'r') as f:
                ANALYSES_DB = json.load(f)
            print(f"[Persistence] Loaded {len(ANALYSES_DB)} analyses from {ANALYSES_LOG_FILE}")
        except Exception as e:
            print(f"[Persistence] Error loading analyses: {e}")
            ANALYSES_DB = {}
    
    # Load events
    if os.path.exists(EVENTS_LOG_FILE):
        try:
            with open(EVENTS_LOG_FILE, 'r') as f:
                EVENTS_DB = json.load(f)
            print(f"[Persistence] Loaded events for {len(EVENTS_DB)} analyses from {EVENTS_LOG_FILE}")
        except Exception as e:
            print(f"[Persistence] Error loading events: {e}")
            EVENTS_DB = {}

def save_data():
    """Save analyses and events to JSON files"""
    try:
        # Save analyses
        with open(ANALYSES_LOG_FILE, 'w') as f:
            json.dump(ANALYSES_DB, f, indent=2)
        
        # Save events
        with open(EVENTS_LOG_FILE, 'w') as f:
            json.dump(EVENTS_DB, f, indent=2)
        
        print(f"[Persistence] Saved {len(ANALYSES_DB)} analyses to disk")
    except Exception as e:
        print(f"[Persistence] Error saving data: {e}")


# ============================================================================
# Helpers
# ============================================================================

def run_pipeline(text: str, source_type: str, metadata: Dict[str, Any] = {}) -> Dict[str, Any]:
    """
    Runs the full agent pipeline synchronously (for now) 
    and returns the final analysis object.
    """
    analysis_id = str(uuid.uuid4())
    created_at = datetime.now()
    
    # Initialize DB entry
    EVENTS_DB[analysis_id] = []
    
    def log_event(agent_name: str, action: str, details: Any):
        event = {
            "timestamp": datetime.now().isoformat(),
            "agentName": agent_name,
            "action": action,
            "details": details
        }
        EVENTS_DB[analysis_id].append(event)
        return event

    try:
        # 1. Ingestion
        log_event("IngestionAgent", "started", {"text_length": len(text)})
        ingestion = IngestionAgent()
        artifact = ingestion.process(text)
        artifact.source_type = source_type # Override if needed
        # Merge provided metadata
        if metadata:
            artifact.metadata.update(metadata)
        log_event("IngestionAgent", "completed", artifact.model_dump())

        # 2. Extraction
        log_event("ExtractorAgent", "started", {})
        extractor = ExtractorAgent()
        indicators = extractor.analyze(artifact)
        log_event("ExtractorAgent", "completed", indicators)

        # 3. Link Analysis
        log_event("LinkAnalyzerAgent", "started", {"url_count": len(artifact.extracted_entities.urls)})
        link_analyzer = LinkAnalyzerAgent()
        link_findings = link_analyzer.analyze(artifact.extracted_entities.urls)
        log_event("LinkAnalyzerAgent", "completed", link_findings)

        # 4. Scoring
        log_event("ScoringAgent", "started", {})
        scoring = ScoringAgent()
        risk_assessment = scoring.calculate_score(indicators, link_findings)
        log_event("ScoringAgent", "completed", risk_assessment)

        # 5. Reporting
        log_event("ReportAgent", "started", {})
        report_agent = ReportAgent()
        report_text = report_agent.generate_report(
            artifact.model_dump(), 
            risk_assessment, 
            link_findings, 
            indicators
        )
        log_event("ReportAgent", "completed", {"summary_length": len(report_text)})

        # Construct Final Analysis Object matched to UI contracts
        analysis_result = {
            "id": analysis_id,
            "createdAt": created_at.isoformat(),
            "updatedAt": datetime.now().isoformat(),
            "sourceType": source_type,
            "sourceName": artifact.sender.display_name or artifact.sender.email or "Unknown",
            "status": "completed",
            
            # Threat props
            "threatScore": risk_assessment.get("risk_score", 0),
            "confidence": 0.9, # Placeholder
            "category": _map_threat_type(risk_assessment.get("scam_type", "OTHER")),
            
            # AI outputs
            "userSummary": report_text, 
            "whyFlagged": risk_assessment.get("reasons", []),
            "recommendedActions": risk_assessment.get("recommended_actions") or _generate_recommendations(risk_assessment),
            
            # Tech details
            "indicators": {
                "urls": artifact.extracted_entities.urls,
                "domains": [], # Would extract from URLs
                "emails": artifact.extracted_entities.emails,
                "phones": artifact.extracted_entities.phones
            },
            "timeline": _generate_timeline(created_at),
            
            # Privacy
            "rawContent": text,
            "safePreview": artifact.body.clean_text[:200] + "...",
            
            # Metadata
            "impersonatedBrand": indicators.get("brand_impersonation", {}).get("brand_name"),
            
            # MAS artifacts (for debugging)
            "mas_artifacts": {
                "message_artifact": artifact.model_dump(),
                "indicators": indicators,
                "link_findings": link_findings,
                "risk_assessment": risk_assessment
            }
        }
        
        ANALYSES_DB[analysis_id] = analysis_result
        save_data()  # Persist to disk
        return analysis_result

    except Exception as e:
        # Log failure
        log_event("Orchestrator", "failed", {"error": str(e)})
        raise e

def _map_threat_type(scam_type: str) -> str:
    # Maps backend scam types to UI ThreatType enum
    scam_type_upper = scam_type.upper()
    if "PHISHING" in scam_type_upper:
        return "FAKE_EMAIL_PHISHING"
    if "MALWARE" in scam_type_upper or "VIRUS" in scam_type_upper:
        return "FAKE_WEBSITE_MALICIOUS_LINK" 
    if "SCAM" in scam_type_upper or "SOCIAL" in scam_type_upper:
        return "HIDDEN_FRAUD_RING_SOCIAL_SCAM"
    return "OTHER"

def _generate_recommendations(risk_assessment: Dict) -> List[Dict]:
    # Simple logic to generate actions based on score
    score = risk_assessment.get("risk_score", 0)
    actions = []
    
    if score > 70:
        actions.append({
            "title": "Do not click any links",
            "priority": "high",
            "detail": "High risk of phishing or malware."
        })
        actions.append({
            "title": "Block the sender",
            "priority": "high",
            "detail": "Prevent further contact."
        })
    elif score > 30:
        actions.append({
            "title": "Verify sender identity",
            "priority": "med",
            "detail": "Contact them through a separate, trusted channel."
        })
    else:
        actions.append({
            "title": "No immediate action needed",
            "priority": "low",
            "detail": "Message appears safe, but stay vigilant."
        })
        
    return actions

def _generate_timeline(start_time: datetime) -> List[Dict]:
    return [
        {
            "timestamp": start_time.isoformat(),
            "label": "Analysis Started",
            "description": "Message received and queued for analysis",
            "status": "info"
        },
        {
            "timestamp": (start_time + timedelta(seconds=2)).isoformat(),
            "label": "AI Scanning",
            "description": "Scanning for malicious patterns and links",
            "status": "info"
        },
        {
            "timestamp": (start_time + timedelta(seconds=4)).isoformat(),
            "label": "Complete",
            "description": "Analysis finished successfully",
            "status": "success"
        }
    ]

# ============================================================================
# Routes
# ============================================================================

@app.route('/api/analyze/email', methods=['POST'])
def analyze_email():
    data = request.json
    text = data.get('text', '')
    if not text:
        return jsonify({"error": "No text provided"}), 400
        
    try:
        result = run_pipeline(text, 'email', data.get('metadata', {}))
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/analyze/url', methods=['POST'])
def analyze_url():
    data = request.json
    url = data.get('url', '')
    if not url:
        return jsonify({"error": "No URL provided"}), 400
        
    # Treat URL as the text input for now, or fetch it? 
    # For now, we'll pass the URL string as the content to ingest.
    # Ideally, IngestionAgent should handle fetching if its just a URL.
    # Looking at IngestionAgent, it likely processes raw text.
    
    # We will simulate the URL analysis by passing it as text context
    text_representation = f"URL to analyze: {url}"
    
    try:
        result = run_pipeline(text_representation, 'url', data.get('metadata', {}))
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/analyze/file', methods=['POST'])
def analyze_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
        
    # Simple text read for now
    try:
        content = file.read().decode('utf-8', errors='ignore')
        result = run_pipeline(content, 'file')
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/analyses', methods=['GET'])
def list_analyses():
    # Convert dict to list
    items = list(ANALYSES_DB.values())
    
    # Sort by date desc
    items.sort(key=lambda x: x['createdAt'], reverse=True)
    
    return jsonify({
        "items": items,
        "hasMore": False,
        "total": len(items)
    })

@app.route('/api/analyses/<id>', methods=['GET'])
def get_analysis(id):
    item = ANALYSES_DB.get(id)
    if not item:
        return jsonify({"error": "Not found"}), 404
    return jsonify(item)

@app.route('/api/stats', methods=['GET'])
def get_stats():
    total = len(ANALYSES_DB)
    items = list(ANALYSES_DB.values())
    
    # 1. High Risk Count
    high_risk = len([i for i in items if i.get('threatScore', 0) >= 70])
    
    # 2. Avg Score
    avg_score = sum(i.get('threatScore', 0) for i in items) / total if total > 0 else 0
    
    # 3. Top Category
    categories = {}
    for i in items:
        cat = i.get('category', 'OTHER')
        categories[cat] = categories.get(cat, 0) + 1
    top_category = max(categories, key=categories.get) if categories else "OTHER"
    
    # 4. Trend Data (Last 7 Days)
    # Group by YYYY-MM-DD
    trend_map = {} # date -> {count: 0, highRiskCount: 0}
    now = datetime.now()
    # Initialize last 7 days with 0
    for i in range(6, -1, -1):
        date_str = (now - timedelta(days=i)).strftime('%Y-%m-%d')
        trend_map[date_str] = {"count": 0, "highRiskCount": 0}
        
    for i in items:
        try:
            dt = datetime.fromisoformat(i['createdAt'])
            date_key = dt.strftime('%Y-%m-%d')
            if date_key in trend_map:
                trend_map[date_key]["count"] += 1
                if i.get('threatScore', 0) >= 70:
                    trend_map[date_key]["highRiskCount"] += 1
        except:
            pass
            
    trend_data = [
        {"date": k, "count": v["count"], "highRiskCount": v["highRiskCount"]} 
        for k, v in trend_map.items()
    ]
    
    # 5. Category Breakdown for Chart
    # Interface: { category: string, count: number, percentage: number }
    category_breakdown = []
    for cat, count in categories.items():
        category_breakdown.append({
            "category": cat,
            "count": count,
            "percentage": (count / total * 100) if total > 0 else 0
        })
    
    # 6. Top Impersonated Brands
    # Interface: { name: string, count: number, avgThreatScore: number }
    brands_stats = {} # name -> {count: 0, total_score: 0}
    for i in items:
        brand = i.get('impersonatedBrand')
        if brand and brand != "None":
            if brand not in brands_stats:
                brands_stats[brand] = {"count": 0, "total_score": 0}
            brands_stats[brand]["count"] += 1
            brands_stats[brand]["total_score"] += i.get('threatScore', 0)
            
    top_brands = []
    # Sort by count desc
    sorted_brands = sorted(brands_stats.items(), key=lambda item: item[1]['count'], reverse=True)[:5]
    for name, stats in sorted_brands:
        top_brands.append({
            "name": name,
            "count": stats["count"],
            "avgThreatScore": stats["total_score"] / stats["count"]
        })
    
    return jsonify({
        "totalAnalyses": total,
        "highRiskCount": high_risk,
        "topCategory": top_category,
        "avgThreatScore": int(avg_score),
        "trendData": trend_data,
        "categoryBreakdown": category_breakdown,
        "topBrands": top_brands,
        "recentHighRisk": [i for i in items if i.get('threatScore', 0) >= 70][:5],
        "startDate": (now - timedelta(days=7)).isoformat(),
        "endDate": now.isoformat()
    })

@app.route('/api/analyses/<id>/events', methods=['GET'])
def get_analysis_events(id):
    # SSE Endpoint
    def generate():
        # First send existing events
        existing = EVENTS_DB.get(id, [])
        for evt in existing:
            yield f"data: {json.dumps(evt)}\n\n"
        
        # If the analysis is already done, we just end?
        # In a real async system, we'd subscribe to a pub/sub.
        # Here analysis is synchronous, so by the time we call this,
        # all events are likely already in DB. 
        # So we just send them and close.
        pass

    response = Response(stream_with_context(generate()), mimetype='text/event-stream')
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3000')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

@app.route('/api/notifications/test', methods=['POST'])
def send_test_notification():
    # Placeholder for notification logic
    data = request.json
    phone = data.get('phoneNumber')
    if not phone:
        return jsonify({"error": "No phone number provided"}), 400
    
    return jsonify({"success": True, "message": f"Test notification sent to {phone}"})

# ============================================================================
# MCP Routes (Internal for LinkAnalyzerAgent)
# ============================================================================

@app.route('/mcp/whois', methods=['POST'])
def handle_whois():
    data = request.json
    domain = data.get('domain')
    if not domain:
        return jsonify({"error": "domain is required"}), 400
    try:
        result = whois_lookup(domain)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/mcp/fetch', methods=['POST'])
def handle_fetch():
    data = request.json
    url = data.get('url')
    if not url:
        return jsonify({"error": "url is required"}), 400
    try:
        result = fetch_url(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/mcp/signals', methods=['POST'])
def handle_signals():
    data = request.json
    url = data.get('url')
    html_content = data.get('html_content') 
    if not url:
        return jsonify({"error": "url is required"}), 400
    try:
        result = extract_page_signals(url, html_content)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================================================
# Recovery Chat AI Routes
# ============================================================================

chat_service = RecoveryChatService()

@app.route('/api/recovery/start', methods=['POST'])
def start_recovery_chat():
    data = request.json
    case_context = data.get('case_context')
    
    if not case_context:
        return jsonify({"error": "case_context is required"}), 400
        
    try:
        session_id = chat_service.start_session(case_context)
        return jsonify({
            "session_id": session_id,
            "assistant_message": "I'm here to help you through the recovery process safely. I have the details of this analysis. Which step would you like to start with, or do you have a specific question?"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/recovery/message', methods=['POST'])
def message_recovery_chat():
    data = request.json
    session_id = data.get('session_id')
    user_message = data.get('user_message')
    
    if not session_id or not user_message:
        return jsonify({"error": "session_id and user_message are required"}), 400
        
    try:
        reply = chat_service.send_message(session_id, user_message)
        return jsonify({"assistant_message": reply})
    except ValueError:
        return jsonify({"error": "Session not found or expired"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    load_data()  # Load existing analyses from disk
    app.run(debug=True, port=5000)
