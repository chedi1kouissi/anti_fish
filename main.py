import asyncio
import sys
import os
from agents.ingestion_agent import IngestionAgent
from agents.extractor_agent import ExtractorAgent
from agents.link_analyzer_agent import LinkAnalyzerAgent
from agents.scoring_agent import ScoringAgent
from agents.report_agent import ReportAgent
from dotenv import load_dotenv

# Ensure we can import modules from current directory
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

load_dotenv()

def main():
    print("---------------------------------------------------------")
    print("   Silent Cyber Threats - Scam Analyzer (Agentic AI)   ")
    print("---------------------------------------------------------")
    
    # 1. Get Input
    print("\nPlease paste the suspicious message (email body or text):")
    print("(Press Ctrl+Z then Enter on Windows, or Ctrl+D on Linux/Mac to finish input)")
    # raw_input = sys.stdin.read()
    
    # For demo purposes, let's allow a simple input or read from a file if provided
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r') as f:
            raw_input = f.read()
    else:
        # Interactive mode fallback (simplified for this script)
        lines = []
        try:
            while True:
                line = input()
                lines.append(line)
        except EOFError:
            pass
        raw_input = "\n".join(lines)

    if not raw_input.strip():
        print("No input provided. Exiting.")
        return

    print("\n[1/5] 📥 Ingesting message...")
    ingestion = IngestionAgent()
    artifact = ingestion.process(raw_input)
    print(f"      Parsed: {artifact.subject} (Sender: {artifact.sender.display_name})")

    print("\n[2/5] 🕵️  Extracting indicators...")
    extractor = ExtractorAgent()
    indicators = extractor.analyze(artifact)
    print(f"      Urgency: {indicators.get('urgency_detected')}, Brand: {indicators.get('brand_impersonation', {}).get('brand_name')}")

    print("\n[3/5] 🔗 Analyzing links (via MCP)...")
    link_analyzer = LinkAnalyzerAgent()
    link_findings = link_analyzer.analyze(artifact.extracted_entities.urls)
    print(f"      Analyzed {len(link_findings)} links.")

    print("\n[4/5] ⚖️  Scoring risk...")
    scoring = ScoringAgent()
    risk_assessment = scoring.calculate_score(indicators, link_findings)
    print(f"      Score: {risk_assessment.get('risk_score')}/100 ({risk_assessment.get('severity_label')})")

    print("\n[5/5] 📝 Generating report...")
    report_agent = ReportAgent()
    report = report_agent.generate_report(
        artifact.model_dump(), 
        risk_assessment, 
        link_findings, 
        indicators
    )

    print("\n" + "="*60)
    print(report)
    print("="*60)

if __name__ == "__main__":
    main()
