# ACDI Platform API - Flat Version
# IFG Quantum Holdings

from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
import uuid
import json

# ============================================================================
# App Setup
# ============================================================================

app = FastAPI(
    title="ACDI Platform API",
    description="Automated Cryptographic Discovery & Intelligence",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# Models
# ============================================================================

class ScanConfig(BaseModel):
    targetNetworks: List[str]
    scanDepth: str = "surface"
    includeCertificates: bool = True
    includeEndpoints: bool = True

class ScanSession(BaseModel):
    sessionId: str
    status: str
    startTime: str
    progress: int = 0

# ============================================================================
# In-Memory Storage
# ============================================================================

scan_sessions = {}
cbom_cache = {}

# ============================================================================
# Demo Data Generator
# ============================================================================

def generate_demo_cbom(target: str) -> dict:
    """Generate realistic demo CBOM data"""
    now = datetime.utcnow().isoformat() + "Z"
    cbom_id = f"CBOM-{uuid.uuid4().hex[:8].upper()}"
    
    implementations = [
        {
            "id": f"IMPL-{uuid.uuid4().hex[:8].upper()}",
            "asset_name": f"web-server-01.{target}",
            "asset_ip": "10.0.1.10",
            "algorithm": "RSA",
            "key_size": 2048,
            "risk_level": "critical",
            "quantum_status": "vulnerable",
            "quantum_risk_score": 95,
            "location": "TLS Certificate",
            "cert_subject": f"CN=web-server-01.{target}",
            "cert_expiry": "2025-06-15T00:00:00Z",
            "cert_days_remaining": 200,
            "shor_vulnerable": True,
            "grover_vulnerable": False
        },
        {
            "id": f"IMPL-{uuid.uuid4().hex[:8].upper()}",
            "asset_name": f"api-gateway.{target}",
            "asset_ip": "10.0.1.20",
            "algorithm": "ECDSA",
            "key_size": 256,
            "risk_level": "high",
            "quantum_status": "vulnerable",
            "quantum_risk_score": 85,
            "location": "TLS Certificate",
            "cert_subject": f"CN=api-gateway.{target}",
            "cert_expiry": "2025-08-20T00:00:00Z",
            "cert_days_remaining": 266,
            "shor_vulnerable": True,
            "grover_vulnerable": False
        },
        {
            "id": f"IMPL-{uuid.uuid4().hex[:8].upper()}",
            "asset_name": f"database.{target}",
            "asset_ip": "10.0.2.10",
            "algorithm": "AES-256",
            "key_size": 256,
            "risk_level": "low",
            "quantum_status": "quantum_safe",
            "quantum_risk_score": 15,
            "location": "Database Encryption",
            "shor_vulnerable": False,
            "grover_vulnerable": True
        },
        {
            "id": f"IMPL-{uuid.uuid4().hex[:8].upper()}",
            "asset_name": f"mail.{target}",
            "asset_ip": "10.0.1.30",
            "algorithm": "RSA",
            "key_size": 4096,
            "risk_level": "high",
            "quantum_status": "vulnerable",
            "quantum_risk_score": 80,
            "location": "SMTP TLS",
            "cert_subject": f"CN=mail.{target}",
            "shor_vulnerable": True,
            "grover_vulnerable": False
        },
        {
            "id": f"IMPL-{uuid.uuid4().hex[:8].upper()}",
            "asset_name": f"vpn.{target}",
            "asset_ip": "10.0.0.5",
            "algorithm": "DH",
            "key_size": 2048,
            "risk_level": "critical",
            "quantum_status": "vulnerable",
            "quantum_risk_score": 92,
            "location": "VPN Key Exchange",
            "shor_vulnerable": True,
            "grover_vulnerable": False
        }
    ]
    
    summary = {
        "total_implementations": len(implementations),
        "total_assets": len(set(i["asset_name"] for i in implementations)),
        "critical_risk": sum(1 for i in implementations if i["risk_level"] == "critical"),
        "high_risk": sum(1 for i in implementations if i["risk_level"] == "high"),
        "medium_risk": sum(1 for i in implementations if i["risk_level"] == "medium"),
        "low_risk": sum(1 for i in implementations if i["risk_level"] == "low"),
        "quantum_vulnerable": sum(1 for i in implementations if i["quantum_status"] == "vulnerable"),
        "quantum_safe": sum(1 for i in implementations if i["quantum_status"] == "quantum_safe"),
        "harvest_now_risk": sum(1 for i in implementations if i.get("shor_vulnerable", False)),
        "overall_compliance_score": 25,
        "algorithms": {"RSA": 2, "ECDSA": 1, "AES-256": 1, "DH": 1},
        "key_sizes": {"2048": 2, "256": 2, "4096": 1}
    }
    
    return {
        "cbom_id": cbom_id,
        "version": "1.0",
        "schema_version": "CBOM-2024-1",
        "generated_at": now,
        "generated_by": "ACDI Platform v1.0",
        "organization": target,
        "scope_description": f"Cryptographic inventory for {target}",
        "implementations": implementations,
        "summary": summary,
        "critical_findings": [
            f"{summary['critical_risk']} critical-risk cryptographic implementations require immediate attention",
            f"{summary['quantum_vulnerable']} implementations are vulnerable to quantum attacks (Shor's algorithm)",
            f"{summary['harvest_now_risk']} systems are exposed to harvest-now-decrypt-later attacks",
            "VPN key exchange using vulnerable Diffie-Hellman"
        ],
        "recommendations": [
            "Prioritize migration of RSA-2048 certificates to hybrid PQC algorithms",
            "Implement ML-KEM (Kyber) for key encapsulation on critical systems",
            "Upgrade VPN to use quantum-resistant key exchange",
            "Plan ECDSA to ML-DSA migration for API gateway",
            "Conduct quarterly cryptographic inventory reviews"
        ],
        "migration_priority": [
            "1. vpn.{} - Critical (DH-2048)".format(target),
            "2. web-server-01.{} - Critical (RSA-2048)".format(target),
            "3. api-gateway.{} - High (ECDSA-256)".format(target),
            "4. mail.{} - High (RSA-4096)".format(target)
        ]
    }

# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/")
async def root():
    return {"message": "ACDI Platform API", "version": "1.0.0", "status": "operational"}

@app.get("/api/v1/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat() + "Z"}

@app.get("/api/v1/info")
async def info():
    return {
        "name": "ACDI Platform API",
        "version": "1.0.0",
        "vendor": "IFG Quantum Holdings",
        "compliance": ["NIST SP 800-207", "CISA ACDI", "CDM 2.0", "FIPS 203/204/205"],
        "capabilities": [
            "network_discovery",
            "tls_analysis", 
            "certificate_inventory",
            "quantum_risk_assessment",
            "cbom_generation",
            "cdm_integration"
        ]
    }

@app.post("/api/v1/scan/start")
async def start_scan(config: ScanConfig):
    session_id = f"SCAN-{uuid.uuid4().hex[:12].upper()}"
    session = {
        "sessionId": session_id,
        "status": "completed",  # Demo: instant completion
        "startTime": datetime.utcnow().isoformat() + "Z",
        "progress": 100,
        "config": config.dict()
    }
    scan_sessions[session_id] = session
    
    # Generate demo CBOM
    target = config.targetNetworks[0] if config.targetNetworks else "demo.agency.gov"
    cbom_cache[session_id] = generate_demo_cbom(target)
    
    return session

@app.get("/api/v1/scan/{session_id}/status")
async def scan_status(session_id: str):
    if session_id not in scan_sessions:
        raise HTTPException(status_code=404, detail="Scan session not found")
    session = scan_sessions[session_id]
    return {
        "sessionId": session_id,
        "status": session["status"],
        "progress": session["progress"],
        "assetsDiscovered": 5,
        "errors": []
    }

@app.get("/api/v1/scan/{session_id}/results")
async def scan_results(session_id: str):
    if session_id not in scan_sessions:
        raise HTTPException(status_code=404, detail="Scan session not found")
    return scan_sessions[session_id]

@app.get("/api/v1/cbom/{scan_id}")
async def get_cbom(scan_id: str, format: str = "json"):
    if scan_id not in cbom_cache:
        # Generate demo if not exists
        cbom_cache[scan_id] = generate_demo_cbom("demo.agency.gov")
    
    cbom = cbom_cache[scan_id]
    
    if format == "cdm":
        return {
            "cdm_version": "2.0",
            "agency_id": "DEMO",
            "assets": cbom["implementations"],
            "risk_score": 100 - cbom["summary"]["overall_compliance_score"],
            "generated_at": cbom["generated_at"]
        }
    
    return cbom

@app.get("/api/v1/assessment/{scan_id}/risk")
async def risk_assessment(scan_id: str):
    return {
        "assessmentId": f"RISK-{uuid.uuid4().hex[:8].upper()}",
        "scanId": scan_id,
        "generatedAt": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "totalAssets": 5,
            "vulnerableAssets": 4,
            "criticalSystems": 2,
            "highRiskSystems": 2,
            "complianceScore": 25
        },
        "threatAnalysis": {
            "harvestNowDecryptLaterExposure": 4,
            "quantumReadinessTimeline": "5-10 years",
            "dataExfiltrationRisk": "high"
        },
        "recommendations": [
            "Begin PQC migration planning immediately",
            "Prioritize systems handling sensitive data",
            "Implement crypto-agility framework"
        ]
    }

@app.get("/api/v1/demo/quick-scan")
async def demo_quick_scan(target: str = "demo.agency.gov"):
    """Demo endpoint - returns sample CBOM without actual scanning"""
    return generate_demo_cbom(target)

# ============================================================================
# Report Generation Endpoints
# ============================================================================

from fastapi.responses import HTMLResponse, Response

@app.get("/api/v1/report/{target}/html", response_class=HTMLResponse)
async def generate_html_report(target: str = "demo.agency.gov"):
    """Generate downloadable HTML report - can print to PDF"""
    cbom = generate_demo_cbom(target)
    s = cbom["summary"]
    
    # Build asset rows
    asset_rows = ""
    for impl in cbom["implementations"]:
        risk_color = {"critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04", "low": "#16a34a"}.get(impl["risk_level"], "#6b7280")
        asset_rows += f"""
        <tr>
            <td>{impl["asset_name"]}</td>
            <td>{impl["asset_ip"]}</td>
            <td>{impl["algorithm"]}</td>
            <td>{impl.get("key_size", "N/A")}</td>
            <td style="color: {risk_color}; font-weight: bold;">{impl["risk_level"].upper()}</td>
            <td>{impl["quantum_risk_score"]}</td>
            <td>{impl["location"]}</td>
        </tr>"""
    
    # Build findings list
    findings_html = "".join(f"<li>{f}</li>" for f in cbom["critical_findings"])
    
    # Build recommendations list
    recs_html = "".join(f"<li>{r}</li>" for r in cbom["recommendations"])
    
    # Build migration priority list
    migration_html = "".join(f"<li>{m}</li>" for m in cbom["migration_priority"])
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>ACDI Cryptographic Assessment Report - {target}</title>
        <style>
            * {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }}
            body {{ max-width: 1000px; margin: 0 auto; padding: 40px; background: #f8fafc; }}
            .header {{ background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%); color: white; padding: 40px; border-radius: 12px; margin-bottom: 30px; }}
            .header h1 {{ margin: 0 0 10px 0; font-size: 28px; }}
            .header p {{ margin: 0; opacity: 0.8; }}
            .logo {{ font-size: 14px; opacity: 0.7; margin-top: 20px; }}
            .section {{ background: white; border-radius: 12px; padding: 30px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
            .section h2 {{ margin-top: 0; color: #1e3a5f; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; }}
            .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }}
            .stat {{ background: #f1f5f9; padding: 20px; border-radius: 8px; text-align: center; }}
            .stat-value {{ font-size: 32px; font-weight: bold; color: #0f172a; }}
            .stat-label {{ font-size: 14px; color: #64748b; margin-top: 5px; }}
            .stat.critical .stat-value {{ color: #dc2626; }}
            .stat.warning .stat-value {{ color: #ea580c; }}
            .stat.success .stat-value {{ color: #16a34a; }}
            table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
            th {{ background: #1e3a5f; color: white; padding: 12px; text-align: left; }}
            td {{ padding: 12px; border-bottom: 1px solid #e2e8f0; }}
            tr:hover {{ background: #f8fafc; }}
            ul {{ padding-left: 20px; }}
            li {{ margin-bottom: 8px; line-height: 1.6; }}
            .critical-findings {{ background: #fef2f2; border-left: 4px solid #dc2626; }}
            .critical-findings h2 {{ color: #dc2626; }}
            .recommendations {{ background: #f0fdf4; border-left: 4px solid #16a34a; }}
            .recommendations h2 {{ color: #16a34a; }}
            .footer {{ text-align: center; color: #64748b; font-size: 12px; margin-top: 40px; padding-top: 20px; border-top: 1px solid #e2e8f0; }}
            @media print {{
                body {{ background: white; }}
                .section {{ box-shadow: none; border: 1px solid #e2e8f0; }}
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Cryptographic Bill of Materials (CBOM)</h1>
            <p>Quantum Vulnerability Assessment Report</p>
            <div class="logo">Generated by IFG Quantum Holdings | ACDI Platform v1.0</div>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <p><strong>Organization:</strong> {target}</p>
            <p><strong>Report ID:</strong> {cbom["cbom_id"]}</p>
            <p><strong>Generated:</strong> {cbom["generated_at"]}</p>
            <p><strong>Compliance Standards:</strong> NIST SP 800-207, CISA ACDI, CDM 2.0, FIPS 203/204/205</p>
            
            <div class="stats">
                <div class="stat">
                    <div class="stat-value">{s["total_implementations"]}</div>
                    <div class="stat-label">Total Assets</div>
                </div>
                <div class="stat critical">
                    <div class="stat-value">{s["quantum_vulnerable"]}</div>
                    <div class="stat-label">Quantum Vulnerable</div>
                </div>
                <div class="stat warning">
                    <div class="stat-value">{s["critical_risk"]}</div>
                    <div class="stat-label">Critical Risk</div>
                </div>
                <div class="stat success">
                    <div class="stat-value">{s["overall_compliance_score"]}%</div>
                    <div class="stat-label">Compliance Score</div>
                </div>
            </div>
        </div>
        
        <div class="section critical-findings">
            <h2>⚠️ Critical Findings</h2>
            <ul>{findings_html}</ul>
        </div>
        
        <div class="section">
            <h2>Cryptographic Asset Inventory</h2>
            <table>
                <thead>
                    <tr>
                        <th>Asset Name</th>
                        <th>IP Address</th>
                        <th>Algorithm</th>
                        <th>Key Size</th>
                        <th>Risk Level</th>
                        <th>Quantum Score</th>
                        <th>Location</th>
                    </tr>
                </thead>
                <tbody>
                    {asset_rows}
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>Migration Priority</h2>
            <ol>{migration_html.replace("<li>", "").replace("</li>", "<br>")}</ol>
        </div>
        
        <div class="section recommendations">
            <h2>✓ Recommendations</h2>
            <ul>{recs_html}</ul>
        </div>
        
        <div class="footer">
            <p><strong>IFG Quantum Holdings</strong> | Automated Cryptographic Discovery & Intelligence</p>
            <p>This report is generated for demonstration purposes. For production assessments, contact info@ifgquantum.com</p>
            <p>© 2025 IFG Quantum Holdings. Patent Pending.</p>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html)


@app.get("/api/v1/report/{target}/csv")
async def generate_csv_report(target: str = "demo.agency.gov"):
    """Generate downloadable CSV report"""
    cbom = generate_demo_cbom(target)
    
    # Build CSV content
    lines = ["Asset Name,IP Address,Algorithm,Key Size,Risk Level,Quantum Score,Quantum Status,Location"]
    for impl in cbom["implementations"]:
        lines.append(f'{impl["asset_name"]},{impl["asset_ip"]},{impl["algorithm"]},{impl.get("key_size", "")},{impl["risk_level"]},{impl["quantum_risk_score"]},{impl["quantum_status"]},{impl["location"]}')
    
    csv_content = "\n".join(lines)
    
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=cbom_{target.replace('.', '_')}.csv"}
    )


@app.get("/api/v1/report/{target}/json")
async def generate_json_report(target: str = "demo.agency.gov"):
    """Generate downloadable JSON report"""
    cbom = generate_demo_cbom(target)
    
    return Response(
        content=json.dumps(cbom, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=cbom_{target.replace('.', '_')}.json"}
    )


# ============================================================================
# Run Server
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
