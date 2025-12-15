"""
ACDI API - Automated Cryptographic Discovery & Intelligence
IFG Quantum Holdings
"""

import os
import re
import socket
import ssl
import uuid
import io
from datetime import datetime, timedelta
from typing import Optional, List, Dict
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

API_VERSION = "1.2.0"

scan_sessions: Dict[str, Dict] = {}
scan_results: Dict[str, Dict] = {}

QUANTUM_VULNERABLE = ["RSA", "ECDSA", "ECDH", "DSA", "DH", "Ed25519", "Ed448"]
WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]

class ScanRequest(BaseModel):
    targetNetworks: List[str]
    scanDepth: str = "surface"
    ports: Optional[List[int]] = [443, 8443, 8080]

@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"[ACDI] Starting ACDI API v{API_VERSION}")
    yield
    print("[ACDI] Shutting down")

app = FastAPI(title="ACDI API", version=API_VERSION, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def is_valid_domain(target: str) -> bool:
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, target))

def resolve_domain(domain: str) -> Optional[str]:
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def is_quantum_vulnerable(algo: str) -> bool:
    return any(v in algo.upper() for v in QUANTUM_VULNERABLE)

def calculate_risk_score(assets: List[Dict]) -> int:
    if not assets:
        return 0
    vuln = sum(1 for a in assets if a.get("quantumVulnerable", False))
    return min(100, int((vuln / len(assets)) * 100))

async def scan_tls_host(host: str, port: int = 443) -> Optional[Dict]:
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        ip = resolve_domain(host) if is_valid_domain(host) else host
        if not ip:
            return None
        
        conn = socket.create_connection((ip, port), timeout=10)
        sock = context.wrap_socket(conn, server_hostname=host if is_valid_domain(host) else None)
        
        cipher = sock.cipher()
        version = sock.version()
        sock.close()
        
        cipher_name = cipher[0] if cipher else "Unknown"
        key_bits = cipher[2] if cipher and len(cipher) > 2 else 0
        
        key_exchange = "RSA"
        if "ECDHE" in cipher_name:
            key_exchange = "ECDHE"
        elif "DHE" in cipher_name:
            key_exchange = "DHE"
        elif "ECDH" in cipher_name:
            key_exchange = "ECDH"
        
        vulnerable = is_quantum_vulnerable(key_exchange)
        
        recommendations = []
        if vulnerable:
            recommendations.append(f"Migrate {key_exchange} to post-quantum (ML-KEM)")
        if version in WEAK_PROTOCOLS:
            recommendations.append(f"Upgrade {version} to TLS 1.3")
        
        return {
            "host": host,
            "port": port,
            "protocol": version,
            "cipherSuites": [cipher_name],
            "keyExchange": key_exchange,
            "keySize": key_bits,
            "quantumVulnerable": vulnerable,
            "vulnerabilityDetails": "Vulnerable to Shor's algorithm" if vulnerable else None,
            "recommendations": recommendations
        }
    except Exception as e:
        print(f"[ACDI] Error scanning {host}:{port}: {e}")
        return None

async def run_scan(session_id: str, targets: List[str], ports: List[int]):
    try:
        scan_sessions[session_id]["status"] = "running"
        all_assets = []
        
        for i, target in enumerate(targets):
            scan_sessions[session_id]["progress"] = int(((i + 1) / len(targets)) * 100)
            scan_sessions[session_id]["currentTarget"] = target
            
            for port in ports:
                result = await scan_tls_host(target, port)
                if result:
                    all_assets.append(result)
                    scan_sessions[session_id]["assetsDiscovered"] = len(all_assets)
        
        vuln_count = sum(1 for a in all_assets if a.get("quantumVulnerable"))
        
        scan_results[session_id] = {
            "scanId": session_id,
            "generatedAt": datetime.utcnow().isoformat(),
            "targetsSummary": targets,
            "totalAssets": len(all_assets),
            "quantumVulnerableCount": vuln_count,
            "quantumSafeCount": len(all_assets) - vuln_count,
            "assets": all_assets,
            "riskScore": calculate_risk_score(all_assets),
            "complianceStatus": {
                "OMB_M-23-02": len(all_assets) > 0,
                "NIST_PQC": vuln_count == 0,
                "CNSA_2.0": vuln_count == 0
            },
            "recommendations": [f"CRITICAL: {vuln_count} assets need PQC migration"] if vuln_count > 0 else ["No critical issues"]
        }
        
        scan_sessions[session_id]["status"] = "completed"
        scan_sessions[session_id]["progress"] = 100
        
    except Exception as e:
        scan_sessions[session_id]["status"] = "failed"
        scan_sessions[session_id]["errors"].append(str(e))

@app.get("/")
async def root():
    return {"service": "ACDI API", "version": API_VERSION, "vendor": "IFG Quantum Holdings"}

@app.get("/api/v1/health")
async def health():
    return {"status": "healthy", "version": API_VERSION}

@app.post("/api/v1/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    session_id = f"SCAN-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
    scan_sessions[session_id] = {
        "sessionId": session_id,
        "status": "queued",
        "progress": 0,
        "assetsDiscovered": 0,
        "currentTarget": None,
        "errors": []
    }
    background_tasks.add_task(run_scan, session_id, request.targetNetworks, request.ports)
    return {"sessionId": session_id, "status": "queued"}

@app.get("/api/v1/scan/{session_id}/status")
async def get_status(session_id: str):
    if session_id not in scan_sessions:
        raise HTTPException(404, "Session not found")
    s = scan_sessions[session_id]
    return {
        "sessionId": s["sessionId"],
        "status": s["status"],
        "progress": s["progress"],
        "assetsDiscovered": s["assetsDiscovered"],
        "currentTarget": s.get("currentTarget"),
        "errors": s.get("errors", [])
    }

@app.get("/api/v1/scan/{session_id}/cbom")
async def get_cbom(session_id: str):
    if session_id not in scan_results:
        raise HTTPException(404, "Results not found")
    return scan_results[session_id]

@app.get("/api/v1/demo/quick-scan")
async def quick_scan(target: str = Query(...)):
    assets = []
    for port in [443, 8443]:
        result = await scan_tls_host(target, port)
        if result:
            assets.append(result)
    
    vuln = sum(1 for a in assets if a.get("quantumVulnerable"))
    return {
        "target": target,
        "scanned": True,
        "realData": len(assets) > 0,
        "assets": assets,
        "summary": {
            "totalAssets": len(assets),
            "quantumVulnerable": vuln,
            "quantumSafe": len(assets) - vuln,
            "riskScore": calculate_risk_score(assets)
        }
    }

@app.get("/api/v1/report/{target}/html")
async def report_html(target: str):
    assets = []
    for port in [443, 8443, 8080]:
        result = await scan_tls_host(target, port)
        if result:
            assets.append(result)
    
    vuln_count = sum(1 for a in assets if a.get("quantumVulnerable"))
    risk = calculate_risk_score(assets)
    
    asset_html = ""
    for a in assets:
        status = "⚠️ VULNERABLE" if a.get("quantumVulnerable") else "✅ SAFE"
        color = "vulnerable" if a.get("quantumVulnerable") else "safe"
        asset_html += f'<div class="asset"><strong>{a["host"]}:{a["port"]}</strong> | {a.get("protocol", "?")} | {a.get("keyExchange", "?")} | <span class="{color}">{status}</span></div>'
    
    if not asset_html:
        asset_html = "<p>No assets found</p>"
    
    html = f"""<!DOCTYPE html>
<html><head><title>ACDI Report - {target}</title>
<style>
body {{ font-family: system-ui; background: #0f172a; color: #e2e8f0; padding: 40px; }}
.container {{ max-width: 800px; margin: 0 auto; }}
h1 {{ color: #38bdf8; }}
.stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 30px 0; }}
.stat {{ background: #1e293b; padding: 20px; border-radius: 12px; text-align: center; }}
.stat-value {{ font-size: 32px; font-weight: bold; }}
.vulnerable {{ color: #f87171; }}
.safe {{ color: #4ade80; }}
.asset {{ background: #1e293b; padding: 16px; border-radius: 8px; margin: 10px 0; }}
.footer {{ text-align: center; margin-top: 40px; color: #64748b; font-size: 14px; }}
</style></head>
<body><div class="container">
<h1>ACDI Cryptographic Assessment</h1>
<p>Target: {target} | Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>
<div class="stats">
<div class="stat"><div class="stat-value">{len(assets)}</div><div>Total Assets</div></div>
<div class="stat"><div class="stat-value vulnerable">{vuln_count}</div><div>Vulnerable</div></div>
<div class="stat"><div class="stat-value safe">{len(assets) - vuln_count}</div><div>Safe</div></div>
<div class="stat"><div class="stat-value {"vulnerable" if risk > 50 else "safe"}">{risk}</div><div>Risk Score</div></div>
</div>
<h2>Discovered Assets</h2>
{asset_html}
<h2>Compliance</h2>
<div class="asset">
<p>{"✅" if len(assets) > 0 else "❌"} OMB M-23-02 - Cryptographic Inventory</p>
<p>{"✅" if vuln_count == 0 else "❌"} NIST PQC - Post-Quantum Ready</p>
<p>{"✅" if vuln_count == 0 else "❌"} NSA CNSA 2.0 - 2027 Deadline</p>
</div>
<div class="footer">
<p>Generated by ACDI - IFG Quantum Holdings</p>
<p>2025 IFG Quantum Holdings | Patents Pending | Austin, Texas</p>
</div>
</div></body></html>"""
    
    return HTMLResponse(content=html)

@app.get("/api/v1/report/{target}/json")
async def report_json(target: str):
    assets = []
    for port in [443, 8443, 8080]:
        result = await scan_tls_host(target, port)
        if result:
            assets.append(result)
    vuln = sum(1 for a in assets if a.get("quantumVulnerable"))
    return {"target": target, "assets": assets, "summary": {"total": len(assets), "vulnerable": vuln}}

@app.get("/api/v1/report/{target}/csv")
async def report_csv(target: str):
    assets = []
    for port in [443, 8443, 8080]:
        result = await scan_tls_host(target, port)
        if result:
            assets.append(result)
    
    csv = "Host,Port,Protocol,KeyExchange,Vulnerable\n"
    for a in assets:
        csv += f"{a['host']},{a['port']},{a.get('protocol','')},{a.get('keyExchange','')},{a.get('quantumVulnerable')}\n"
    
    return StreamingResponse(io.StringIO(csv), media_type="text/csv")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
