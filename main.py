"""
ACDI API - Automated Cryptographic Discovery & Intelligence
IFG Quantum Holdings
Production-ready backend for cryptographic asset discovery
"""

import asyncio
import hashlib
import json
import os
import re
import socket
import ssl
import subprocess
import uuid
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
import io

# ============================================
# CONFIGURATION
# ============================================

API_VERSION = "1.2.0"
API_TITLE = "ACDI - Automated Cryptographic Discovery & Intelligence"
API_DESCRIPTION = """
Post-quantum cryptographic discovery platform by IFG Quantum Holdings.
Identifies quantum-vulnerable encryption across networks and generates 
Cryptographic Bill of Materials (CBOM) for compliance reporting.
"""

# In-memory storage (use Redis in production)
scan_sessions: Dict[str, Dict] = {}
scan_results: Dict[str, Dict] = {}

# Quantum vulnerability classifications
QUANTUM_VULNERABLE_ALGORITHMS = {
    "RSA": {"vulnerable": True, "reason": "Broken by Shor's algorithm", "timeline": "2030-2035"},
    "ECDSA": {"vulnerable": True, "reason": "Broken by Shor's algorithm", "timeline": "2030-2035"},
    "ECDH": {"vulnerable": True, "reason": "Broken by Shor's algorithm", "timeline": "2030-2035"},
    "DSA": {"vulnerable": True, "reason": "Broken by Shor's algorithm", "timeline": "2030-2035"},
    "DH": {"vulnerable": True, "reason": "Broken by Shor's algorithm", "timeline": "2030-2035"},
    "Ed25519": {"vulnerable": True, "reason": "Broken by Shor's algorithm", "timeline": "2030-2035"},
    "Ed448": {"vulnerable": True, "reason": "Broken by Shor's algorithm", "timeline": "2030-2035"},
    "AES-128": {"vulnerable": False, "reason": "Grover reduces to 64-bit (upgrade to 256)", "timeline": "N/A"},
    "AES-256": {"vulnerable": False, "reason": "Grover reduces to 128-bit (still secure)", "timeline": "N/A"},
    "SHA-256": {"vulnerable": False, "reason": "Grover impact minimal", "timeline": "N/A"},
    "SHA-384": {"vulnerable": False, "reason": "Grover impact minimal", "timeline": "N/A"},
    "ChaCha20": {"vulnerable": False, "reason": "Symmetric - Grover impact only", "timeline": "N/A"},
}

WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]
RECOMMENDED_PROTOCOLS = ["TLSv1.2", "TLSv1.3"]

# ============================================
# PYDANTIC MODELS
# ============================================

class ScanRequest(BaseModel):
    targetNetworks: List[str] = Field(..., description="List of targets (domains, IPs, or CIDR ranges)")
    scanDepth: str = Field(default="surface", description="Scan depth: surface, standard, deep")
    ports: Optional[List[int]] = Field(default=[443, 8443, 8080, 993, 995, 587, 465], description="Ports to scan")

class ScanStatus(BaseModel):
    sessionId: str
    status: str  # queued, running, completed, failed
    progress: int
    assetsDiscovered: int
    currentTarget: Optional[str] = None
    estimatedCompletion: Optional[str] = None
    errors: List[str] = []

class CryptoAsset(BaseModel):
    host: str
    port: int
    protocol: str
    certificate: Optional[Dict] = None
    cipherSuites: List[str] = []
    keyExchange: Optional[str] = None
    keySize: Optional[int] = None
    quantumVulnerable: bool
    vulnerabilityDetails: Optional[str] = None
    recommendations: List[str] = []

class CBOM(BaseModel):
    scanId: str
    generatedAt: str
    organization: Optional[str] = None
    targetsSummary: List[str]
    totalAssets: int
    quantumVulnerableCount: int
    quantumSafeCount: int
    assets: List[CryptoAsset]
    riskScore: int  # 0-100
    complianceStatus: Dict[str, bool]
    recommendations: List[str]

# ============================================
# LIFESPAN & APP SETUP
# ============================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print(f"[ACDI] Starting ACDI API v{API_VERSION}")
    print(f"[ACDI] Quantum vulnerability database loaded: {len(QUANTUM_VULNERABLE_ALGORITHMS)} algorithms")
    yield
    # Shutdown
    print("[ACDI] Shutting down ACDI API")

app = FastAPI(
    title=API_TITLE,
    description=API_DESCRIPTION,
    version=API_VERSION,
    lifespan=lifespan
)

# CORS - allow frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================
# UTILITY FUNCTIONS
# ============================================

def is_valid_domain(target: str) -> bool:
    """Check if target looks like a domain name"""
    domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(domain_pattern, target))

def is_valid_ip(target: str) -> bool:
    """Check if target is a valid IP address"""
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, target):
        parts = target.split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    return False

def is_cidr(target: str) -> bool:
    """Check if target is a CIDR range"""
    cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    return bool(re.match(cidr_pattern, target))

def resolve_domain(domain: str) -> Optional[str]:
    """Resolve domain to IP address"""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def classify_algorithm(algo_name: str) -> Dict:
    """Classify an algorithm for quantum vulnerability"""
    algo_upper = algo_name.upper()
    
    for known_algo, info in QUANTUM_VULNERABLE_ALGORITHMS.items():
        if known_algo.upper() in algo_upper:
            return info
    
    # Default: assume vulnerable if uses RSA/EC/DH
    if any(x in algo_upper for x in ["RSA", "EC", "DH", "DSA", "ECDSA", "ECDHE"]):
        return {"vulnerable": True, "reason": "Uses quantum-vulnerable key exchange", "timeline": "2030-2035"}
    
    return {"vulnerable": False, "reason": "Unknown algorithm - manual review recommended", "timeline": "N/A"}

def calculate_risk_score(assets: List[Dict]) -> int:
    """Calculate overall risk score 0-100"""
    if not assets:
        return 0
    
    vulnerable_count = sum(1 for a in assets if a.get("quantumVulnerable", False))
    weak_protocol_count = sum(1 for a in assets if a.get("protocol", "") in WEAK_PROTOCOLS)
    
    # Base score on percentage of vulnerable assets
    vuln_percentage = (vulnerable_count / len(assets)) * 100
    
    # Add penalty for weak protocols
    weak_penalty = (weak_protocol_count / len(assets)) * 20
    
    return min(100, int(vuln_percentage + weak_penalty))

# ============================================
# TLS SCANNING FUNCTIONS
# ============================================

async def scan_tls_host(host: str, port: int = 443) -> Optional[Dict]:
    """Scan a single host:port for TLS information"""
    try:
        # Create SSL context that accepts all certs (for scanning purposes)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Resolve domain if needed
        ip = host
        if is_valid_domain(host):
            ip = resolve_domain(host)
            if not ip:
                return None
        
        # Connect and get certificate info
        conn = socket.create_connection((ip, port), timeout=10)
        sock = context.wrap_socket(conn, server_hostname=host if is_valid_domain(host) else None)
        
        # Get certificate
        cert = sock.getpeercert(binary_form=True)
        cert_dict = sock.getpeercert()
        cipher = sock.cipher()
        version = sock.version()
        
        sock.close()
        
        # Parse certificate for crypto details
        cipher_name = cipher[0] if cipher else "Unknown"
        cipher_version = cipher[1] if cipher and len(cipher) > 1 else "Unknown"
        key_bits = cipher[2] if cipher and len(cipher) > 2 else 0
        
        # Determine key exchange algorithm from cipher suite
        key_exchange = "Unknown"
        if "ECDHE" in cipher_name:
            key_exchange = "ECDHE"
        elif "DHE" in cipher_name:
            key_exchange = "DHE"
        elif "RSA" in cipher_name:
            key_exchange = "RSA"
        elif "ECDH" in cipher_name:
            key_exchange = "ECDH"
        
        # Check quantum vulnerability
        vuln_info = classify_algorithm(key_exchange)
        
        # Build recommendations
        recommendations = []
        if vuln_info["vulnerable"]:
            recommendations.append(f"Migrate {key_exchange} to post-quantum key exchange (ML-KEM)")
        if version in WEAK_PROTOCOLS:
            recommendations.append(f"Upgrade from {version} to TLS 1.3")
        if key_bits and key_bits < 256:
            recommendations.append("Increase symmetric key size to 256-bit minimum")
        
        # Extract certificate details
        cert_info = None
        if cert_dict:
            cert_info = {
                "subject": dict(x[0] for x in cert_dict.get("subject", [])),
                "issuer": dict(x[0] for x in cert_dict.get("issuer", [])),
                "notBefore": cert_dict.get("notBefore"),
                "notAfter": cert_dict.get("notAfter"),
                "serialNumber": cert_dict.get("serialNumber"),
            }
        
        return {
            "host": host,
            "port": port,
            "protocol": version,
            "certificate": cert_info,
            "cipherSuites": [cipher_name],
            "keyExchange": key_exchange,
            "keySize": key_bits,
            "quantumVulnerable": vuln_info["vulnerable"],
            "vulnerabilityDetails": vuln_info["reason"] if vuln_info["vulnerable"] else None,
            "recommendations": recommendations
        }
        
    except ssl.SSLError as e:
        print(f"[ACDI] SSL error scanning {host}:{port}: {e}")
        return None
    except socket.timeout:
        print(f"[ACDI] Timeout scanning {host}:{port}")
        return None
    except socket.error as e:
        print(f"[ACDI] Socket error scanning {host}:{port}: {e}")
        return None
    except Exception as e:
        print(f"[ACDI] Error scanning {host}:{port}: {e}")
        return None

async def scan_target(target: str, ports: List[int], session_id: str) -> List[Dict]:
    """Scan a target (domain, IP, or CIDR) on specified ports"""
    results = []
    
    # Handle different target types
    hosts_to_scan = []
    
    if is_valid_domain(target):
        hosts_to_scan = [target]
    elif is_valid_ip(target):
        hosts_to_scan = [target]
    elif is_cidr(target):
        # For CIDR, we'll scan a sample (full CIDR scanning would be too slow for demo)
        # In production, use proper network scanning libraries
        base_ip = target.split('/')[0]
        hosts_to_scan = [base_ip]  # Just scan the base for demo
    else:
        # Try as domain anyway
        hosts_to_scan = [target]
    
    for host in hosts_to_scan:
        # Update session status
        if session_id in scan_sessions:
            scan_sessions[session_id]["currentTarget"] = f"{host}"
        
        for port in ports:
            result = await scan_tls_host(host, port)
            if result:
                results.append(result)
                # Update discovered count
                if session_id in scan_sessions:
                    scan_sessions[session_id]["assetsDiscovered"] = len(results)
    
    return results

# ============================================
# BACKGROUND SCAN TASK
# ============================================

async def run_scan(session_id: str, targets: List[str], ports: List[int]):
    """Background task to run the full scan"""
    try:
        scan_sessions[session_id]["status"] = "running"
        scan_sessions[session_id]["startedAt"] = datetime.utcnow().isoformat()
        
        all_assets = []
        total_targets = len(targets)
        
        for i, target in enumerate(targets):
            # Update progress
            progress = int(((i + 1) / total_targets) * 100)
            scan_sessions[session_id]["progress"] = progress
            scan_sessions[session_id]["currentTarget"] = target
            
            # Scan target
            target_assets = await scan_target(target, ports, session_id)
            all_assets.extend(target_assets)
            
            # Update assets count
            scan_sessions[session_id]["assetsDiscovered"] = len(all_assets)
        
        # Calculate summary stats
        vulnerable_count = sum(1 for a in all_assets if a.get("quantumVulnerable", False))
        safe_count = len(all_assets) - vulnerable_count
        
        # Generate CBOM
        cbom = {
            "scanId": session_id,
            "generatedAt": datetime.utcnow().isoformat(),
            "organization": None,
            "targetsSummary": targets,
            "totalAssets": len(all_assets),
            "quantumVulnerableCount": vulnerable_count,
            "quantumSafeCount": safe_count,
            "assets": all_assets,
            "riskScore": calculate_risk_score(all_assets),
            "complianceStatus": {
                "OMB_M-23-02": len(all_assets) > 0,  # Has inventory
                "NIST_PQC": vulnerable_count == 0,    # All quantum-safe
                "CNSA_2.0": vulnerable_count == 0 and all(a.get("protocol") in RECOMMENDED_PROTOCOLS for a in all_assets)
            },
            "recommendations": generate_recommendations(all_assets, vulnerable_count)
        }
        
        # Store results
        scan_results[session_id] = cbom
        
        # Mark complete
        scan_sessions[session_id]["status"] = "completed"
        scan_sessions[session_id]["progress"] = 100
        scan_sessions[session_id]["completedAt"] = datetime.utcnow().isoformat()
        
        print(f"[ACDI] Scan {session_id} completed: {len(all_assets)} assets, {vulnerable_count} vulnerable")
        
    except Exception as e:
        print(f"[ACDI] Scan {session_id} failed: {e}")
        scan_sessions[session_id]["status"] = "failed"
        scan_sessions[session_id]["errors"].append(str(e))

def generate_recommendations(assets: List[Dict], vulnerable_count: int) -> List[str]:
    """Generate actionable recommendations based on scan results"""
    recommendations = []
    
    if vulnerable_count > 0:
        recommendations.append(f"CRITICAL: {vulnerable_count} assets use quantum-vulnerable encryption. Begin PQC migration planning.")
    
    # Check for weak protocols
    weak_assets = [a for a in assets if a.get("protocol") in WEAK_PROTOCOLS]
    if weak_assets:
        recommendations.append(f"HIGH: {len(weak_assets)} assets use deprecated TLS versions. Upgrade to TLS 1.2/1.3.")
    
    # Check for RSA key exchange
    rsa_assets = [a for a in assets if a.get("keyExchange") == "RSA"]
    if rsa_assets:
        recommendations.append(f"MEDIUM: {len(rsa_assets)} assets use RSA key exchange. Migrate to ECDHE or PQC.")
    
    if not recommendations:
        recommendations.append("No critical vulnerabilities detected. Continue monitoring for PQC readiness.")
    
    return recommendations

# ============================================
# API ENDPOINTS
# ============================================

@app.get("/")
async def root():
    return {
        "service": "ACDI API",
        "version": API_VERSION,
        "vendor": "IFG Quantum Holdings",
        "status": "operational",
        "endpoints": {
            "health": "/api/v1/health",
            "scan": "POST /api/v1/scan",
            "status": "/api/v1/scan/{session_id}/status",
            "cbom": "/api/v1/scan/{session_id}/cbom",
            "quick_scan": "/api/v1/demo/quick-scan?target=example.com",
            "report_json": "/api/v1/report/{target}/json",
            "report_html": "/api/v1/report/{target}/html",
            "report_csv": "/api/v1/report/{target}/csv",
            "report_pdf": "/api/v1/report/{target}/pdf"
        }
    }

@app.get("/api/v1/health")
async def health_check():
    return {
        "status": "healthy",
        "version": API_VERSION,
        "timestamp": datetime.utcnow().isoformat(),
        "activeSessions": len([s for s in scan_sessions.values() if s.get("status") == "running"])
    }

# ============================================
# SCAN ENDPOINTS (for frontend dashboard)
# ============================================

@app.post("/api/v1/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new scan session"""
    session_id = f"SCAN-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
    
    # Initialize session
    scan_sessions[session_id] = {
        "sessionId": session_id,
        "status": "queued",
        "progress": 0,
        "assetsDiscovered": 0,
        "currentTarget": None,
        "estimatedCompletion": (datetime.utcnow() + timedelta(minutes=2)).isoformat(),
        "errors": [],
        "targets": request.targetNetworks,
        "ports": request.ports,
        "scanDepth": request.scanDepth,
        "createdAt": datetime.utcnow().isoformat()
    }
    
    # Start background scan
    background_tasks.add_task(run_scan, session_id, request.targetNetworks, request.ports)
    
    print(f"[ACDI] Scan {session_id} queued for targets: {request.targetNetworks}")
    
    return {"sessionId": session_id, "status": "queued"}

@app.get("/api/v1/scan/{session_id}/status")
async def get_scan_status(session_id: str):
    """Get status of a scan session"""
    if session_id not in scan_sessions:
        raise HTTPException(status_code=404, detail="Scan session not found")
    
    session = scan_sessions[session_id]
    return ScanStatus(
        sessionId=session["sessionId"],
        status=session["status"],
        progress=session["progress"],
        assetsDiscovered=session["assetsDiscovered"],
        currentTarget=session.get("currentTarget"),
        estimatedCompletion=session.get("estimatedCompletion"),
        errors=session.get("errors", [])
    )

@app.get("/api/v1/scan/{session_id}/cbom")
async def get_scan_cbom(session_id: str):
    """Get CBOM results for a completed scan"""
    if session_id not in scan_results:
        if session_id in scan_sessions:
            status = scan_sessions[session_id]["status"]
            if status != "completed":
                raise HTTPException(status_code=400, detail=f"Scan not completed. Current status: {status}")
        raise HTTPException(status_code=404, detail="Scan results not found")
    
    return scan_results[session_id]

# ============================================
# QUICK SCAN / DEMO ENDPOINTS
# ============================================

@app.get("/api/v1/demo/quick-scan")
async def quick_scan(target: str = Query(..., description="Target domain or IP")):
    """Quick single-target scan for demos"""
    print(f"[ACDI] Quick scan requested for: {target}")
    
    # Default ports for quick scan
    ports = [443, 8443]
    
    assets = []
    for port in ports:
        result = await scan_tls_host(target, port)
        if result:
            assets.append(result)
    
    if not assets:
        # Return demo data if real scan fails
        return {
            "target": target,
            "scanned": True,
            "realData": False,
            "message": f"Could not connect to {target}. Showing sample data.",
            "assets": [{
                "host": target,
                "port": 443,
                "protocol": "TLSv1.2",
                "keyExchange": "ECDHE-RSA",
                "keySize": 256,
                "quantumVulnerable": True,
                "vulnerabilityDetails": "Uses ECDHE key exchange - vulnerable to Shor's algorithm",
                "recommendations": ["Migrate to ML-KEM (Kyber) for post-quantum security"]
            }],
            "summary": {
                "totalAssets": 1,
                "quantumVulnerable": 1,
                "quantumSafe": 0,
                "riskScore": 85
            }
        }
    
    vulnerable_count = sum(1 for a in assets if a.get("quantumVulnerable", False))
    
    return {
        "target": target,
        "scanned": True,
        "realData": True,
        "assets": assets,
        "summary": {
            "totalAssets": len(assets),
            "quantumVulnerable": vulnerable_count,
            "quantumSafe": len(assets) - vulnerable_count,
            "riskScore": calculate_risk_score(assets)
        }
    }

# ============================================
# REPORT GENERATION
# ============================================

@app.get("/api/v1/report/{target}/json")
async def get_report_json(target: str):
    """Generate JSON report for a target"""
    # Quick scan the target
    assets = []
    for port in [443, 8443, 8080]:
        result = await scan_tls_host(target, port)
        if result:
            assets.append(result)
    
    vulnerable_count = sum(1 for a in assets if a.get("quantumVulnerable", False))
    
    report = {
        "reportType": "ACDI Cryptographic Assessment",
        "generatedAt": datetime.utcnow().isoformat(),
        "generatedBy": "IFG Quantum Holdings",
        "target": target,
        "summary": {
            "totalAssets": len(assets),
            "quantumVulnerable": vulnerable_count,
            "quantumSafe": len(assets) - vulnerable_count,
            "riskScore": calculate_risk_score(assets),
            "complianceStatus": {
                "OMB_M-23-02": True,
                "NIST_PQC": vulnerable_count == 0,
                "CNSA_2.0": vulnerable_count == 0
            }
        },
        "assets": assets,
        "recommendations": generate_recommendations(assets, vulnerable_count)
    }
    
    return report

@app.get("/api/v1/report/{target}/html")
async def get_report_html(target: str):
    """Generate HTML report for a target"""
    # Get JSON data first
    assets = []
    for port in [443, 8443, 8080]:
        result = await scan_tls_host(target, port)
        if result:
            assets.append(result)
    
    vulnerable_count = sum(1 for a in assets if a.get("quantumVulnerable", False))
    risk_score = calculate_risk_score(assets)
    
    # Generate HTML
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ACDI Report - {target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; padding: 40px; }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        .header {{ text-align: center; margin-bottom: 40px; padding-bottom: 20px; border-bottom: 1px solid #334155; }}
        .header h1 {{ color: #38bdf8; font-size: 28px; margin-bottom: 8px; }}
        .header p {{ color: #94a3b8; }}
        .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 40px; }}
        .stat {{ background: #1e293b; padding: 24px; border-radius: 12px; text-align: center; }}
        .stat-value {{ font-size: 36px; font-weight: bold; color: #38bdf8; }}
        .stat-value.danger {{ color: #f87171; }}
        .stat-value.success {{ color: #4ade80; }}
        .stat-label {{ color: #94a3b8; font-size: 14px; margin-top: 8px; }}
        .section {{ background: #1e293b; padding: 24px; border-radius: 12px; margin-bottom: 24px; }}
        .section h2 {{ color: #f1f5f9; margin-bottom: 16px; font-size: 18px; }}
        .asset {{ background: #0f172a; padding: 16px; border-radius: 8px; margin-bottom: 12px; }}
        .asset-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }}
        .asset-host {{ font-family: monospace; color: #38bdf8; }}
        .badge {{ padding: 4px 12px; border-radius: 9999px; font-size: 12px; font-weight: 600; }}
        .badge-danger {{ background: #7f1d1d; color: #fca5a5; }}
        .badge-success {{ background: #14532d; color: #86efac; }}
        .asset-details {{ font-size: 14px; color: #94a3b8; }}
        .recommendations {{ list-style: none; }}
        .recommendations li {{ padding: 12px; background: #0f172a; border-radius: 8px; margin-bottom: 8px; border-left: 4px solid #f59e0b; }}
        .footer {{ text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #334155; color: #64748b; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 ACDI Cryptographic Assessment Report</h1>
            <p>Target: {target} | Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>
            <p style="margin-top: 8px; color: #64748b;">IFG Quantum Holdings | Post-Quantum Cryptography Assessment</p>
        </div>
        
        <div class="summary">
            <div class="stat">
                <div class="stat-value">{len(assets)}</div>
                <div class="stat-label">Total Assets</div>
            </div>
            <div class="stat">
                <div class="stat-value danger">{vulnerable_count}</div>
                <div class="stat-label">Quantum Vulnerable</div>
            </div>
            <div class="stat">
                <div class="stat-value success">{len(assets) - vulnerable_count}</div>
                <div class="stat-label">Quantum Safe</div>
            </div>
            <div class="stat">
                <div class="stat-value {'danger' if risk_score > 50 else 'success'}">{risk_score}</div>
                <div class="stat-label">Risk Score</div>
            </div>
        </div>
        
        <div class="section">
            <h2>📋 Discovered Cryptographic Assets</h2>
            {''.join(f'''
            <div class="asset">
                <div class="asset-header">
                    <span class="asset-host">{asset['host']}:{asset['port']}</span>
                    <span class="badge {'badge-danger' if asset.get('quantumVulnerable') else 'badge-success'}">
                        {'⚠️ Quantum Vulnerable' if asset.get('quantumVulnerable') else '✅ Quantum Safe'}
                    </span>
                </div>
                <div class="asset-details">
                    Protocol: {asset.get('protocol', 'Unknown')} | 
                    Key Exchange: {asset.get('keyExchange', 'Unknown')} |
                    Key Size: {asset.get('keySize', 'Unknown')} bits
                    {f"<br><strong>Risk:</strong> {asset.get('vulnerabilityDetails')}" if asset.get('vulnerabilityDetails') else ''}
                </div>
            </div>
            ''' for asset in assets) if assets else '<p style="color: #94a3b8;">No assets discovered. Target may be unreachable.</p>'}
        </div>
        
        <div class="section">
            <h2>📝 Recommendations</h2>
            <ul class="recommendations">
                {''.join(f'<li>{rec}</li>' for rec in generate_recommendations(assets, vulnerable_count))}
            </ul>
        </div>
        
        <div class="section">
            <h2>📊 Compliance Status</h2>
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px;">
                <div class="asset" style="text-align: center;">
                    <div style="font-size: 24px;">{'✅' if len(assets) > 0 else '❌'}</div>
                    <div style="font-weight: bold; margin-top: 8px;">OMB M-23-02</div>
                    <div style="font-size: 12px; color: #94a3b8;">Cryptographic Inventory</div>
                </div>
                <div class="asset" style="text-align: center;">
                    <div style="font-size: 24px;">{'✅' if vulnerable_count == 0 else '❌'}</div>
                    <div style="font-weight: bold; margin-top: 8px;">NIST PQC</div>
                    <div style="font-size: 12px; color: #94a3b8;">Post-Quantum Ready</div>
                </div>
                <div class="asset" style="text-align: center;">
                    <div style="font-size: 24px;">{'✅' if vulnerable_count == 0 else '❌'}</div>
                    <div style="font-weight: bold; margin-top: 8px;">NSA CNSA 2.0</div>
                    <div style="font-size: 12px; color: #94a3b8;">2027 Deadline</div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by ACDI - Automated Cryptographic Discovery & Intelligence</p>
            <p>© 2025 IFG Quantum Holdings | Patents Pending | Austin, Texas</p>
        </div>
    </div>
</body>
</html>
"""
    
    return HTMLResponse(content=html)

@app.get("/api/v1/report/{target}/csv")
async def get_report_csv(target: str):
    """Generate CSV report for a target"""
    assets = []
    for port in [443, 8443, 8080]:
        result = await scan_tls_host(target, port)
        if result:
            assets.append(result)
    
    # Generate CSV
    csv_lines = ["Host,Port,Protocol,Key Exchange,Key Size,Quantum Vulnerable,Vulnerability Details"]
    
    for asset in assets:
        csv_lines.append(
            f"{asset['host']},{asset['port']},{asset.get('protocol', '')},{asset.get('keyExchange', '')},"
            f"{asset.get('keySize', '')},{asset.get('quantumVulnerable', False)},\"{asset.get('vulnerabilityDetails', '')}\""
        )
    
    csv_content = "\n".join(csv_lines)
    
    return StreamingResponse(
        io.StringIO(csv_content),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=acdi-report-{target}-{datetime.utcnow().strftime('%Y%m%d')}.csv"}
    )

@app.get("/api/v1/report/{target}/pdf")
async def get_report_pdf(target: str):
    """Generate PDF report for a target"""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    
    # Scan the target
    assets = []
    for port in [443, 8443, 8080]:
        result = await scan_tls_host(target, port)
        if result:
            assets.append(result)
    
    vulnerable_count = sum(1 for a in assets if a.get("quantumVulnerable", False))
    risk_score = calculate_risk_score(assets)
    
    # Create PDF buffer
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
    
    # Styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=12,
        alignment=TA_CENTER,
        textColor=colors.HexColor('#1e40af')
    )
    subtitle_style = ParagraphStyle(
        'CustomSubtitle',
        parent=styles['Normal'],
        fontSize=12,
        spaceAfter=20,
        alignment=TA_CENTER,
        textColor=colors.HexColor('#64748b')
    )
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        spaceBefore=20,
        spaceAfter=10,
        textColor=colors.HexColor('#1e293b')
    )
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=6
    )
    
    # Build content
    content = []
    
    # Header
    content.append(Paragraph("🔐 ACDI Cryptographic Assessment Report", title_style))
    content.append(Paragraph(f"Target: {target}", subtitle_style))
    content.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} | IFG Quantum Holdings", subtitle_style))
    content.append(Spacer(1, 20))
    
    # Executive Summary Table
    content.append(Paragraph("Executive Summary", heading_style))
    
    summary_data = [
        ["Total Assets", "Quantum Vulnerable", "Quantum Safe", "Risk Score"],
        [str(len(assets)), str(vulnerable_count), str(len(assets) - vulnerable_count), f"{risk_score}/100"]
    ]
    
    summary_table = Table(summary_data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 1.5*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('TOPPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f1f5f9')),
        ('FONTSIZE', (0, 1), (-1, -1), 12),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 10),
        ('TOPPADDING', (0, 1), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        # Color the vulnerable count red if > 0
        ('TEXTCOLOR', (1, 1), (1, 1), colors.HexColor('#dc2626') if vulnerable_count > 0 else colors.black),
        # Color risk score based on value
        ('TEXTCOLOR', (3, 1), (3, 1), colors.HexColor('#dc2626') if risk_score > 50 else colors.HexColor('#16a34a')),
    ]))
    content.append(summary_table)
    content.append(Spacer(1, 20))
    
    # Compliance Status
    content.append(Paragraph("Compliance Status", heading_style))
    
    compliance_data = [
        ["Standard", "Status", "Details"],
        ["OMB M-23-02", "✅ Compliant" if len(assets) > 0 else "❌ Non-Compliant", "Cryptographic inventory completed"],
        ["NIST PQC", "✅ Ready" if vulnerable_count == 0 else "❌ Action Required", f"{vulnerable_count} assets need PQC migration"],
        ["NSA CNSA 2.0 (2027)", "✅ On Track" if vulnerable_count == 0 else "⚠️ At Risk", "Software must support PQC by 2027"],
    ]
    
    compliance_table = Table(compliance_data, colWidths=[1.8*inch, 1.5*inch, 3*inch])
    compliance_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    content.append(compliance_table)
    content.append(Spacer(1, 20))
    
    # Discovered Assets
    content.append(Paragraph("Discovered Cryptographic Assets", heading_style))
    
    if assets:
        asset_data = [["Host:Port", "Protocol", "Key Exchange", "Key Size", "Status"]]
        for asset in assets:
            status = "⚠️ VULNERABLE" if asset.get("quantumVulnerable") else "✅ SAFE"
            asset_data.append([
                f"{asset['host']}:{asset['port']}",
                asset.get('protocol', 'Unknown'),
                asset.get('keyExchange', 'Unknown'),
                str(asset.get('keySize', 'N/A')),
                status
            ])
        
        asset_table = Table(asset_data, colWidths=[2*inch, 1*inch, 1.2*inch, 0.8*inch, 1.3*inch])
        asset_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#334155')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
        ]))
        content.append(asset_table)
    else:
        content.append(Paragraph("No assets discovered. Target may be unreachable or not running TLS services.", body_style))
    
    content.append(Spacer(1, 20))
    
    # Recommendations
    content.append(Paragraph("Recommendations", heading_style))
    recommendations = generate_recommendations(assets, vulnerable_count)
    for i, rec in enumerate(recommendations, 1):
        content.append(Paragraph(f"{i}. {rec}", body_style))
    
    content.append(Spacer(1, 30))
    
    # Footer
    footer_style = ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=8,
        alignment=TA_CENTER,
        textColor=colors.HexColor('#94a3b8')
    )
    content.append(Paragraph("─" * 80, footer_style))
    content.append(Paragraph("Generated by ACDI - Automated Cryptographic Discovery & Intelligence", footer_style))
    content.append(Paragraph("© 2025 IFG Quantum Holdings | Patents Pending | Austin, Texas", footer_style))
    content.append(Paragraph("www.ifgquantum.com | info@ifgquantum.com", footer_style))
    
    # Build PDF
    doc.build(content)
    buffer.seek(0)
    
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=ACDI-Report-{target}-{datetime.utcnow().strftime('%Y%m%d')}.pdf"}
    )

# ============================================
# ERROR HANDLERS
# ============================================

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    print(f"[ACDI] Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": str(exc)}
    )

# ============================================
# MAIN
# ============================================

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
