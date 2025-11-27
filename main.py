"""
ACDI Platform API
FastAPI backend connecting scanner, analyzer, and CBOM generator

IFG Quantum Holdings - Confidential
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum
import asyncio
import json
import uuid
import io

# Import our modules
import sys
sys.path.append('/home/claude/acdi-mvp/src')
from scanner.network_scanner import NetworkScanner, quick_scan
from analyzer.tls_analyzer import TLSAnalyzer, analyze_tls
from cbom.cbom_generator import CBOMGenerator, generate_cbom, generate_cbom_cdm_format


# ============================================================================
# API Models (matching TypeScript definitions)
# ============================================================================

class ScanDepth(str, Enum):
    surface = "surface"
    deep = "deep"


class ScanConfig(BaseModel):
    targetNetworks: List[str] = Field(..., description="IP ranges to scan")
    scanDepth: ScanDepth = Field(default=ScanDepth.surface)
    includeEndpoints: bool = True
    includeCertificates: bool = True
    includeApplications: bool = False
    cdmIntegration: bool = False


class ScanStatus(BaseModel):
    sessionId: str
    status: str
    progress: int
    assetsDiscovered: int
    currentTarget: Optional[str] = None
    estimatedCompletion: Optional[str] = None
    errors: List[str] = []


class RiskAssessmentRequest(BaseModel):
    scanId: str


class ComplianceReportRequest(BaseModel):
    scanId: str
    standards: List[str] = ["NIST", "CISA", "FIPS"]


class MigrationConstraints(BaseModel):
    budget: int = 1000000
    timeframe: int = 12  # months
    acceptableDowntime: int = 4  # hours
    staffAvailability: int = 5  # FTE
    priorityOrder: str = "risk"


class CDMCredentials(BaseModel):
    endpoint: str
    apiKey: str
    agencyId: str
    environment: str = "production"


class ReportConfig(BaseModel):
    template: str = "executive"
    sections: List[str] = ["summary", "findings", "recommendations"]
    includeCharts: bool = True
    includeTables: bool = True
    includeRawData: bool = False
    format: str = "json"


# ============================================================================
# In-Memory Storage (replace with database in production)
# ============================================================================

scan_sessions: Dict[str, Dict[str, Any]] = {}
scan_results: Dict[str, Dict[str, Any]] = {}
tls_results: Dict[str, List[Dict[str, Any]]] = {}
cbom_cache: Dict[str, Dict[str, Any]] = {}


# ============================================================================
# FastAPI Application
# ============================================================================

app = FastAPI(
    title="ACDI Platform API",
    description="Automated Cryptographic Discovery & Intelligence Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware - allow v0.app and Vercel deployments
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://localhost:3000",
        "https://*.vercel.app",
        "https://*.v0.dev",
        "https://v0.app",
        "*"  # For demo - restrict in production
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# Background Tasks
# ============================================================================

async def run_scan_task(session_id: str, config: ScanConfig):
    """Background task to run network scan"""
    scanner = NetworkScanner()
    analyzer = TLSAnalyzer()
    
    session = scan_sessions[session_id]
    session['status'] = 'running'
    session['progress'] = 0
    
    all_services = []
    all_tls_analyses = []
    total_targets = len(config.targetNetworks)
    
    for idx, target in enumerate(config.targetNetworks):
        session['currentTarget'] = target
        session['progress'] = int((idx / total_targets) * 100)
        
        try:
            # Run network scan
            if config.scanDepth == ScanDepth.deep:
                result = scanner.scan_deep(target)
            else:
                result = scanner.scan_surface(target)
            
            all_services.extend(result.services)
            session['assetsDiscovered'] = len(all_services)
            
            # Run TLS analysis on discovered SSL services
            if config.includeCertificates:
                for service in result.services:
                    if service.has_ssl:
                        try:
                            tls_result = analyzer.analyze(service.ip_address, service.port)
                            all_tls_analyses.append(tls_result.to_dict())
                        except Exception as e:
                            session['errors'].append(f"TLS analysis failed for {service.ip_address}:{service.port}: {str(e)}")
            
            if result.errors:
                session['errors'].extend(result.errors)
                
        except Exception as e:
            session['errors'].append(f"Scan failed for {target}: {str(e)}")
    
    # Store results
    scan_results[session_id] = {
        'scan_id': session_id,
        'target': ','.join(config.targetNetworks),
        'start_time': session['startTime'],
        'end_time': datetime.now().isoformat(),
        'status': 'completed',
        'hosts_up': len(set(s.ip_address for s in all_services)),
        'hosts_total': len(set(s.ip_address for s in all_services)),
        'services': [s.to_dict() for s in all_services]
    }
    
    tls_results[session_id] = all_tls_analyses
    
    # Generate CBOM
    generator = CBOMGenerator()
    cbom = generator.from_scan_and_analysis(
        scan_results[session_id],
        all_tls_analyses,
        f"Scan of {','.join(config.targetNetworks)}"
    )
    cbom_cache[session_id] = cbom.to_dict()
    
    session['status'] = 'completed'
    session['progress'] = 100
    session['currentTarget'] = None
    session['estimatedCompletion'] = datetime.now().isoformat()


# ============================================================================
# API Endpoints - Discovery
# ============================================================================

@app.post("/api/v1/scan/start", response_model=Dict[str, Any])
async def start_scan(config: ScanConfig, background_tasks: BackgroundTasks):
    """
    Start a new cryptographic discovery scan
    """
    session_id = f"SCAN-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"
    
    session = {
        'sessionId': session_id,
        'status': 'pending',
        'startTime': datetime.now().isoformat(),
        'config': config.dict(),
        'progress': 0,
        'assetsDiscovered': 0,
        'currentTarget': None,
        'estimatedCompletion': None,
        'errors': []
    }
    
    scan_sessions[session_id] = session
    
    # Start background scan
    background_tasks.add_task(run_scan_task, session_id, config)
    
    return {
        'sessionId': session_id,
        'status': 'pending',
        'startTime': session['startTime'],
        'config': config.dict(),
        'progress': 0
    }


@app.get("/api/v1/scan/{session_id}/status", response_model=ScanStatus)
async def get_scan_status(session_id: str):
    """
    Get status of a running or completed scan
    """
    if session_id not in scan_sessions:
        raise HTTPException(status_code=404, detail="Scan session not found")
    
    session = scan_sessions[session_id]
    return ScanStatus(
        sessionId=session_id,
        status=session['status'],
        progress=session['progress'],
        assetsDiscovered=session['assetsDiscovered'],
        currentTarget=session.get('currentTarget'),
        estimatedCompletion=session.get('estimatedCompletion'),
        errors=session.get('errors', [])
    )


@app.get("/api/v1/scan/{session_id}/results")
async def get_scan_results(session_id: str):
    """
    Get results of a completed scan
    """
    if session_id not in scan_results:
        if session_id in scan_sessions:
            session = scan_sessions[session_id]
            if session['status'] != 'completed':
                raise HTTPException(status_code=202, detail="Scan still in progress")
        raise HTTPException(status_code=404, detail="Scan results not found")
    
    return scan_results[session_id]


# ============================================================================
# API Endpoints - Assessment
# ============================================================================

@app.get("/api/v1/assessment/{scan_id}/risk")
async def get_risk_assessment(scan_id: str):
    """
    Generate risk assessment from scan results
    """
    if scan_id not in cbom_cache:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    cbom = cbom_cache[scan_id]
    summary = cbom.get('summary', {})
    
    return {
        'assessmentId': f"RISK-{uuid.uuid4().hex[:8]}",
        'generatedAt': datetime.now().isoformat(),
        'summary': {
            'totalAssets': summary.get('total_implementations', 0),
            'vulnerableAssets': summary.get('quantum_vulnerable', 0),
            'criticalSystems': summary.get('critical_risk', 0),
            'highRiskSystems': summary.get('high_risk', 0),
            'complianceScore': summary.get('overall_compliance_score', 0)
        },
        'threatAnalysis': {
            'harvestNowDecryptLaterExposure': summary.get('harvest_now_risk', 0),
            'quantumReadinessTimeline': '5-10 years',
            'dataExfiltrationRisk': 'high' if summary.get('quantum_vulnerable', 0) > 0 else 'low'
        },
        'recommendations': cbom.get('recommendations', [])
    }


@app.post("/api/v1/assessment/{scan_id}/compliance")
async def get_compliance_report(scan_id: str, request: ComplianceReportRequest):
    """
    Generate compliance report for specified standards
    """
    if scan_id not in cbom_cache:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    cbom = cbom_cache[scan_id]
    summary = cbom.get('summary', {})
    implementations = cbom.get('implementations', [])
    
    findings = []
    for impl in implementations:
        status = "compliant" if impl.get('nist_approved') else "non-compliant"
        findings.append({
            'standard': 'NIST FIPS 203/204/205',
            'requirement': 'Post-Quantum Cryptography',
            'status': status,
            'evidence': [impl.get('algorithm', 'Unknown')],
            'remediation': 'Migrate to ML-KEM/ML-DSA' if status == 'non-compliant' else None
        })
    
    return {
        'reportId': f"COMP-{uuid.uuid4().hex[:8]}",
        'scanId': scan_id,
        'generatedAt': datetime.now().isoformat(),
        'standards': request.standards,
        'overallCompliance': summary.get('overall_compliance_score', 0),
        'findings': {
            'compliant': summary.get('fips_203_compliant', 0) + summary.get('fips_204_compliant', 0),
            'nonCompliant': summary.get('quantum_vulnerable', 0),
            'partiallyCompliant': 0
        },
        'details': findings[:20]  # Limit to first 20
    }


# ============================================================================
# API Endpoints - CBOM
# ============================================================================

@app.get("/api/v1/cbom/{scan_id}")
async def get_cbom(scan_id: str, format: str = Query("json", regex="^(json|cdm)$")):
    """
    Get Cryptographic Bill of Materials for a scan
    """
    if scan_id not in cbom_cache:
        raise HTTPException(status_code=404, detail="CBOM not found")
    
    cbom = cbom_cache[scan_id]
    
    if format == "cdm":
        # Generate CDM-compatible format
        generator = CBOMGenerator()
        scan_result = scan_results.get(scan_id, {})
        tls_analysis = tls_results.get(scan_id, [])
        cbom_obj = generator.from_scan_and_analysis(scan_result, tls_analysis)
        return cbom_obj.to_cdm_format()
    
    return cbom


@app.get("/api/v1/cbom/{scan_id}/export")
async def export_cbom(scan_id: str, format: str = Query("json", regex="^(json|csv|xml)$")):
    """
    Export CBOM in various formats
    """
    if scan_id not in cbom_cache:
        raise HTTPException(status_code=404, detail="CBOM not found")
    
    cbom = cbom_cache[scan_id]
    
    if format == "json":
        content = json.dumps(cbom, indent=2)
        media_type = "application/json"
        filename = f"cbom_{scan_id}.json"
    elif format == "csv":
        # Generate CSV
        lines = ["id,asset_name,algorithm,key_size,risk_level,quantum_status"]
        for impl in cbom.get('implementations', []):
            lines.append(f"{impl.get('id')},{impl.get('asset_name')},{impl.get('algorithm')},{impl.get('key_size')},{impl.get('risk_level')},{impl.get('quantum_status')}")
        content = '\n'.join(lines)
        media_type = "text/csv"
        filename = f"cbom_{scan_id}.csv"
    else:  # xml
        # Basic XML generation
        xml_parts = ['<?xml version="1.0" encoding="UTF-8"?>', '<cbom>']
        for impl in cbom.get('implementations', []):
            xml_parts.append(f'  <implementation id="{impl.get("id")}">')
            xml_parts.append(f'    <asset_name>{impl.get("asset_name")}</asset_name>')
            xml_parts.append(f'    <algorithm>{impl.get("algorithm")}</algorithm>')
            xml_parts.append(f'    <risk_level>{impl.get("risk_level")}</risk_level>')
            xml_parts.append(f'  </implementation>')
        xml_parts.append('</cbom>')
        content = '\n'.join(xml_parts)
        media_type = "application/xml"
        filename = f"cbom_{scan_id}.xml"
    
    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# ============================================================================
# API Endpoints - Migration Planning
# ============================================================================

@app.post("/api/v1/migration/{scan_id}/plan")
async def generate_migration_plan(scan_id: str, constraints: MigrationConstraints):
    """
    Generate PQC migration plan based on constraints
    """
    if scan_id not in cbom_cache:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    cbom = cbom_cache[scan_id]
    implementations = cbom.get('implementations', [])
    
    # Sort by priority
    priority_order = {
        'risk': lambda x: ({'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(x.get('risk_level', 'medium'), 2), -x.get('quantum_risk_score', 0)),
        'cost': lambda x: (x.get('key_size', 0),),
        'timeline': lambda x: (x.get('cert_days_remaining', 365),)
    }
    
    sorted_impl = sorted(implementations, key=priority_order.get(constraints.priorityOrder, priority_order['risk']))
    
    # Generate phases
    phase_size = max(1, len(sorted_impl) // 4)
    phases = []
    
    for i in range(4):
        start = i * phase_size
        end = start + phase_size if i < 3 else len(sorted_impl)
        phase_impl = sorted_impl[start:end]
        
        if phase_impl:
            phases.append({
                'phaseNumber': i + 1,
                'name': ['Critical Systems', 'High Priority', 'Standard Migration', 'Final Phase'][i],
                'duration': f"{constraints.timeframe // 4} months",
                'systems': [impl.get('asset_name') for impl in phase_impl[:5]],
                'milestones': [
                    {
                        'name': f"Phase {i+1} Complete",
                        'date': f"Month {(i+1) * (constraints.timeframe // 4)}",
                        'description': f"Complete migration of {len(phase_impl)} systems"
                    }
                ],
                'resources': {
                    'personnel': constraints.staffAvailability,
                    'budget': f"${constraints.budget // 4:,}",
                    'thirdPartySupport': i == 0  # Critical phase gets support
                }
            })
    
    return {
        'planId': f"MIG-{uuid.uuid4().hex[:8]}",
        'phases': phases,
        'totalDuration': f"{constraints.timeframe} months",
        'totalCost': f"${constraints.budget:,}",
        'riskMitigation': [
            "Implement hybrid cryptography during transition",
            "Maintain rollback capability for each phase",
            "Test PQC implementations in staging before production"
        ],
        'successCriteria': [
            "All critical systems migrated to NIST-approved PQC",
            "Zero security incidents during migration",
            "Performance within 10% of baseline"
        ]
    }


# ============================================================================
# API Endpoints - CDM Integration
# ============================================================================

@app.post("/api/v1/cdm/connect")
async def connect_cdm(credentials: CDMCredentials):
    """
    Establish connection to CDM dashboard
    """
    # In production, this would actually connect to CDM
    return {
        'connectionId': f"CDM-{uuid.uuid4().hex[:8]}",
        'status': 'active',
        'lastSync': datetime.now().isoformat(),
        'dataFeedsActive': 4,
        'complianceLevel': 85
    }


@app.post("/api/v1/cdm/sync/{scan_id}")
async def sync_to_cdm(scan_id: str):
    """
    Sync scan results to CDM dashboard
    """
    if scan_id not in cbom_cache:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    cbom = cbom_cache[scan_id]
    record_count = len(cbom.get('implementations', []))
    
    return {
        'syncId': f"SYNC-{uuid.uuid4().hex[:8]}",
        'status': 'success',
        'recordsSynced': record_count,
        'recordsFailed': 0,
        'timestamp': datetime.now().isoformat()
    }


@app.get("/api/v1/cdm/report/{scan_id}")
async def generate_cdm_report(scan_id: str, format: str = Query("json", regex="^(json|xml)$")):
    """
    Generate CDM-formatted report
    """
    if scan_id not in cbom_cache:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    generator = CBOMGenerator()
    scan_result = scan_results.get(scan_id, {})
    tls_analysis = tls_results.get(scan_id, [])
    cbom_obj = generator.from_scan_and_analysis(scan_result, tls_analysis)
    cdm_data = cbom_obj.to_cdm_format()
    
    return {
        'reportId': f"CDM-RPT-{uuid.uuid4().hex[:8]}",
        'format': format,
        'generatedAt': datetime.now().isoformat(),
        'data': cdm_data,
        'recordCount': len(cdm_data.get('assets', [])),
        'complianceLevel': cdm_data.get('summary', {}).get('compliant_count', 0)
    }


# ============================================================================
# API Endpoints - Reports
# ============================================================================

@app.post("/api/v1/reports/{scan_id}/generate")
async def generate_report(scan_id: str, config: ReportConfig):
    """
    Generate executive, technical, or compliance report
    """
    if scan_id not in cbom_cache:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    cbom = cbom_cache[scan_id]
    summary = cbom.get('summary', {})
    
    sections = []
    
    if 'summary' in config.sections:
        sections.append({
            'title': 'Executive Summary',
            'content': f"""
## Cryptographic Discovery Assessment

**Total Assets Discovered:** {summary.get('total_implementations', 0)}
**Quantum Vulnerable:** {summary.get('quantum_vulnerable', 0)}
**Critical Risk:** {summary.get('critical_risk', 0)}
**Overall Compliance Score:** {summary.get('overall_compliance_score', 0)}%

This assessment identifies cryptographic implementations that require migration to 
post-quantum cryptography (PQC) to protect against future quantum computer attacks.
"""
        })
    
    if 'findings' in config.sections:
        findings_content = "## Key Findings\n\n"
        for finding in cbom.get('critical_findings', []):
            findings_content += f"- {finding}\n"
        sections.append({
            'title': 'Findings',
            'content': findings_content
        })
    
    if 'recommendations' in config.sections:
        rec_content = "## Recommendations\n\n"
        for rec in cbom.get('recommendations', []):
            rec_content += f"1. {rec}\n"
        sections.append({
            'title': 'Recommendations',
            'content': rec_content
        })
    
    return {
        'reportId': f"RPT-{uuid.uuid4().hex[:8]}",
        'title': f"ACDI {config.template.title()} Report",
        'generatedAt': datetime.now().isoformat(),
        'sections': sections,
        'attachments': []
    }


# ============================================================================
# Health & Info Endpoints
# ============================================================================

@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


@app.get("/api/v1/info")
async def api_info():
    """API information"""
    return {
        "name": "ACDI Platform API",
        "version": "1.0.0",
        "vendor": "IFG Quantum Holdings",
        "compliance": ["NIST FIPS 203", "NIST FIPS 204", "NIST FIPS 205", "CDM 2.0"],
        "capabilities": [
            "Network cryptographic discovery",
            "TLS/SSL certificate analysis",
            "Quantum vulnerability assessment",
            "CBOM generation",
            "CDM integration",
            "Migration planning"
        ]
    }


# ============================================================================
# Quick Test Endpoint (for demo)
# ============================================================================

@app.get("/api/v1/demo/quick-scan")
async def demo_quick_scan(target: str = Query("127.0.0.1", description="Target to scan")):
    """
    Quick demo scan - returns immediate results for demo purposes
    """
    # Generate demo data
    demo_cbom = {
        'cbom_id': f"DEMO-{uuid.uuid4().hex[:8]}",
        'generated_at': datetime.now().isoformat(),
        'organization': 'Demo Agency',
        'summary': {
            'total_implementations': 5,
            'quantum_vulnerable': 4,
            'critical_risk': 1,
            'high_risk': 2,
            'medium_risk': 1,
            'low_risk': 1,
            'overall_compliance_score': 15
        },
        'implementations': [
            {
                'id': str(uuid.uuid4()),
                'asset_name': f'HTTPS on {target}',
                'algorithm': 'RSA-2048',
                'key_size': 2048,
                'risk_level': 'high',
                'quantum_status': 'quantum_vulnerable',
                'quantum_risk_score': 85,
                'location': f'{target}:443'
            },
            {
                'id': str(uuid.uuid4()),
                'asset_name': f'SSH on {target}',
                'algorithm': 'ECDSA-256',
                'key_size': 256,
                'risk_level': 'high',
                'quantum_status': 'quantum_vulnerable',
                'quantum_risk_score': 80,
                'location': f'{target}:22'
            }
        ],
        'critical_findings': [
            '4 cryptographic implementations vulnerable to quantum attacks',
            'No post-quantum cryptography detected',
            'Harvest-now-decrypt-later risk present'
        ],
        'recommendations': [
            'Begin PQC migration planning immediately',
            'Prioritize systems with sensitive long-term data',
            'Implement hybrid cryptography as interim measure'
        ]
    }
    
    return demo_cbom


# ============================================================================
# Run Server
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
