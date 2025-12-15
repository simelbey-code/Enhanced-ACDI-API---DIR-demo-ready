# ACDI API - Automated Cryptographic Discovery & Intelligence

**IFG Quantum Holdings** | Post-Quantum Cryptography Assessment Platform

## Overview

ACDI (Automated Cryptographic Discovery & Intelligence) is a vendor-neutral cryptographic discovery platform that identifies quantum-vulnerable encryption across networks and generates Cryptographic Bill of Materials (CBOM) for compliance reporting.

## Features

- ✅ **Real TLS Scanning** - Connects to targets and analyzes actual TLS handshakes
- ✅ **Domain & IP Support** - Accepts domains (dir.texas.gov), IPs (192.168.1.1), or CIDR ranges
- ✅ **Quantum Vulnerability Detection** - Flags RSA, ECDSA, ECDH, and other Shor-vulnerable algorithms
- ✅ **CBOM Generation** - Cryptographic Bill of Materials for compliance
- ✅ **Multiple Report Formats** - JSON, HTML, CSV export
- ✅ **Session-Based Scanning** - Async scanning with progress tracking
- ✅ **Compliance Mapping** - OMB M-23-02, NIST PQC, NSA CNSA 2.0

## API Endpoints

### Health & Info
```
GET /                           # API info
GET /api/v1/health              # Health check
```

### Scanning (Session-Based)
```
POST /api/v1/scan               # Start new scan session
GET /api/v1/scan/{id}/status    # Get scan progress
GET /api/v1/scan/{id}/cbom      # Get CBOM results
```

### Quick Scan (Demo)
```
GET /api/v1/demo/quick-scan?target=example.com
```

### Reports
```
GET /api/v1/report/{target}/json   # JSON report
GET /api/v1/report/{target}/html   # HTML report (styled)
GET /api/v1/report/{target}/csv    # CSV export
```

## Usage Examples

### Start a Scan
```bash
curl -X POST https://your-api.railway.app/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"targetNetworks": ["dir.texas.gov"], "scanDepth": "surface"}'
```

Response:
```json
{"sessionId": "SCAN-20251210-A1B2C3D4", "status": "queued"}
```

### Check Status
```bash
curl https://your-api.railway.app/api/v1/scan/SCAN-20251210-A1B2C3D4/status
```

### Get Results
```bash
curl https://your-api.railway.app/api/v1/scan/SCAN-20251210-A1B2C3D4/cbom
```

### Quick Demo Scan
```bash
curl "https://your-api.railway.app/api/v1/demo/quick-scan?target=dir.texas.gov"
```

### Generate HTML Report
```bash
curl https://your-api.railway.app/api/v1/report/dir.texas.gov/html > report.html
```

## Deployment

### Railway (Recommended)
1. Connect GitHub repo to Railway
2. Railway auto-detects Dockerfile
3. Deploy

### Local Development
```bash
pip install -r requirements.txt
python main.py
# API runs on http://localhost:8080
```

### Docker
```bash
docker build -t acdi-api .
docker run -p 8080:8080 acdi-api
```

## Quantum Vulnerability Classification

| Algorithm | Vulnerable | Reason |
|-----------|------------|--------|
| RSA | ✅ Yes | Shor's algorithm |
| ECDSA | ✅ Yes | Shor's algorithm |
| ECDH/ECDHE | ✅ Yes | Shor's algorithm |
| DH/DHE | ✅ Yes | Shor's algorithm |
| DSA | ✅ Yes | Shor's algorithm |
| AES-256 | ❌ No | Grover reduces to 128-bit (still secure) |
| SHA-256+ | ❌ No | Minimal Grover impact |
| ChaCha20 | ❌ No | Symmetric - Grover only |

## Compliance Mapping

- **OMB M-23-02**: Cryptographic inventory requirement (NOW)
- **NIST PQC**: ML-KEM, ML-DSA, SLH-DSA standards (2024-2025)
- **NSA CNSA 2.0**: Software PQC support (2027), Full PQC (2033)

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| PORT | 8080 | Server port |

## License

Proprietary - IFG Quantum Holdings

Patents Pending

---

**IFG Quantum Holdings** | Austin, Texas | info@ifgquantum.com
