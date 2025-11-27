"""
ACDI CBOM Generator Module
Generates Cryptographic Bill of Materials in CDM-compatible format

IFG Quantum Holdings - Confidential
"""

import json
import uuid
from dataclasses import dataclass, asdict, field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum
import hashlib


class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class QuantumVulnerability(Enum):
    VULNERABLE = "quantum_vulnerable"
    PARTIALLY_SAFE = "partially_quantum_safe"
    QUANTUM_SAFE = "quantum_safe"
    UNKNOWN = "unknown"


class ComplianceStatus(Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partially_compliant"
    NOT_APPLICABLE = "not_applicable"


@dataclass
class CryptoImplementation:
    """Individual cryptographic implementation in CBOM"""
    # Required fields first
    id: str
    discovery_timestamp: str
    asset_id: str
    asset_name: str
    asset_ip: str
    asset_hostname: str
    asset_type: str  # server, endpoint, network_device, application
    asset_criticality: str
    crypto_type: str  # tls, certificate, key_exchange, symmetric, hash, signature
    algorithm: str
    location: str  # service path, file path, etc.
    
    # Fields with defaults
    asset_owner: str = "Unknown"
    algorithm_variant: str = ""
    key_size: int = 0
    protocol_version: str = ""
    implementation_library: str = ""
    
    # Quantum assessment
    quantum_status: str = QuantumVulnerability.VULNERABLE.value
    quantum_risk_score: int = 100
    quantum_risk_factors: List[str] = field(default_factory=list)
    shor_vulnerable: bool = True  # Vulnerable to Shor's algorithm
    grover_vulnerable: bool = True  # Vulnerable to Grover's algorithm
    harvest_now_decrypt_later_risk: bool = True
    
    # Risk assessment
    risk_level: str = RiskLevel.HIGH.value
    risk_factors: List[str] = field(default_factory=list)
    data_sensitivity: str = "unknown"
    data_lifespan_years: int = 0
    
    # Compliance
    fips_203_compliant: bool = False  # ML-KEM
    fips_204_compliant: bool = False  # ML-DSA
    fips_205_compliant: bool = False  # SLH-DSA
    nist_approved: bool = False
    compliance_score: int = 0
    compliance_gaps: List[str] = field(default_factory=list)
    
    # Certificate-specific (if applicable)
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_expiry: str = ""
    cert_days_remaining: int = 0
    cert_fingerprint: str = ""
    
    # Metadata
    discovery_method: str = ""
    confidence_score: int = 100
    last_seen: str = ""
    notes: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CBOMSummary:
    """Summary statistics for CBOM"""
    total_implementations: int = 0
    total_assets: int = 0
    
    # By risk level
    critical_risk: int = 0
    high_risk: int = 0
    medium_risk: int = 0
    low_risk: int = 0
    
    # Quantum stats
    quantum_vulnerable: int = 0
    quantum_safe: int = 0
    harvest_now_risk: int = 0
    
    # Compliance stats
    fips_203_compliant: int = 0
    fips_204_compliant: int = 0
    fips_205_compliant: int = 0
    overall_compliance_score: int = 0
    
    # Algorithm breakdown
    algorithms: Dict[str, int] = field(default_factory=dict)
    key_sizes: Dict[str, int] = field(default_factory=dict)
    protocols: Dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CBOM:
    """Complete Cryptographic Bill of Materials"""
    cbom_id: str
    version: str = "1.0"
    schema_version: str = "ACDI-CBOM-1.0"
    
    # Generation metadata
    generated_at: str = ""
    generated_by: str = "IFG ACDI Platform"
    scan_id: str = ""
    
    # Scope
    organization: str = ""
    scope_description: str = ""
    target_networks: List[str] = field(default_factory=list)
    
    # Content
    implementations: List[CryptoImplementation] = field(default_factory=list)
    summary: CBOMSummary = field(default_factory=CBOMSummary)
    
    # Recommendations
    critical_findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    migration_priority: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['implementations'] = [i.to_dict() for i in self.implementations]
        result['summary'] = self.summary.to_dict()
        return result
    
    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)
    
    def to_cdm_format(self) -> Dict[str, Any]:
        """Convert to CDM-compatible format"""
        return {
            "cdm_version": "2.0",
            "data_type": "CRYPTOGRAPHIC_INVENTORY",
            "timestamp": self.generated_at,
            "agency_id": self.organization,
            "assets": [
                {
                    "asset_id": impl.asset_id,
                    "asset_type": "CRYPTOGRAPHIC_IMPLEMENTATION",
                    "vulnerability_score": impl.quantum_risk_score,
                    "risk_category": impl.risk_level.upper(),
                    "compliance_status": "COMPLIANT" if impl.nist_approved else "NON_COMPLIANT",
                    "remediation_priority": self._get_remediation_priority(impl),
                    "last_assessed": impl.discovery_timestamp,
                    "assessment_method": "QUANTUM_VULNERABILITY_ANALYSIS",
                    "details": {
                        "algorithm": impl.algorithm,
                        "key_size": impl.key_size,
                        "quantum_vulnerable": impl.quantum_status == QuantumVulnerability.VULNERABLE.value,
                        "location": impl.location
                    }
                }
                for impl in self.implementations
            ],
            "summary": {
                "total_assets": self.summary.total_assets,
                "vulnerable_count": self.summary.quantum_vulnerable,
                "compliant_count": self.summary.fips_203_compliant + self.summary.fips_204_compliant + self.summary.fips_205_compliant,
                "overall_risk_score": 100 - self.summary.overall_compliance_score
            }
        }
    
    def _get_remediation_priority(self, impl: CryptoImplementation) -> int:
        """Calculate remediation priority (1-100, higher = more urgent)"""
        priority = 0
        
        # Base priority from risk level
        risk_scores = {
            RiskLevel.CRITICAL.value: 80,
            RiskLevel.HIGH.value: 60,
            RiskLevel.MEDIUM.value: 40,
            RiskLevel.LOW.value: 20,
            RiskLevel.INFO.value: 5
        }
        priority = risk_scores.get(impl.risk_level, 50)
        
        # Adjust for quantum vulnerability
        if impl.quantum_status == QuantumVulnerability.VULNERABLE.value:
            priority += 10
        
        # Adjust for harvest-now risk
        if impl.harvest_now_decrypt_later_risk:
            priority += 10
        
        return min(100, priority)


class CBOMGenerator:
    """
    Generates CBOM from scan results and TLS analysis
    """
    
    # Algorithm to quantum vulnerability mapping
    QUANTUM_VULNERABLE_ALGORITHMS = {
        # Asymmetric (Shor's algorithm)
        'RSA': {'shor': True, 'grover': False, 'status': QuantumVulnerability.VULNERABLE},
        'DSA': {'shor': True, 'grover': False, 'status': QuantumVulnerability.VULNERABLE},
        'ECDSA': {'shor': True, 'grover': False, 'status': QuantumVulnerability.VULNERABLE},
        'ECDH': {'shor': True, 'grover': False, 'status': QuantumVulnerability.VULNERABLE},
        'DH': {'shor': True, 'grover': False, 'status': QuantumVulnerability.VULNERABLE},
        'DHE': {'shor': True, 'grover': False, 'status': QuantumVulnerability.VULNERABLE},
        'ECDHE': {'shor': True, 'grover': False, 'status': QuantumVulnerability.VULNERABLE},
        
        # Symmetric (Grover's algorithm - need to double key size)
        'AES-128': {'shor': False, 'grover': True, 'status': QuantumVulnerability.PARTIALLY_SAFE},
        'AES-192': {'shor': False, 'grover': True, 'status': QuantumVulnerability.PARTIALLY_SAFE},
        'AES-256': {'shor': False, 'grover': False, 'status': QuantumVulnerability.QUANTUM_SAFE},
        '3DES': {'shor': False, 'grover': True, 'status': QuantumVulnerability.VULNERABLE},
        'DES': {'shor': False, 'grover': True, 'status': QuantumVulnerability.VULNERABLE},
        
        # Hash (Grover's algorithm)
        'SHA-256': {'shor': False, 'grover': True, 'status': QuantumVulnerability.PARTIALLY_SAFE},
        'SHA-384': {'shor': False, 'grover': False, 'status': QuantumVulnerability.QUANTUM_SAFE},
        'SHA-512': {'shor': False, 'grover': False, 'status': QuantumVulnerability.QUANTUM_SAFE},
        'SHA-1': {'shor': False, 'grover': True, 'status': QuantumVulnerability.VULNERABLE},
        'MD5': {'shor': False, 'grover': True, 'status': QuantumVulnerability.VULNERABLE},
        
        # PQC (Quantum-safe)
        'ML-KEM': {'shor': False, 'grover': False, 'status': QuantumVulnerability.QUANTUM_SAFE},
        'ML-DSA': {'shor': False, 'grover': False, 'status': QuantumVulnerability.QUANTUM_SAFE},
        'SLH-DSA': {'shor': False, 'grover': False, 'status': QuantumVulnerability.QUANTUM_SAFE},
        'KYBER': {'shor': False, 'grover': False, 'status': QuantumVulnerability.QUANTUM_SAFE},
        'DILITHIUM': {'shor': False, 'grover': False, 'status': QuantumVulnerability.QUANTUM_SAFE},
    }
    
    def __init__(self, organization: str = ""):
        self.organization = organization
        
    def _generate_id(self) -> str:
        """Generate unique ID"""
        return str(uuid.uuid4())
    
    def _generate_asset_id(self, ip: str, port: int, service: str) -> str:
        """Generate deterministic asset ID"""
        data = f"{ip}:{port}:{service}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    def _assess_quantum_vulnerability(self, algorithm: str, key_size: int = 0) -> Dict[str, Any]:
        """Assess quantum vulnerability of an algorithm"""
        # Normalize algorithm name
        algo_upper = algorithm.upper()
        
        # Check known algorithms
        for known_algo, vuln_info in self.QUANTUM_VULNERABLE_ALGORITHMS.items():
            if known_algo in algo_upper:
                return {
                    'status': vuln_info['status'].value,
                    'shor_vulnerable': vuln_info['shor'],
                    'grover_vulnerable': vuln_info['grover'],
                    'risk_score': 100 if vuln_info['status'] == QuantumVulnerability.VULNERABLE else (
                        50 if vuln_info['status'] == QuantumVulnerability.PARTIALLY_SAFE else 0
                    )
                }
        
        # Default to vulnerable if unknown
        return {
            'status': QuantumVulnerability.UNKNOWN.value,
            'shor_vulnerable': True,
            'grover_vulnerable': True,
            'risk_score': 75
        }
    
    def _calculate_risk_level(self, quantum_score: int, key_size: int, is_expired: bool = False) -> str:
        """Calculate overall risk level"""
        if is_expired:
            return RiskLevel.CRITICAL.value
        
        if quantum_score >= 80:
            return RiskLevel.CRITICAL.value
        elif quantum_score >= 60:
            return RiskLevel.HIGH.value
        elif quantum_score >= 40:
            return RiskLevel.MEDIUM.value
        elif quantum_score >= 20:
            return RiskLevel.LOW.value
        else:
            return RiskLevel.INFO.value
    
    def from_scan_and_analysis(
        self,
        scan_result: Dict[str, Any],
        tls_analyses: List[Dict[str, Any]],
        scope_description: str = ""
    ) -> CBOM:
        """
        Generate CBOM from scan results and TLS analyses
        
        Args:
            scan_result: Output from network_scanner.quick_scan()
            tls_analyses: List of outputs from tls_analyzer.analyze_tls()
            scope_description: Description of scan scope
        """
        cbom = CBOM(
            cbom_id=self._generate_id(),
            generated_at=datetime.now().isoformat(),
            scan_id=scan_result.get('scan_id', ''),
            organization=self.organization,
            scope_description=scope_description,
            target_networks=[scan_result.get('target', '')]
        )
        
        implementations = []
        
        # Process TLS analyses
        for tls in tls_analyses:
            target = tls.get('target', '')
            port = tls.get('port', 443)
            
            # Certificate-based implementation
            cert = tls.get('certificate')
            if cert:
                algo = cert.get('public_key_algorithm', 'Unknown')
                key_size = cert.get('public_key_size', 0)
                quantum_assess = self._assess_quantum_vulnerability(algo, key_size)
                
                impl = CryptoImplementation(
                    id=self._generate_id(),
                    discovery_timestamp=datetime.now().isoformat(),
                    asset_id=self._generate_asset_id(target, port, 'certificate'),
                    asset_name=cert.get('subject', target),
                    asset_ip=target,
                    asset_hostname=target,
                    asset_type='server',
                    asset_criticality='high' if port == 443 else 'medium',
                    crypto_type='certificate',
                    algorithm=algo,
                    key_size=key_size,
                    location=f"{target}:{port}",
                    quantum_status=quantum_assess['status'],
                    quantum_risk_score=quantum_assess['risk_score'],
                    shor_vulnerable=quantum_assess['shor_vulnerable'],
                    grover_vulnerable=quantum_assess['grover_vulnerable'],
                    harvest_now_decrypt_later_risk=quantum_assess['shor_vulnerable'],
                    risk_level=self._calculate_risk_level(
                        quantum_assess['risk_score'],
                        key_size,
                        cert.get('is_expired', False)
                    ),
                    cert_subject=cert.get('subject', ''),
                    cert_issuer=cert.get('issuer', ''),
                    cert_expiry=cert.get('not_after', ''),
                    cert_days_remaining=cert.get('days_until_expiry', 0),
                    cert_fingerprint=cert.get('fingerprint_sha256', ''),
                    discovery_method='tls_analysis'
                )
                
                # Add risk factors
                if quantum_assess['shor_vulnerable']:
                    impl.risk_factors.append(f"{algo} vulnerable to Shor's algorithm")
                    impl.quantum_risk_factors.append("Asymmetric cryptography broken by quantum computers")
                
                if cert.get('is_expired'):
                    impl.risk_factors.append("Certificate is expired")
                    impl.risk_level = RiskLevel.CRITICAL.value
                
                if cert.get('days_until_expiry', 0) < 30 and cert.get('days_until_expiry', 0) > 0:
                    impl.risk_factors.append(f"Certificate expires in {cert.get('days_until_expiry')} days")
                
                if cert.get('is_self_signed'):
                    impl.risk_factors.append("Self-signed certificate")
                
                # Compliance gaps
                impl.compliance_gaps = [
                    "Not FIPS 203 compliant (ML-KEM required for quantum-safe key exchange)",
                    "Not FIPS 204 compliant (ML-DSA required for quantum-safe signatures)",
                    "Requires migration to post-quantum cryptography"
                ]
                
                implementations.append(impl)
            
            # Cipher suite implementations
            for suite in tls.get('cipher_suites', []):
                kex = suite.get('key_exchange', 'Unknown')
                quantum_assess = self._assess_quantum_vulnerability(kex)
                
                impl = CryptoImplementation(
                    id=self._generate_id(),
                    discovery_timestamp=datetime.now().isoformat(),
                    asset_id=self._generate_asset_id(target, port, suite.get('name', '')),
                    asset_name=f"TLS Cipher: {suite.get('name', 'Unknown')}",
                    asset_ip=target,
                    asset_hostname=target,
                    asset_type='server',
                    asset_criticality='high',
                    crypto_type='key_exchange',
                    algorithm=kex,
                    algorithm_variant=suite.get('name', ''),
                    key_size=suite.get('key_size', 0),
                    protocol_version=suite.get('protocol', ''),
                    location=f"{target}:{port}",
                    quantum_status=quantum_assess['status'],
                    quantum_risk_score=quantum_assess['risk_score'],
                    shor_vulnerable=quantum_assess['shor_vulnerable'],
                    grover_vulnerable=quantum_assess['grover_vulnerable'],
                    harvest_now_decrypt_later_risk=quantum_assess['shor_vulnerable'],
                    risk_level=self._calculate_risk_level(quantum_assess['risk_score'], suite.get('key_size', 0)),
                    discovery_method='cipher_enumeration'
                )
                
                if suite.get('is_weak'):
                    impl.risk_factors.append(f"Weak cipher suite: {suite.get('name')}")
                    impl.risk_level = RiskLevel.HIGH.value
                
                implementations.append(impl)
        
        # Process scan results for services
        for service in scan_result.get('services', []):
            if service.get('has_ssl'):
                # Check if we already have TLS analysis for this
                existing = any(
                    i.asset_ip == service.get('ip_address') and 
                    str(service.get('port')) in i.location
                    for i in implementations
                )
                
                if not existing:
                    # Add basic entry for SSL service without detailed analysis
                    impl = CryptoImplementation(
                        id=self._generate_id(),
                        discovery_timestamp=service.get('discovery_time', datetime.now().isoformat()),
                        asset_id=self._generate_asset_id(
                            service.get('ip_address', ''),
                            service.get('port', 0),
                            service.get('service_name', '')
                        ),
                        asset_name=f"{service.get('service_name', 'Unknown')} on {service.get('hostname', service.get('ip_address'))}",
                        asset_ip=service.get('ip_address', ''),
                        asset_hostname=service.get('hostname', ''),
                        asset_type='server',
                        asset_criticality='medium',
                        crypto_type='tls',
                        algorithm='TLS',
                        protocol_version=service.get('service_version', ''),
                        implementation_library=service.get('service_version', ''),
                        location=f"{service.get('ip_address')}:{service.get('port')}",
                        quantum_status=QuantumVulnerability.VULNERABLE.value,
                        quantum_risk_score=75,
                        risk_level=RiskLevel.HIGH.value,
                        discovery_method='network_scan',
                        notes="Detailed TLS analysis recommended"
                    )
                    impl.risk_factors.append("SSL/TLS service detected - requires detailed analysis")
                    implementations.append(impl)
        
        cbom.implementations = implementations
        
        # Calculate summary
        cbom.summary = self._calculate_summary(implementations)
        
        # Generate findings and recommendations
        cbom.critical_findings = self._generate_critical_findings(implementations)
        cbom.recommendations = self._generate_recommendations(implementations)
        cbom.migration_priority = self._generate_migration_priority(implementations)
        
        return cbom
    
    def _calculate_summary(self, implementations: List[CryptoImplementation]) -> CBOMSummary:
        """Calculate CBOM summary statistics"""
        summary = CBOMSummary()
        summary.total_implementations = len(implementations)
        summary.total_assets = len(set(i.asset_id for i in implementations))
        
        for impl in implementations:
            # Risk levels
            if impl.risk_level == RiskLevel.CRITICAL.value:
                summary.critical_risk += 1
            elif impl.risk_level == RiskLevel.HIGH.value:
                summary.high_risk += 1
            elif impl.risk_level == RiskLevel.MEDIUM.value:
                summary.medium_risk += 1
            else:
                summary.low_risk += 1
            
            # Quantum stats
            if impl.quantum_status == QuantumVulnerability.VULNERABLE.value:
                summary.quantum_vulnerable += 1
            elif impl.quantum_status == QuantumVulnerability.QUANTUM_SAFE.value:
                summary.quantum_safe += 1
            
            if impl.harvest_now_decrypt_later_risk:
                summary.harvest_now_risk += 1
            
            # Compliance
            if impl.fips_203_compliant:
                summary.fips_203_compliant += 1
            if impl.fips_204_compliant:
                summary.fips_204_compliant += 1
            if impl.fips_205_compliant:
                summary.fips_205_compliant += 1
            
            # Algorithm breakdown
            algo = impl.algorithm
            summary.algorithms[algo] = summary.algorithms.get(algo, 0) + 1
            
            # Key size breakdown
            if impl.key_size > 0:
                key_str = f"{impl.key_size}-bit"
                summary.key_sizes[key_str] = summary.key_sizes.get(key_str, 0) + 1
        
        # Calculate overall compliance score
        if summary.total_implementations > 0:
            compliant = summary.fips_203_compliant + summary.fips_204_compliant + summary.fips_205_compliant
            max_possible = summary.total_implementations * 3
            summary.overall_compliance_score = int((compliant / max_possible) * 100) if max_possible > 0 else 0
        
        return summary
    
    def _generate_critical_findings(self, implementations: List[CryptoImplementation]) -> List[str]:
        """Generate list of critical findings"""
        findings = []
        
        critical_count = sum(1 for i in implementations if i.risk_level == RiskLevel.CRITICAL.value)
        if critical_count > 0:
            findings.append(f"{critical_count} cryptographic implementations at CRITICAL risk level")
        
        harvest_risk = sum(1 for i in implementations if i.harvest_now_decrypt_later_risk)
        if harvest_risk > 0:
            findings.append(f"{harvest_risk} implementations vulnerable to 'harvest now, decrypt later' attacks")
        
        expired = sum(1 for i in implementations if i.cert_days_remaining < 0)
        if expired > 0:
            findings.append(f"{expired} expired certificates detected")
        
        expiring_soon = sum(1 for i in implementations if 0 < i.cert_days_remaining < 30)
        if expiring_soon > 0:
            findings.append(f"{expiring_soon} certificates expiring within 30 days")
        
        quantum_vuln = sum(1 for i in implementations if i.quantum_status == QuantumVulnerability.VULNERABLE.value)
        if quantum_vuln > 0:
            findings.append(f"{quantum_vuln} implementations fully vulnerable to quantum attacks")
        
        return findings
    
    def _generate_recommendations(self, implementations: List[CryptoImplementation]) -> List[str]:
        """Generate recommendations based on findings"""
        recommendations = [
            "Begin post-quantum cryptography migration planning per NIST guidelines",
            "Prioritize migration of systems handling sensitive data with long-term value",
            "Implement hybrid cryptography (classical + PQC) as interim measure",
            "Review and update cryptographic inventory quarterly",
            "Establish key rotation procedures aligned with PQC migration timeline"
        ]
        
        # Add specific recommendations based on findings
        rsa_count = sum(1 for i in implementations if 'RSA' in i.algorithm.upper())
        if rsa_count > 0:
            recommendations.insert(0, f"Plan migration of {rsa_count} RSA implementations to ML-KEM/ML-DSA")
        
        return recommendations
    
    def _generate_migration_priority(self, implementations: List[CryptoImplementation]) -> List[str]:
        """Generate prioritized migration list"""
        # Sort by risk and criticality
        sorted_impl = sorted(
            implementations,
            key=lambda x: (
                {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}.get(x.risk_level, 5),
                -x.quantum_risk_score
            )
        )
        
        priority_list = []
        for impl in sorted_impl[:10]:  # Top 10 priorities
            priority_list.append(
                f"[{impl.risk_level.upper()}] {impl.asset_name} ({impl.algorithm}) - {impl.location}"
            )
        
        return priority_list


def generate_cbom(
    scan_result: Dict[str, Any],
    tls_analyses: List[Dict[str, Any]],
    organization: str = "",
    scope_description: str = ""
) -> Dict[str, Any]:
    """Convenience function for API use"""
    generator = CBOMGenerator(organization=organization)
    cbom = generator.from_scan_and_analysis(scan_result, tls_analyses, scope_description)
    return cbom.to_dict()


def generate_cbom_cdm_format(
    scan_result: Dict[str, Any],
    tls_analyses: List[Dict[str, Any]],
    organization: str = ""
) -> Dict[str, Any]:
    """Generate CBOM in CDM-compatible format"""
    generator = CBOMGenerator(organization=organization)
    cbom = generator.from_scan_and_analysis(scan_result, tls_analyses)
    return cbom.to_cdm_format()


if __name__ == "__main__":
    # Test with sample data
    sample_scan = {
        "scan_id": "SCAN-TEST-001",
        "target": "192.168.1.0/24",
        "services": [
            {
                "ip_address": "192.168.1.1",
                "hostname": "server1.local",
                "port": 443,
                "service_name": "https",
                "has_ssl": True,
                "discovery_time": datetime.now().isoformat()
            }
        ]
    }
    
    sample_tls = [
        {
            "target": "192.168.1.1",
            "port": 443,
            "certificate": {
                "subject": "CN=server1.local",
                "issuer": "CN=Local CA",
                "public_key_algorithm": "RSA",
                "public_key_size": 2048,
                "not_after": "2025-12-31T00:00:00",
                "days_until_expiry": 400,
                "is_expired": False,
                "is_self_signed": False,
                "fingerprint_sha256": "abc123..."
            },
            "cipher_suites": [
                {
                    "name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                    "key_exchange": "ECDHE",
                    "key_size": 256,
                    "protocol": "TLSv1.3",
                    "is_weak": False
                }
            ]
        }
    ]
    
    generator = CBOMGenerator(organization="Test Agency")
    cbom = generator.from_scan_and_analysis(sample_scan, sample_tls, "Test scan")
    print(cbom.to_json())
